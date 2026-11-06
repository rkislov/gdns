// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"gdns/internal/access"
	"gdns/internal/core"
	validation "gdns/internal/dnssec"
	"gdns/internal/storage"
	"gdns/internal/telemetry"
	"gdns/internal/transport"
	"gdns/internal/web"
	"github.com/miekg/dns"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func loadConfig(ctx context.Context, path string, store *storage.Store, importConfig bool) (core.Config, error) {
	c, err := store.Load(ctx)
	if err != nil && !errors.Is(err, storage.ErrEmpty) {
		return c, err
	}
	if err == nil && !importConfig {
		return c, nil
	}
	c = core.DefaultConfig()
	data, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(data, &c); e != nil {
			return c, e
		}
	} else if !errors.Is(e, os.ErrNotExist) || importConfig {
		return c, e
	}
	engine, e := core.New(c)
	if e != nil {
		return c, e
	}
	c = engine.Config()
	if c.DoHListen != "" || c.DoTListen != "" {
		if _, e = tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); e != nil {
			return c, e
		}
	}
	if e != nil {
		return c, e
	}
	manager, managedErr := validation.OpenManager(ctx, store.LoadManaged, store.SaveManaged)
	if managedErr != nil {
		return c, managedErr
	}
	if managedErr = manager.CheckSeeds(c.DNSSEC); managedErr != nil {
		return c, managedErr
	}
	if e = store.Save(ctx, c); e != nil {
		return c, e
	}
	return c, nil
}
func run() error {
	showVersion := flag.Bool("version", false, "print build version and exit")
	path := flag.String("config", "gdns.json", "initial/import JSON configuration; token path prefix")
	driver := flag.String("storage", "sqlite", "sqlite or postgres")
	database := flag.String("database", "", "SQLite path or PostgreSQL DSN (prefer GDNS_DATABASE_URL)")
	doImport := flag.Bool("import-config", false, "replace database configuration from -config JSON")
	export := flag.String("export-config", "", "export database configuration to a private JSON file and exit")
	check := flag.Bool("check", false, "validate stored configuration and certificates, then exit")
	metricsListen := flag.String("metrics-listen", "127.0.0.1:9090", "Prometheus HTTP listen address; empty disables exporter")
	metricsDisk := flag.String("metrics-disk-path", "", "filesystem path to monitor; defaults to SQLite/config directory")
	flag.Parse()
	if *showVersion {
		fmt.Printf("gdns %s (%s; %s)\n", version, commit, buildDate)
		return nil
	}
	dsn := *database
	if dsn == "" {
		if *driver == "postgres" {
			dsn = compatibleEnv("GDNS_DATABASE_URL", "GHOLE_DATABASE_URL")
		} else {
			dsn = *path + ".db"
		}
	}
	startup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, err := storage.Open(startup, *driver, dsn)
	if err != nil {
		return err
	}
	defer store.Close()
	c, err := loadConfig(startup, *path, store, *doImport)
	if err != nil {
		return err
	}
	engine, err := core.New(c)
	if err != nil {
		return err
	}
	manager, err := validation.OpenManager(startup, store.LoadManaged, store.SaveManaged)
	if err != nil {
		return fmt.Errorf("load RFC 5011 state: %w", err)
	}
	if err = engine.SetRootManager(manager); err != nil {
		return err
	}
	if *export != "" {
		return web.Save(*export, c)
	}
	if *check {
		if c.DoHListen != "" || c.DoTListen != "" {
			if _, err = tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
				return err
			}
		}
		fmt.Printf("Configuration OK (storage=%s)\n", *driver)
		return nil
	}
	anchorsCtx, anchorsStop := context.WithCancel(context.Background())
	anchorsDone := make(chan struct{})
	go func() { defer close(anchorsDone); manager.Run(anchorsCtx, engine.RefreshRootAnchors) }()
	defer func() { anchorsStop(); <-anchorsDone }()
	if err = os.MkdirAll(filepath.Dir(*path), 0700); err != nil {
		return err
	}
	token := strings.TrimSpace(compatibleEnv("GDNS_ADMIN_TOKEN", "GHOLE_ADMIN_TOKEN"))
	if token == "" {
		tokenPath := *path + ".token"
		b, e := os.ReadFile(tokenPath)
		if e == nil {
			token = strings.TrimSpace(string(b))
		} else if errors.Is(e, os.ErrNotExist) {
			buf := make([]byte, 32)
			if _, e = rand.Read(buf); e != nil {
				return e
			}
			token = hex.EncodeToString(buf)
			if e = os.WriteFile(tokenPath, []byte(token), 0600); e != nil {
				return e
			}
			log.Printf("Admin token saved to %s", tokenPath)
		} else {
			return e
		}
	}
	if len(token) < 24 {
		return fmt.Errorf("admin token must contain at least 24 characters")
	}
	accessManager, err := access.Open(startup, store.LoadAccess, store.SaveAccess, *path+".admin-password")
	if err != nil {
		return fmt.Errorf("access configuration: %w", err)
	}
	udp, err := transport.ListenUDP(c.DNSListen, c.UDPWorkers)
	if err != nil {
		return err
	}
	defer func() {
		for _, conn := range udp {
			conn.Close()
		}
	}()
	tcp, err := net.Listen("tcp", c.DNSListen)
	if err != nil {
		return err
	}
	defer tcp.Close()
	listener, err := net.Listen("tcp", c.HTTPListen)
	if err != nil {
		return err
	}
	defer listener.Close()
	us := make([]*dns.Server, len(udp))
	for i, conn := range udp {
		us[i] = &dns.Server{PacketConn: conn, TsigProvider: engine, Handler: engine, UDPSize: 1232}
	}
	ts := &dns.Server{Listener: tcp, TsigProvider: engine, Handler: engine, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxTCPQueries: -1}
	diskPath := *metricsDisk
	if diskPath == "" {
		diskPath = filepath.Dir(*path)
		if *driver == "sqlite" {
			diskPath = filepath.Dir(dsn)
		}
	}
	diskPath, err = filepath.Abs(diskPath)
	if err != nil {
		return err
	}
	monitor := telemetry.New(diskPath)
	monitor.RegisterRFC5011(func() validation.ManagedStatus { return engine.RootTrustStatus() })
	engine.SetObserver(monitor)
	monitorCtx, monitorStop := context.WithCancel(context.Background())
	defer monitorStop()
	go monitor.Run(monitorCtx)
	var metricsServer *http.Server
	var metricsListener net.Listener
	if *metricsListen != "" {
		metricsListener, err = net.Listen("tcp", *metricsListen)
		if err != nil {
			return err
		}
		defer metricsListener.Close()
		mux := http.NewServeMux()
		mux.Handle("/metrics", monitor.Handler())
		metricsServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	}
	running := core.Config{UDPWorkers: c.UDPWorkers, DNSListen: c.DNSListen, HTTPListen: c.HTTPListen, DoHListen: c.DoHListen, DoTListen: c.DoTListen, TLSCertFile: c.TLSCertFile, TLSKeyFile: c.TLSKeyFile}
	admin := &web.Server{Access: accessManager, Monitor: monitor, Engine: engine, Path: *path, Token: token, Running: &running, StorageDriver: *driver, UDPWorkers: len(udp), Persist: func(prepared core.Config) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return store.Save(ctx, prepared)
	}}
	secondaryCtx, secondaryStop := context.WithCancel(context.Background())
	secondaryDone := make(chan struct{})
	go func() { defer close(secondaryDone); admin.RunSecondaries(secondaryCtx) }()
	defer func() { secondaryStop(); <-secondaryDone }()
	encrypted, err := transport.ListenWithAdmin(c, engine, admin.Handler())
	if err != nil {
		return err
	}
	defer encrypted.Close()

	hs := &http.Server{Handler: admin.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 125 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	errs := make(chan error, len(us)+5)
	for _, server := range us {
		go func() { errs <- server.ActivateAndServe() }()
	}
	go func() { errs <- ts.ActivateAndServe() }()
	go func() { errs <- hs.Serve(listener) }()
	encrypted.Start(errs)
	if metricsServer != nil {
		go func() { errs <- metricsServer.Serve(metricsListener) }()
		log.Printf("Prometheus http://%s/metrics", *metricsListen)
	}
	log.Printf("gdns DNS udp/tcp=%s web=http://%s mode=%s storage=%s udp_workers=%d", c.DNSListen, c.HTTPListen, c.Mode, *driver, len(us))
	if c.DoHListen != "" {
		log.Printf("DoH https://%s/dns-query", c.DoHListen)
	}
	if c.DoTListen != "" {
		log.Printf("DoT tls://%s", c.DoTListen)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if metricsServer != nil {
		_ = metricsServer.Shutdown(shutdown)
	}
	encrypted.Shutdown(shutdown)
	_ = hs.Shutdown(shutdown)
	for _, server := range us {
		_ = server.ShutdownContext(shutdown)
	}
	_ = ts.ShutdownContext(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Explicit gdns environment values take precedence; legacy deployments keep working.
func compatibleEnv(current, legacy string) string {
	if value := os.Getenv(current); value != "" {
		return value
	}
	return os.Getenv(legacy)
}
