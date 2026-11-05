// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"ghole/internal/core"
	validation "ghole/internal/dnssec"
	"ghole/internal/telemetry"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var assets embed.FS

type Server struct {
	Engine        *core.Engine
	Path, Token   string
	mu            sync.Mutex
	Persist       func(core.Config) error
	Running       *core.Config
	StorageDriver string
	Monitor       *telemetry.Monitor
}

func Save(path string, c core.Config) error {
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".ghole-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func (s *Server) commit(c core.Config) error {
	if c.DoHListen != "" || c.DoTListen != "" {
		if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
			return fmt.Errorf("TLS certificate/key: %w", err)
		}
	}
	persist := s.Persist
	if persist == nil {
		persist = func(c core.Config) error { return Save(s.Path, c) }
	}
	return s.Engine.Update(c, persist)

}
func (s *Server) restartRequired() bool {
	if s.Running == nil {
		return false
	}
	return s.Engine.NeedsRestart(*s.Running)
}
func configETag(c core.Config) string {
	b, _ := json.Marshal(c)
	return fmt.Sprintf("\"%x\"", sha256.Sum256(b))
}
func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusBadRequest) }
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(assets, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(auth), []byte(s.Token)) != 1 {
			http.Error(w, "Unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, core.MaxImport)
		switch r.URL.Path {
		case "/api/status":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			data := map[string]any{"queries": s.Engine.Queries.Load(), "blocked": s.Engine.Blocked.Load(), "cache_hits": s.Engine.Hits.Load(), "failures": s.Engine.Failures.Load(), "storage": s.StorageDriver, "restart_required": s.restartRequired(), "dnssec": s.Engine.DNSSECStatus(), "logs": s.Engine.RecentLogs(8)}
			if s.Monitor != nil {
				data["telemetry"] = s.Monitor.Snapshot()
			}
			jsonResponse(w, data)
		case "/api/dnssec/rfc5011/refresh":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			if !s.Engine.Config().DNSSEC.AutoUpdate.Enabled {
				fail(w, fmt.Errorf("RFC 5011 automatic refresh is disabled"))
				return
			}
			if err := s.Engine.RefreshRootAnchors(r.Context()); err != nil {
				fail(w, err)
				return
			}
			jsonResponse(w, s.Engine.DNSSECStatus())
		case "/api/dnssec/anchors":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			anchors, err := validation.FetchIANA(r.Context())
			if err != nil {
				fail(w, err)
				return
			}
			jsonResponse(w, map[string]any{"anchors": anchors, "source": validation.IANAURL, "retrieved_at": time.Now().UTC().Format(time.RFC3339)})

		case "/api/logs":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			page, size := 1, 25
			var err error
			if v := r.URL.Query().Get("page"); v != "" {
				page, err = strconv.Atoi(v)
				if err != nil || page < 1 || page > 1000000 {
					fail(w, fmt.Errorf("invalid page"))
					return
				}
			}
			if v := r.URL.Query().Get("page_size"); v != "" {
				size, err = strconv.Atoi(v)
				if err != nil || (size != 10 && size != 25 && size != 50 && size != 100) {
					fail(w, fmt.Errorf("page_size must be 10, 25, 50 or 100"))
					return
				}
			}
			anchor := uint64(0)
			if v := r.URL.Query().Get("anchor"); v != "" {
				anchor, err = strconv.ParseUint(v, 10, 64)
				if err != nil {
					fail(w, fmt.Errorf("invalid anchor"))
					return
				}
			}
			jsonResponse(w, s.Engine.QueryLogs(page, size, anchor))

		case "/api/config":
			if r.Method == "GET" {
				c := s.Engine.Config()
				w.Header().Set("ETag", configETag(c))
				jsonResponse(w, c)
				return
			}
			if r.Method != "PUT" {
				w.WriteHeader(405)
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if r.Header.Get("If-Match") != configETag(s.Engine.Config()) {
				http.Error(w, "Configuration changed. Reload before saving.", http.StatusPreconditionFailed)
				return
			}
			var c core.Config
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if e := d.Decode(&c); e != nil {
				fail(w, e)
				return
			}
			if e := s.commit(c); e != nil {
				fail(w, e)
				return
			}
			jsonResponse(w, map[string]bool{"ok": true, "restart_required": s.restartRequired()})
		case "/api/zone/import":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			records, e := core.ParseZone(r.Body, r.URL.Query().Get("name"))
			if e != nil {
				fail(w, e)
				return
			}
			jsonResponse(w, map[string]any{"records": records})
		case "/api/zone/export":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			i, e := strconv.Atoi(r.URL.Query().Get("id"))
			c := s.Engine.Config()
			if e != nil || i < 0 || i >= len(c.Zones) || c.Zones[i].Kind != "primary" {
				http.Error(w, "zone not found", 404)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=zone.bind")
			fmt.Fprintln(w, strings.Join(c.Zones[i].Records, "\n"))
		case "/api/feed/refresh", "/api/feed/import":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			c := s.Engine.Config()
			i, e := strconv.Atoi(r.URL.Query().Get("id"))
			if e != nil || i < 0 || i >= len(c.Feeds) {
				fail(w, fmt.Errorf("invalid feed id"))
				return
			}
			var domains []string
			if r.URL.Path == "/api/feed/refresh" {
				domains, e = core.DownloadFeed(r.Context(), c.Feeds[i])
			} else {
				domains, e = core.ParseFeed(r.Body)
			}
			if e != nil {
				fail(w, e)
				return
			}
			c.Feeds[i].Domains = domains
			c.Feeds[i].Updated = time.Now().UTC().Format(time.RFC3339)
			if e = s.commit(c); e != nil {
				fail(w, e)
				return
			}
			jsonResponse(w, map[string]any{"count": len(domains)})
		default:
			http.NotFound(w, r)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}
