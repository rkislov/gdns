// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"ghole/internal/core"
	"ghole/internal/telemetry"
	"ghole/internal/web"
	"github.com/miekg/dns"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func certificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(cp, public, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(public)
	return cp, kp, pool
}
func TestEncryptedTransports(t *testing.T) {
	c := core.DefaultConfig()
	split := c.Zones[0]
	split.Clients = []string{"127.0.0.0/8"}
	split.Records = append([]string{}, split.Records...)
	split.Records[3] = "router.home.arpa. 300 IN A 10.9.8.7"
	c.Zones = append(c.Zones, split)
	e, err := core.New(c)
	if err != nil {
		t.Fatal(err)
	}
	monitor := telemetry.New(t.TempDir())
	e.SetObserver(monitor)
	cert, key, pool := certificate(t)
	c.DoHListen = "127.0.0.1:0"
	c.DoTListen = "127.0.0.1:0"
	c.TLSCertFile = cert
	c.TLSKeyFile = key
	admin := &web.Server{Engine: e, Token: strings.Repeat("a", 32)}
	s, err := ListenWithAdmin(c, e, admin.Handler())
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	s.Start(errs)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	}()
	q := new(dns.Msg)
	q.SetQuestion("router.home.arpa.", dns.TypeA)
	q.Id = 1234
	wire, _ := q.Pack()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	url := "https://" + s.dohListener.Addr().String() + "/dns-query"
	for _, method := range []string{"GET", "POST"} {
		path := url
		if method == "GET" {
			path += "?dns=" + base64.RawURLEncoding.EncodeToString(wire)
		}
		req, _ := http.NewRequest(method, path, bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.ProtoMajor != 2 || resp.Header.Get("Content-Type") != "application/dns-message" {
			t.Fatalf("%s: %s HTTP/%d %s", method, resp.Status, resp.ProtoMajor, data)
		}
		m := new(dns.Msg)
		if err = m.Unpack(data); err != nil || m.Id != 1234 || len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "10.9.8.7" {
			t.Fatalf("DoH: %v %v", m, err)
		}
	}
	adminURL := "https://" + s.dohListener.Addr().String() + "/api/config"
	for _, authorized := range []bool{false, true} {
		req, _ := http.NewRequest("GET", adminURL, nil)
		if authorized {
			req.Header.Set("Authorization", "Bearer "+admin.Token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 401
		if authorized {
			want = 200
		}
		if resp.StatusCode != want {
			t.Fatalf("HTTPS admin auth: %d, want %d", resp.StatusCode, want)
		}
	}

	dc := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}}
	m, _, err := dc.Exchange(q, s.dotListener.Addr().String())
	if err != nil || len(m.Answer) != 1 {
		t.Fatalf("DoT: %v %v", m, err)
	}
	if m.Answer[0].(*dns.A).A.String() != "10.9.8.7" {
		t.Fatal("DoT split view mismatch")
	}
	if e.Queries.Load() != 3 {
		t.Fatal("transport accounting")
	}
	w := httptest.NewRecorder()
	monitor.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`ghole_dns_queries_total{result="NOERROR",transport="doh"} 2`, `ghole_dns_queries_total{result="NOERROR",transport="dot"} 1`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("encrypted transport metrics missing: %s", want)
		}
	}

	untrusted := &dns.Client{Net: "tcp-tls", Timeout: time.Second}
	if _, _, err = untrusted.Exchange(q, s.dotListener.Addr().String()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
func TestDoHValidationAndPeerACL(t *testing.T) {
	c := core.DefaultConfig()
	e, _ := core.New(c)
	h := DoHHandler(e)
	q := new(dns.Msg)
	q.SetQuestion("router.home.arpa.", dns.TypeA)
	wire, _ := q.Pack()
	for _, tc := range []struct {
		method, path, content string
		body                  []byte
		code                  int
	}{{"GET", "/dns-query?dns=invalid!", "", nil, 400}, {"POST", "/dns-query", "text/plain", wire, 415}, {"DELETE", "/dns-query", "", nil, 405}, {"POST", "/dns-query", "application/dns-message", make([]byte, 65536), 400}, {"GET", "/not-dns", "", nil, 404}} {
		r := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.content)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(wire))
	r.Header.Set("Content-Type", "application/dns-message")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.RemoteAddr = "203.0.113.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	m := new(dns.Msg)
	if err := m.Unpack(w.Body.Bytes()); err != nil || m.Rcode != dns.RcodeRefused {
		t.Fatal("spoofed proxy header bypassed ACL", err, m)
	}
}
