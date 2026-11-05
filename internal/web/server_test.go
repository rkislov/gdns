// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"ghole/internal/core"
	"github.com/miekg/dns"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminPersistenceAndConcurrency(t *testing.T) {
	c := core.DefaultConfig()
	e, err := core.New(c)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Engine: e, Path: filepath.Join(t.TempDir(), "config.json"), Token: strings.Repeat("a", 32)}
	h := s.Handler()
	request := func(method, path, token, etag string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/config", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request("GET", "/api/config", s.Token, "", nil)
	etag := w.Header().Get("ETag")
	if w.Code != 200 || etag == "" {
		t.Fatal(w.Code)
	}
	c.Blocked = []string{"bad.example"}
	b, _ := json.Marshal(c)
	w = request("PUT", "/api/config", s.Token, etag, b)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	data, err := os.ReadFile(s.Path)
	if err != nil || !bytes.Contains(data, []byte("bad.example")) {
		t.Fatalf("save failed: %v", err)
	}
	info, _ := os.Stat(s.Path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config permissions")
	}
	if w = request("PUT", "/api/config", s.Token, etag, b); w.Code != http.StatusPreconditionFailed {
		t.Fatal("stale config overwrites newer version")
	}
	w = request("GET", "/api/config", s.Token, "", nil)
	etag = w.Header().Get("ETag")
	c.DNSSECValidation = true
	c.DNSSEC.TrustAnchors = []string{"invalid"}
	b, _ = json.Marshal(c)
	if w = request("PUT", "/api/config", s.Token, etag, b); w.Code != 400 {
		t.Fatal("invalid config accepted")
	}
	if e.Config().DNSSECValidation {
		t.Fatal("invalid config applied")
	}

	c.DNSSECValidation = false
	c.DNSSEC.TrustAnchors = nil
	c.Blocked = []string{"new.example"}
	b, _ = json.Marshal(c)
	s.Path = t.TempDir()
	if w = request("PUT", "/api/config", s.Token, etag, b); w.Code != 400 {
		t.Fatal("failed persistence reported success")
	}
	if e.Config().Blocked[0] != "bad.example" {
		t.Fatal("failed persistence published snapshot")
	}
}

func TestListenerChangesNeedRestart(t *testing.T) {
	c := core.DefaultConfig()
	e, _ := core.New(c)
	s := &Server{Engine: e, Running: &c, Persist: func(core.Config) error { return nil }}
	updated := e.Config()
	updated.DNSListen = "127.0.0.1:1153"
	if err := s.commit(updated); err != nil {
		t.Fatal(err)
	}
	if !s.restartRequired() {
		t.Fatal("listener change silently marked applied")
	}
	updated.DoHListen = "127.0.0.1:1443"
	updated.TLSCertFile = "/missing/cert.pem"
	updated.TLSKeyFile = "/missing/key.pem"
	if err := s.commit(updated); err == nil {
		t.Fatal("unreadable TLS certificate persisted")
	}
	if e.Config().DoHListen != "" {
		t.Fatal("failed TLS setup published")
	}
}

func TestLogsAPIPageSizes(t *testing.T) {
	c := core.DefaultConfig()
	e, _ := core.New(c)
	for i := 0; i < 65; i++ {
		q := new(dns.Msg)
		q.SetQuestion("router.home.arpa.", dns.TypeA)
		e.Answer(context.Background(), q, netip.MustParseAddr("127.0.0.1"))
	}
	s := &Server{Engine: e, Token: strings.Repeat("a", 32)}
	h := s.Handler()
	for _, size := range []int{10, 25, 50, 100} {
		r := httptest.NewRequest("GET", fmt.Sprintf("/api/logs?page=2&page_size=%d", size), nil)
		r.Header.Set("Authorization", "Bearer "+s.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var page core.LogPage
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.Total != 65 || len(page.Items) > size {
			t.Fatal("invalid log page", w.Code, err)
		}
	}
	r := httptest.NewRequest("GET", "/api/logs?page_size=1000000", nil)
	r.Header.Set("Authorization", "Bearer "+s.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("unbounded log page")
	}
}

func TestDNSSECHotConfiguration(t *testing.T) {
	c := core.DefaultConfig()
	e, _ := core.New(c)
	var saved core.Config
	s := &Server{Engine: e, Running: &c, Token: strings.Repeat("a", 32), Persist: func(c core.Config) error { saved = c; return nil }}
	h := s.Handler()
	c.DNSSECValidation = true
	c.DNSSEC.AutoUpdate.Enabled = true
	c.DNSSEC.AutoUpdate.RefreshHours = 2
	c.DNSSEC.ExemptZones = []string{"corp.internal."}
	zero := uint16(0)
	c.DNSSEC.MaxNSEC3Iterations = &zero
	b, _ := json.Marshal(c)
	r := httptest.NewRequest("PUT", "/api/config", bytes.NewReader(b))
	r.Header.Set("Authorization", "Bearer "+s.Token)
	r.Header.Set("If-Match", configETag(e.Config()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !saved.DNSSECValidation || !saved.DNSSEC.AutoUpdate.Enabled || saved.DNSSEC.AutoUpdate.RefreshHours != 2 || !e.Config().DNSSECValidation || s.restartRequired() {
		t.Fatal("DNSSEC not applied live", w.Body.String())
	}
	r = httptest.NewRequest("GET", "/api/status", nil)
	r.Header.Set("Authorization", "Bearer "+s.Token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"validating"`) {
		t.Fatal(w.Body.String())
	}
	r = httptest.NewRequest("GET", "/api/dnssec/anchors", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("anchor fetch unauthenticated")
	}
}

func TestRFC5011EndpointRequiresAuthAndEnabledSettings(t *testing.T) {
	c := core.DefaultConfig()
	e, _ := core.New(c)
	s := &Server{Engine: e, Token: strings.Repeat("a", 32)}
	h := s.Handler()
	for _, tc := range []struct {
		method, token string
		want          int
	}{{"POST", "", 401}, {"GET", s.Token, 405}, {"POST", s.Token, 400}} {
		r := httptest.NewRequest(tc.method, "/api/dnssec/rfc5011/refresh", nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
