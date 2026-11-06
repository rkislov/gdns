// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"gdns/internal/access"
	"gdns/internal/core"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var webHashOnce sync.Once
var webHash string

const webPassword = "web-test-password-123"

func authServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	webHashOnce.Do(func() {
		var err error
		webHash, err = access.HashPassword(webPassword)
		if err != nil {
			t.Fatal(err)
		}
	})
	cfg := access.Config{Users: []access.User{{Username: "admin", PasswordHash: webHash, Role: "admin"}, {Username: "operator", PasswordHash: webHash, Role: "operator"}, {Username: "viewer", PasswordHash: webHash, Role: "viewer"}}, LDAP: access.LDAP{BindPassword: "private-bind-secret"}}
	rev := uint64(1)
	manager, err := access.Open(context.Background(), func(context.Context) (access.Config, uint64, error) { return cfg, rev, nil }, func(_ context.Context, c access.Config, expected uint64) (uint64, error) {
		if expected != rev {
			t.Fatal("bad revision")
		}
		cfg = c
		rev++
		return rev, nil
	}, filepath.Join(t.TempDir(), "pw"))
	if err != nil {
		t.Fatal(err)
	}
	c := core.DefaultConfig()
	c.Feeds = []core.Feed{{Name: "subscription", URL: "https://feed.example/private-key-in-path?key=secret", Authorization: "Bearer private-feed-secret", Enabled: true}}
	engine, err := core.New(c)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Access: manager, Engine: engine, Token: "private-automation-token-123456", Persist: func(core.Config) error { return nil }}
	h := httptest.NewTLSServer(s.Handler())
	t.Cleanup(h.Close)
	return s, h
}
func apiRequest(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, url, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data, response.Header
}
func loginClient(t *testing.T, server *httptest.Server, name string) (*http.Client, string) {
	t.Helper()
	client := server.Client()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	code, data, headers := apiRequest(t, client, "POST", server.URL+"/api/auth/login", map[string]string{"source": "local", "username": name, "password": webPassword}, nil)
	if code != 200 {
		t.Fatalf("login %d: %s", code, data)
	}
	cookie := headers.Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatal("unsafe session cookie", cookie)
	}
	var result struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(data, &result)
	return client, result.CSRF
}
func TestPasswordLoginCookieCSRFAndLogout(t *testing.T) {
	s, h := authServer(t)
	client, csrf := loginClient(t, h, "admin")
	code, data, _ := apiRequest(t, client, "GET", h.URL+"/api/auth/me", nil, nil)
	if code != 200 || !strings.Contains(string(data), `"username":"admin"`) {
		t.Fatal(code, string(data))
	}
	code, _, _ = apiRequest(t, client, "GET", h.URL+"/api/status", nil, map[string]string{"Authorization": "Bearer invalid"})
	if code != 401 {
		t.Fatal("invalid bearer fell back to cookie", code)
	}
	code, _, _ = apiRequest(t, client, "POST", h.URL+"/api/auth/logout", nil, nil)
	if code != 401 {
		t.Fatal("CSRF accepted", code)
	}
	code, _, _ = apiRequest(t, client, "POST", h.URL+"/api/auth/logout", nil, map[string]string{"X-CSRF-Token": csrf, "Origin": "https://attacker.example"})
	if code != 401 {
		t.Fatal("foreign Origin accepted", code)
	}
	code, data, _ = apiRequest(t, client, "GET", h.URL+"/api/access", nil, nil)
	if code != 200 || strings.Contains(string(data), "argon2id") || strings.Contains(string(data), "private-bind-secret") {
		t.Fatal("access secrets leaked", code, string(data))
	}
	code, _, _ = apiRequest(t, client, "POST", h.URL+"/api/auth/logout", nil, map[string]string{"X-CSRF-Token": csrf})
	if code != 200 {
		t.Fatal(code)
	}
	code, _, _ = apiRequest(t, client, "GET", h.URL+"/api/status", nil, nil)
	if code != 401 {
		t.Fatal("logout ineffective", code)
	}
	code, _, _ = apiRequest(t, client, "GET", h.URL+"/api/status", nil, map[string]string{"Authorization": "Bearer " + s.Token})
	if code != 200 {
		t.Fatal("legacy token unavailable", code)
	}
}
func TestViewerAndOperatorAuthorization(t *testing.T) {
	_, h := authServer(t)
	for _, name := range []string{"viewer", "operator"} {
		t.Run(name, func(t *testing.T) {
			client, csrf := loginClient(t, h, name)
			headers := map[string]string{"X-CSRF-Token": csrf}
			code, data, responseHeaders := apiRequest(t, client, "GET", h.URL+"/api/config", nil, nil)
			if code != 200 || strings.Contains(string(data), "private-feed-secret") || strings.Contains(string(data), "private-key-in-path") {
				t.Fatal("feed secret exposed", code)
			}
			var c core.Config
			if err := json.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}
			headers["If-Match"] = responseHeaders.Get("ETag")
			code, _, _ = apiRequest(t, client, "GET", h.URL+"/api/access", nil, nil)
			if code != 403 {
				t.Fatal("access config readable", code)
			}
			code, _, _ = apiRequest(t, client, "POST", h.URL+"/api/dnssec/rfc5011/refresh", nil, headers)
			if code != 403 {
				t.Fatal("trust write allowed", code)
			}
			c.Blocked = append(c.Blocked, "blocked.example")
			code, data, responseHeaders = apiRequest(t, client, "PUT", h.URL+"/api/config", c, headers)
			if name == "viewer" {
				if code != 403 {
					t.Fatal("viewer write", code)
				}
				return
			}
			if code != 200 {
				t.Fatal("operator zone policy", code, string(data))
			}
			code, data, responseHeaders = apiRequest(t, client, "GET", h.URL+"/api/config", nil, nil)
			json.Unmarshal(data, &c)
			headers["If-Match"] = responseHeaders.Get("ETag")
			c.AllowedClients = []string{"0.0.0.0/0"}
			code, _, _ = apiRequest(t, client, "PUT", h.URL+"/api/config", c, headers)
			if code != 403 {
				t.Fatal("operator ACL write", code)
			}
		})
	}
}
func TestLoginRequiresTLSAndOrigin(t *testing.T) {
	s, _ := authServer(t)
	body := `{"source":"local","username":"admin","password":"` + webPassword + `"}`
	for _, tc := range []struct {
		remote, origin string
		tls            bool
	}{{"203.0.113.1:1234", "", false}, {"127.0.0.1:1234", "https://attacker.example", true}} {
		request := httptest.NewRequest("POST", "https://gdns.example/api/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.RemoteAddr = tc.remote
		if tc.origin != "" {
			request.Header.Set("Origin", tc.origin)
		}
		if tc.tls {
			request.TLS = &tls.ConnectionState{}
		} else {
			request.TLS = nil
		}
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatal("insecure login", response.Code)
		}
	}
}
