// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"gdns/internal/access"
	"gdns/internal/core"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const sessionCookie = "gdns_session"

func (s *Server) principal(r *http.Request) (access.Principal, string, bool) {
	if header := r.Header.Get("Authorization"); header != "" {
		if !strings.HasPrefix(header, "Bearer ") || s.Token == "" {
			return access.Principal{}, "", false
		}
		got, want := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer "))), sha256.Sum256([]byte(s.Token))
		if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			return access.Principal{Username: "token", Source: "token", Role: "admin"}, "", true
		}
		return access.Principal{}, "", false
	}
	if s.Access == nil {
		return access.Principal{}, "", false
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return access.Principal{}, "", false
	}
	p, csrf, err := s.Access.Authenticate(r.Context(), cookie.Value)
	if err != nil {
		return access.Principal{}, "", false
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		got := r.Header.Get("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(csrf)) != 1 || !sameOrigin(r) {
			return access.Principal{}, "", false
		}
	}
	return p, csrf, true
}
func sameOrigin(r *http.Request) bool {
	value := r.Header.Get("Origin")
	if value == "" {
		return true
	}
	parsed, err := url.Parse(value)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Scheme == scheme && strings.EqualFold(parsed.Host, r.Host)
}
func peer(r *http.Request) string { host, _, _ := net.SplitHostPort(r.RemoteAddr); return host }
func privateTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	ip, err := netip.ParseAddr(peer(r))
	return err == nil && ip.Unmap().IsLoopback()
}
func cookie(w http.ResponseWriter, r *http.Request, value string, remove bool) {
	c := &http.Cookie{Name: sessionCookie, Value: value, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600}
	if remove {
		c.Value = ""
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, c)
}
func parseAccessJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		http.Error(w, "expected application/json", 415)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid request", 400)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", 400)
		return false
	}
	return true
}
func (s *Server) publicAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/api/auth/info" {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return true
		}
		enabled := false
		if s.Access != nil {
			c, _ := s.Access.View()
			enabled = c.LDAP.Enabled
		}
		jsonResponse(w, map[string]any{"password_login": s.Access != nil, "domain_enabled": enabled})
		return true
	}
	if r.URL.Path != "/api/auth/login" {
		return false
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return true
	}
	if s.Access == nil {
		http.Error(w, "password login unavailable", 503)
		return true
	}
	if !privateTransport(r) || !sameOrigin(r) {
		http.Error(w, "use HTTPS or a local SSH tunnel", 403)
		return true
	}
	if !s.Access.Permit(peer(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many login attempts", 429)
		return true
	}
	var body struct {
		Source   string `json:"source"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !parseAccessJSON(w, r, &body) {
		return true
	}
	raw, csrf, p, err := s.Access.Login(r.Context(), body.Source, strings.TrimSpace(body.Username), body.Password)
	if err != nil {
		status := 401
		if err == access.ErrBusy {
			status = 429
		}
		http.Error(w, "login failed", status)
		return true
	}
	cookie(w, r, raw, false)
	jsonResponse(w, map[string]any{"user": p, "csrf_token": csrf})
	return true
}
func permitted(p access.Principal, r *http.Request) bool {
	if p.Role == "admin" {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/access") {
		return false
	}
	if r.URL.Path == "/api/auth/me" || r.URL.Path == "/api/auth/logout" || r.URL.Path == "/api/auth/password" {
		return true
	}
	if r.Method == "GET" {
		switch r.URL.Path {
		case "/api/status", "/api/config", "/api/logs", "/api/zone/export":
			return true
		}
		return false
	}
	if p.Role != "operator" {
		return false
	}
	switch r.URL.Path {
	case "/api/config":
		return r.Method == "PUT"
	case "/api/zone/refresh", "/api/zone/import", "/api/feed/import", "/api/feed/refresh":
		return r.Method == "POST"
	}
	return false
}
func publicConfig(c core.Config, p access.Principal) core.Config {
	if p.Role != "admin" {
		for i := range c.Zones {
			if c.Zones[i].Transfer.Secret != "" {
				c.Zones[i].Transfer.Secret = "***"
			}
		}
		for i := range c.Feeds {
			c.Feeds[i].URL = ""
			if c.Feeds[i].Authorization != "" {
				c.Feeds[i].Authorization = "***"
			}
		}
	}
	return c
}
func operatorConfig(c *core.Config, old core.Config) bool {
	if len(c.Feeds) != len(old.Feeds) {
		return false
	}
	for i := range c.Feeds {
		if c.Feeds[i].URL != "" || c.Feeds[i].Authorization != "" && c.Feeds[i].Authorization != "***" {
			return false
		}
		c.Feeds[i].URL = old.Feeds[i].URL
		c.Feeds[i].Authorization = old.Feeds[i].Authorization
	}
	for i := range c.Zones {
		z := &c.Zones[i]
		if z.Transfer.Secret == "***" {
			found := false
			for _, prev := range old.Zones {
				if prev.Name == z.Name && reflect.DeepEqual(prev.Clients, z.Clients) {
					z.Transfer.Secret = prev.Transfer.Secret
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	want := old
	want.Zones = c.Zones
	want.Blocked = c.Blocked
	return reflect.DeepEqual(*c, want)
}
func (s *Server) accessAPI(w http.ResponseWriter, r *http.Request, p access.Principal, csrf string) bool {
	switch r.URL.Path {
	case "/api/auth/me":
		if r.Method != "GET" {
			w.WriteHeader(405)
			return true
		}
		jsonResponse(w, map[string]any{"user": p, "csrf_token": csrf})
		return true
	case "/api/auth/logout":
		if r.Method != "POST" {
			w.WriteHeader(405)
			return true
		}
		if s.Access != nil {
			if c, err := r.Cookie(sessionCookie); err == nil {
				s.Access.Logout(c.Value)
			}
		}
		cookie(w, r, "", true)
		jsonResponse(w, map[string]bool{"ok": true})
		return true
	case "/api/auth/password":
		if r.Method != "POST" {
			w.WriteHeader(405)
			return true
		}
		if p.Source != "local" || s.Access == nil {
			http.Error(w, "local session required", 403)
			return true
		}
		if !privateTransport(r) || !s.Access.Permit(peer(r)) {
			http.Error(w, "password change temporarily unavailable", 429)
			return true
		}
		var body struct {
			Current  string `json:"current_password"`
			Password string `json:"password"`
		}
		if !parseAccessJSON(w, r, &body) {
			return true
		}
		c, rev := s.Access.Snapshot()
		var hash string
		err := s.Access.Work(r.Context(), func() error {
			for _, u := range c.Users {
				if u.Username == p.Username && access.VerifyPassword(body.Current, u.PasswordHash) {
					var err error
					hash, err = access.HashPassword(body.Password)
					return err
				}
			}
			return access.ErrBadCredentials
		})
		if err != nil {
			http.Error(w, "password change failed; use 12..1024 bytes", 400)
			return true
		}
		err = s.Access.Update(r.Context(), rev, func(c *access.Config) error {
			for i := range c.Users {
				if c.Users[i].Username == p.Username {
					c.Users[i].PasswordHash = hash
					return nil
				}
			}
			return access.ErrBadCredentials
		})
		if err != nil {
			fail(w, err)
			return true
		}
		cookie(w, r, "", true)
		jsonResponse(w, map[string]bool{"ok": true})
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/access") {
		return false
	}
	if s.Access == nil {
		http.Error(w, "access settings unavailable", 503)
		return true
	}
	c, rev := s.Access.Snapshot()
	if r.URL.Path == "/api/access" && r.Method == "GET" {
		view, viewRev := s.Access.View()
		w.Header().Set("ETag", fmt.Sprintf("\"access-%d\"", viewRev))
		jsonResponse(w, view)
		return true
	}
	if r.URL.Path == "/api/access/ldap/test" && r.Method == "POST" {
		if !s.Access.Permit(peer(r)) {
			http.Error(w, "too many directory attempts", 429)
			return true
		}
		var body struct {
			LDAP     access.LDAP `json:"ldap"`
			Username string      `json:"username"`
		}
		if !parseAccessJSON(w, r, &body) {
			return true
		}
		groups, role, err := s.Access.DirectoryTest(r.Context(), body.LDAP, body.Username)
		if err != nil {
			http.Error(w, "LDAP lookup failed: check TLS, service account, base DN and filter", 400)
			return true
		}
		jsonResponse(w, map[string]any{"groups": groups, "role": role, "allowed": role != ""})
		return true
	}
	if r.Header.Get("If-Match") != fmt.Sprintf("\"access-%d\"", rev) {
		http.Error(w, "access configuration changed; reload", 412)
		return true
	}
	switch r.URL.Path {
	case "/api/access/ldap":
		if r.Method != "PUT" {
			w.WriteHeader(405)
			return true
		}
		var body access.LDAP
		if !parseAccessJSON(w, r, &body) {
			return true
		}
		if body.BindPassword == "***" {
			body.BindPassword = c.LDAP.BindPassword
		}
		if err := s.Access.Update(r.Context(), rev, func(c *access.Config) error { c.LDAP = body; return nil }); err != nil {
			fail(w, err)
			return true
		}
	case "/api/access/users":
		if r.Method == "DELETE" {
			name := r.URL.Query().Get("username")
			if err := s.Access.Update(r.Context(), rev, func(c *access.Config) error {
				for i, u := range c.Users {
					if u.Username == name {
						c.Users = append(c.Users[:i], c.Users[i+1:]...)
						return nil
					}
				}
				return fmt.Errorf("user not found")
			}); err != nil {
				fail(w, err)
				return true
			}
		} else if r.Method == "POST" {
			var body struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Role     string `json:"role"`
				Disabled bool   `json:"disabled"`
			}
			if !parseAccessJSON(w, r, &body) {
				return true
			}
			hash := ""
			if body.Password != "" {
				if !privateTransport(r) || !s.Access.Permit(peer(r)) {
					http.Error(w, "user update temporarily unavailable", 429)
					return true
				}
				if err := s.Access.Work(r.Context(), func() error { var err error; hash, err = access.HashPassword(body.Password); return err }); err != nil {
					fail(w, err)
					return true
				}
			}
			if err := s.Access.Update(r.Context(), rev, func(c *access.Config) error {
				for i := range c.Users {
					if strings.EqualFold(c.Users[i].Username, body.Username) {
						c.Users[i].Role = body.Role
						c.Users[i].Disabled = body.Disabled
						if hash != "" {
							c.Users[i].PasswordHash = hash
						}
						return nil
					}
				}
				c.Users = append(c.Users, access.User{Username: body.Username, PasswordHash: hash, Role: body.Role, Disabled: body.Disabled})
				return nil
			}); err != nil {
				fail(w, err)
				return true
			}
		} else {
			w.WriteHeader(405)
			return true
		}
	default:
		http.NotFound(w, r)
		return true
	}
	view, newRev := s.Access.View()
	w.Header().Set("ETag", strconv.Quote(fmt.Sprintf("access-%d", newRev)))
	jsonResponse(w, view)
	return true
}
