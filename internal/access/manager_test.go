// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package access

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testHashOnce sync.Once
var testHash string

const testPassword = "correct-local-password-123"

func fixtureHash(t *testing.T) string {
	t.Helper()
	testHashOnce.Do(func() {
		var err error
		testHash, err = HashPassword(testPassword)
		if err != nil {
			t.Fatal(err)
		}
	})
	return testHash
}
func fixtureManager(t *testing.T) *Manager {
	t.Helper()
	hash := fixtureHash(t)
	c := Config{Users: []User{{Username: "admin", Role: "admin", PasswordHash: hash}, {Username: "operator", Role: "operator", PasswordHash: hash}, {Username: "viewer", Role: "viewer", PasswordHash: hash}}, LDAP: LDAP{URL: "ldaps://directory.example:636", BindDN: "svc@example", BindPassword: "private-bind-secret", BaseDN: "dc=example", UserFilter: "(uid={username})", Groups: []Group{{DN: "cn=dns,dc=example", Role: "operator"}}}}
	rev := uint64(1)
	m, err := Open(context.Background(), func(context.Context) (Config, uint64, error) { return c, rev, nil }, func(_ context.Context, next Config, expected uint64) (uint64, error) {
		if expected != rev {
			return 0, errors.New("conflict")
		}
		c = clone(next)
		rev++
		return rev, nil
	}, filepath.Join(t.TempDir(), "password"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestLocalSessionsRolesRevocationAndRedaction(t *testing.T) {
	m := fixtureManager(t)
	ctx := context.Background()
	raw, csrf, p, err := m.Login(ctx, "local", "OPERATOR", testPassword)
	if err != nil || p.Username != "operator" || p.Role != "operator" || csrf == "" {
		t.Fatal(p, err)
	}
	if _, _, err = m.Authenticate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	view, rev := m.View()
	if view.Users[0].PasswordHash != "" || view.LDAP.BindPassword != "***" {
		t.Fatal("secrets exposed")
	}
	if err = m.Update(ctx, rev, func(c *Config) error { c.Users[1].Role = "viewer"; return nil }); err != nil {
		t.Fatal(err)
	}
	if p, _, err = m.Authenticate(ctx, raw); err != nil || p.Role != "viewer" {
		t.Fatal("role change not applied", p, err)
	}
	_, rev = m.Snapshot()
	if err = m.Update(ctx, rev, func(c *Config) error { c.Users[0].Disabled = true; return nil }); err == nil {
		t.Fatal("last local admin disabled")
	}
	_, rev = m.Snapshot()
	if err = m.Update(ctx, rev, func(c *Config) error { c.Users[1].Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Authenticate(ctx, raw); err == nil {
		t.Fatal("disabled user session accepted")
	}
	raw, _, _, err = m.Login(ctx, "local", "admin", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	m.Logout(raw)
	if _, _, err = m.Authenticate(ctx, raw); err == nil {
		t.Fatal("logout not effective")
	}
	if _, _, _, err = m.Login(ctx, "local", "admin", "bad password"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
	if _, _, _, err = m.Login(ctx, "local", "unknown", testPassword); !errors.Is(err, ErrBadCredentials) {
		t.Fatal(err)
	}
}
func TestDirectorySessionRefreshAndLocalFallback(t *testing.T) {
	m := fixtureManager(t)
	ctx := context.Background()
	_, rev := m.Snapshot()
	if err := m.Update(ctx, rev, func(c *Config) error { c.LDAP.Enabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	groups := []string{"CN=DNS,DC=EXAMPLE"}
	offline := false
	m.directory = func(_ context.Context, _ LDAP, _ string, password *string) ([]string, error) {
		if offline {
			return nil, errors.New("directory offline")
		}
		return groups, nil
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	raw, _, p, err := m.Login(ctx, "ldap", "directory-user", "domain-password")
	if err != nil || p.Role != "operator" {
		t.Fatal(p, err)
	}
	if _, _, _, err = m.Login(ctx, "ldap", "admin", "domain-password"); err == nil {
		t.Fatal("directory claimed local identity")
	}
	now = now.Add(6 * time.Minute)
	groups = nil
	if _, _, err = m.Authenticate(ctx, raw); err == nil {
		t.Fatal("removed directory group retained access")
	}
	groups = []string{"cn=dns,dc=example"}
	raw, _, _, err = m.Login(ctx, "ldap", "directory-user", "domain-password")
	if err != nil {
		t.Fatal(err)
	}
	offline = true
	if _, _, _, err = m.Login(ctx, "local", "admin", testPassword); err != nil {
		t.Fatal("local fallback lost", err)
	}
	now = now.Add(6 * time.Minute)
	if _, _, err = m.Authenticate(ctx, raw); err == nil {
		t.Fatal("offline refresh failed open")
	}
}
func TestSessionExpiryAndPolicyChange(t *testing.T) {
	m := fixtureManager(t)
	ctx := context.Background()
	now := time.Now()
	m.now = func() time.Time { return now }
	raw, _, _, err := m.Login(ctx, "local", "admin", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Hour)
	if _, _, err = m.Authenticate(ctx, raw); err == nil {
		t.Fatal("expired session accepted")
	}
}
func TestBootstrapOnceAndPasswordBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-password")
	var c Config
	rev := uint64(0)
	load := func(context.Context) (Config, uint64, error) {
		if rev == 0 {
			return c, 0, ErrEmpty
		}
		return c, rev, nil
	}
	save := func(_ context.Context, next Config, expected uint64) (uint64, error) {
		if expected != rev {
			t.Fatal("unexpected revision")
		}
		c = next
		rev++
		return rev, nil
	}
	m, err := Open(context.Background(), load, save, path)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("bootstrap file permissions")
	}
	if _, _, _, err = m.Login(context.Background(), "local", "admin", strings.TrimSpace(string(bytes))); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(context.Background(), load, save, path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(bytes) || rev != 1 {
		t.Fatal("bootstrap rotated on restart")
	}
	for _, hash := range []string{"", strings.Replace(fixtureHash(t), "m=65536", "m=4294967295", 1), strings.Replace(fixtureHash(t), "v=19", "v=16", 1)} {
		if VerifyPassword(testPassword, hash) {
			t.Fatal("unsafe PHC accepted")
		}
	}
	if _, err = HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}
func TestRateAndWorkLimits(t *testing.T) {
	m := fixtureManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		if !m.Permit("peer") {
			t.Fatal("early limit")
		}
	}
	if m.Permit("peer") {
		t.Fatal("per-peer limit ignored")
	}
	now = now.Add(time.Minute + time.Second)
	if !m.Permit("peer") {
		t.Fatal("limit did not expire")
	}
	m.slots <- struct{}{}
	m.slots <- struct{}{}
	if err := m.Work(context.Background(), func() error { t.Fatal("ran beyond work bound"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	<-m.slots
	<-m.slots
}
