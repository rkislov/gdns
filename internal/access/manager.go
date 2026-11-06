// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Load func(context.Context) (Config, uint64, error)
type Save func(context.Context, Config, uint64) (uint64, error)
type DirectoryFunc func(context.Context, LDAP, string, *string) ([]string, error)
type Principal struct {
	Username string `json:"username"`
	Source   string `json:"source"`
	Role     string `json:"role"`
}
type snapshot struct {
	Config   Config
	Revision uint64
}
type session struct {
	Principal
	Hash             string
	LDAPDigest       [32]byte
	Groups           []string
	Expires, Checked time.Time
	CSRF             string
}
type attempt struct {
	At    time.Time
	Count int
}
type Manager struct {
	state      atomic.Pointer[snapshot]
	writeMu    sync.Mutex
	save       Save
	sessionsMu sync.Mutex
	sessions   map[[32]byte]session
	attemptsMu sync.Mutex
	attempts   map[string]attempt
	global     attempt
	slots      chan struct{}
	dummy      string
	directory  DirectoryFunc
	now        func() time.Time
}

func randomSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func clone(c Config) Config {
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	return out
}
func Open(ctx context.Context, load Load, save Save, passwordFile string) (*Manager, error) {
	c, rev, err := load(ctx)
	if errors.Is(err, ErrEmpty) {
		password := ""
		existing, e := os.ReadFile(passwordFile)
		if e == nil {
			password = strings.TrimSpace(string(existing))
			if len(password) < 24 {
				return nil, fmt.Errorf("invalid bootstrap password file")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		} else {
			password, e = randomSecret()
			if e != nil {
				return nil, e
			}
			f, e := os.OpenFile(passwordFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return nil, e
			}
			_, e = f.WriteString(password + "\n")
			if e == nil {
				e = f.Sync()
			}
			closeErr := f.Close()
			if e != nil {
				return nil, e
			}
			if closeErr != nil {
				return nil, closeErr
			}
		}
		hash, e := HashPassword(password)
		if e != nil {
			return nil, e
		}
		c = Config{Users: []User{{Username: "admin", Role: "admin", PasswordHash: hash}}, LDAP: LDAP{UserFilter: "(sAMAccountName={username})", GroupAttribute: "memberOf", TimeoutSeconds: 5, Groups: []Group{}}}
		rev, err = save(ctx, c, rev)
	}
	if err != nil {
		return nil, err
	}
	if err = Validate(c); err != nil {
		return nil, err
	}
	// Reuse a valid PHC hash for timing-equivalent unknown-user verification.
	m := &Manager{save: save, sessions: map[[32]byte]session{}, attempts: map[string]attempt{}, slots: make(chan struct{}, 2), dummy: c.Users[0].PasswordHash, directory: Directory, now: time.Now}
	m.state.Store(&snapshot{clone(c), rev})
	return m, nil
}
func (m *Manager) Snapshot() (Config, uint64) {
	s := m.state.Load()
	return clone(s.Config), s.Revision
}
func (m *Manager) View() (Config, uint64) {
	c, r := m.Snapshot()
	for i := range c.Users {
		c.Users[i].PasswordHash = ""
	}
	if c.LDAP.BindPassword != "" {
		c.LDAP.BindPassword = "***"
	}
	return c, r
}
func (m *Manager) Update(ctx context.Context, revision uint64, edit func(*Config) error) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	old := m.state.Load()
	if revision != old.Revision {
		return fmt.Errorf("access configuration changed; reload")
	}
	c := clone(old.Config)
	if err := edit(&c); err != nil {
		return err
	}
	if err := Validate(c); err != nil {
		return err
	}
	rev, err := m.save(ctx, c, old.Revision)
	if err != nil {
		return err
	}
	m.state.Store(&snapshot{c, rev})
	return nil
}

// Limit password/directory work without touching the DNS request path.
func (m *Manager) Permit(peer string) bool {
	m.attemptsMu.Lock()
	defer m.attemptsMu.Unlock()
	now := m.now()
	if now.Sub(m.global.At) >= time.Minute {
		m.global = attempt{At: now}
	}
	if m.global.Count >= 30 {
		return false
	}
	a := m.attempts[peer]
	if now.Sub(a.At) >= time.Minute {
		a = attempt{At: now}
	}
	if a.Count >= 10 {
		return false
	}
	if len(m.attempts) >= 4096 {
		for k, v := range m.attempts {
			if now.Sub(v.At) > time.Minute {
				delete(m.attempts, k)
			}
		}
		if len(m.attempts) >= 4096 {
			return false
		}
	}
	a.Count++
	m.global.Count++
	m.attempts[peer] = a
	return true
}
func (m *Manager) Work(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
		return fn()
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ErrBusy
	}
}
func ldapDigest(c LDAP) [32]byte { b, _ := json.Marshal(c); return sha256.Sum256(b) }
func local(c Config, name string) (User, bool) {
	for _, u := range c.Users {
		if strings.EqualFold(u.Username, name) {
			return u, true
		}
	}
	return User{}, false
}
func (m *Manager) Login(ctx context.Context, source, name, password string) (string, string, Principal, error) {
	if len(name) == 0 || len(name) > 256 || len(password) == 0 || len(password) > 1024 {
		return "", "", Principal{}, ErrBadCredentials
	}
	s := m.state.Load()
	entry := session{Principal: Principal{Username: name, Source: source}, Expires: m.now().Add(8 * time.Hour), Checked: m.now()}
	err := m.Work(ctx, func() error {
		switch source {
		case "local":
			u, ok := local(s.Config, name)
			hash := m.dummy
			if ok {
				hash = u.PasswordHash
			}
			valid := VerifyPassword(password, hash)
			if !ok || u.Disabled || !valid {
				return ErrBadCredentials
			}
			entry.Username = u.Username
			entry.Role = u.Role
			entry.Hash = u.PasswordHash
		case "ldap":
			if _, ok := local(s.Config, name); ok {
				return ErrBadCredentials
			}
			groups, err := m.directory(ctx, s.Config.LDAP, name, &password)
			if err != nil {
				return ErrBadCredentials
			}
			entry.Groups = groups
			entry.Role = directoryRole(s.Config.LDAP, groups)
			entry.LDAPDigest = ldapDigest(s.Config.LDAP)
			if entry.Role == "" {
				return ErrBadCredentials
			}
		default:
			return ErrBadCredentials
		}
		return nil
	})
	if err != nil {
		return "", "", Principal{}, err
	}
	raw, err := randomSecret()
	if err != nil {
		return "", "", Principal{}, err
	}
	entry.CSRF, err = randomSecret()
	if err != nil {
		return "", "", Principal{}, err
	}
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	count := 0
	var oldestKey [32]byte
	var oldest time.Time
	for key, value := range m.sessions {
		if !value.Expires.After(m.now()) {
			delete(m.sessions, key)
			continue
		}
		if value.Source == entry.Source && value.Username == entry.Username {
			count++
			if oldest.IsZero() || value.Expires.Before(oldest) {
				oldest = value.Expires
				oldestKey = key
			}
		}
	}
	if count >= 8 {
		delete(m.sessions, oldestKey)
	}
	if len(m.sessions) >= 8192 {
		return "", "", Principal{}, ErrBusy
	}
	m.sessions[sha256.Sum256([]byte(raw))] = entry
	return raw, entry.CSRF, entry.Principal, nil
}
func (m *Manager) Authenticate(ctx context.Context, raw string) (Principal, string, error) {
	if len(raw) != 64 {
		return Principal{}, "", ErrBadCredentials
	}
	key := sha256.Sum256([]byte(raw))
	m.sessionsMu.Lock()
	entry, ok := m.sessions[key]
	m.sessionsMu.Unlock()
	if !ok || !entry.Expires.After(m.now()) {
		m.Logout(raw)
		return Principal{}, "", ErrBadCredentials
	}
	cfg := m.state.Load().Config
	if entry.Source == "local" {
		u, ok := local(cfg, entry.Username)
		if !ok || u.Disabled || u.PasswordHash != entry.Hash {
			m.Logout(raw)
			return Principal{}, "", ErrBadCredentials
		}
		entry.Role = u.Role
	} else {
		if !cfg.LDAP.Enabled || entry.LDAPDigest != ldapDigest(cfg.LDAP) {
			m.Logout(raw)
			return Principal{}, "", ErrBadCredentials
		}
		if _, exists := local(cfg, entry.Username); exists {
			m.Logout(raw)
			return Principal{}, "", ErrBadCredentials
		}
		if m.now().Sub(entry.Checked) >= 5*time.Minute {
			err := m.Work(ctx, func() error {
				groups, err := m.directory(ctx, cfg.LDAP, entry.Username, nil)
				if err != nil {
					return err
				}
				entry.Groups = groups
				entry.Checked = m.now()
				return nil
			})
			if err != nil {
				m.Logout(raw)
				return Principal{}, "", ErrBadCredentials
			}
			m.sessionsMu.Lock()
			if current, exists := m.sessions[key]; exists && current.CSRF == entry.CSRF {
				m.sessions[key] = entry
			}
			m.sessionsMu.Unlock()
		}
		entry.Role = directoryRole(cfg.LDAP, entry.Groups)
		if entry.Role == "" {
			m.Logout(raw)
			return Principal{}, "", ErrBadCredentials
		}
	}
	return entry.Principal, entry.CSRF, nil
}
func (m *Manager) Logout(raw string) {
	m.sessionsMu.Lock()
	delete(m.sessions, sha256.Sum256([]byte(raw)))
	m.sessionsMu.Unlock()
}
func (m *Manager) DirectoryTest(ctx context.Context, c LDAP, name string) ([]string, string, error) {
	if c.BindPassword == "***" {
		c.BindPassword = m.state.Load().Config.LDAP.BindPassword
	}
	c.Enabled = true
	var groups []string
	err := m.Work(ctx, func() error { var e error; groups, e = m.directory(ctx, c, name, nil); return e })
	return groups, directoryRole(c, groups), err
}
