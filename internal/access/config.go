// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package access

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var ErrBadCredentials = errors.New("invalid credentials")
var ErrEmpty = errors.New("access configuration is empty")
var ErrBusy = errors.New("authentication temporarily busy")
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash,omitempty"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled"`
}
type Group struct {
	DN   string `json:"dn"`
	Role string `json:"role"`
}
type LDAP struct {
	Enabled        bool    `json:"enabled"`
	URL            string  `json:"url"`
	StartTLS       bool    `json:"start_tls"`
	CAFile         string  `json:"ca_file,omitempty"`
	BindDN         string  `json:"bind_dn"`
	BindPassword   string  `json:"bind_password,omitempty"`
	BaseDN         string  `json:"base_dn"`
	UserFilter     string  `json:"user_filter"`
	GroupAttribute string  `json:"group_attribute,omitempty"`
	TimeoutSeconds int     `json:"timeout_seconds,omitempty"`
	Groups         []Group `json:"groups"`
}
type Config struct {
	Users []User `json:"users"`
	LDAP  LDAP   `json:"ldap"`
}

func Rank(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	}
	return 0
}
func ValidateLDAP(c LDAP) error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return fmt.Errorf("LDAP URL must use ldaps:// or ldap:// with StartTLS")
	}
	if u.Scheme == "ldap" && !c.StartTLS || u.Scheme == "ldaps" && c.StartTLS {
		return fmt.Errorf("LDAP requires LDAPS or ldap:// with StartTLS")
	}
	if c.BindDN == "" || c.BindPassword == "" || c.BaseDN == "" {
		return fmt.Errorf("LDAP bind_dn, bind_password and base_dn are required")
	}
	if len(c.BindPassword) > 4096 || len(c.UserFilter) > 4096 || !strings.Contains(c.UserFilter, "{username}") {
		return fmt.Errorf("invalid LDAP filter or credentials length")
	}
	if _, err := ldap.ParseDN(c.BaseDN); err != nil {
		return fmt.Errorf("invalid LDAP base DN")
	}
	if _, err := ldap.CompileFilter(strings.ReplaceAll(c.UserFilter, "{username}", "test")); err != nil {
		return fmt.Errorf("invalid LDAP user filter")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 30 {
		return fmt.Errorf("LDAP timeout must be 0..30 seconds")
	}
	return nil
}
func Validate(c Config) error {
	if len(c.Users) == 0 || len(c.Users) > 256 {
		return fmt.Errorf("configure 1..256 local users")
	}
	admins := 0
	names := map[string]bool{}
	for _, u := range c.Users {
		key := strings.ToLower(u.Username)
		if !usernamePattern.MatchString(u.Username) || names[key] || Rank(u.Role) == 0 || !validHash(u.PasswordHash) {
			return fmt.Errorf("invalid or duplicate local user")
		}
		names[key] = true
		if u.Role == "admin" && !u.Disabled {
			admins++
		}
	}
	if admins == 0 {
		return fmt.Errorf("at least one enabled local administrator must remain")
	}
	if len(c.LDAP.Groups) > 128 {
		return fmt.Errorf("too many LDAP group rules")
	}
	for _, g := range c.LDAP.Groups {
		if _, err := ldap.ParseDN(g.DN); err != nil || g.DN == "" || Rank(g.Role) == 0 {
			return fmt.Errorf("invalid LDAP group DN or role")
		}
	}
	if c.LDAP.Enabled && len(c.LDAP.Groups) == 0 {
		return fmt.Errorf("LDAP requires at least one allowed group")
	}
	return ValidateLDAP(c.LDAP)
}
func directoryRole(c LDAP, groups []string) string {
	role := ""
	for _, grant := range c.Groups {
		want, err := ldap.ParseDN(grant.DN)
		if err != nil {
			continue
		}
		for _, value := range groups {
			got, err := ldap.ParseDN(value)
			if err == nil && want.EqualFold(got) && Rank(grant.Role) > Rank(role) {
				role = grant.Role
			}
		}
	}
	return role
}
