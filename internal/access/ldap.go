// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Directory authenticates by search and user bind. Group values are full DNs.
// password == nil performs a service-account lookup for refresh, never a login.
func Directory(ctx context.Context, cfg LDAP, username string, password *string) ([]string, error) {
	if !cfg.Enabled || strings.TrimSpace(username) == "" || (password != nil && *password == "") {
		return nil, ErrBadCredentials
	}
	if err := ValidateLDAP(cfg); err != nil {
		return nil, err
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	parsedURL, _ := url.Parse(cfg.URL)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsedURL.Hostname()}
	if cfg.CAFile != "" {
		b, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("LDAP CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("LDAP CA file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}), ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	conn.SetTimeout(timeout)
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("LDAP StartTLS failed: %w", err)
		}
	}
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("LDAP service bind failed")
	}
	attr := cfg.GroupAttribute
	if attr == "" {
		attr = "memberOf"
	}
	filter := strings.ReplaceAll(cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	result, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(timeout.Seconds()), false, filter, []string{attr, "userAccountControl"}, nil))
	if err != nil || len(result.Entries) != 1 {
		return nil, ErrBadCredentials
	}
	entry := result.Entries[0]
	if value := entry.GetEqualFoldAttributeValue("userAccountControl"); value != "" {
		flags, err := strconv.ParseUint(value, 10, 32)
		if err != nil || flags&2 != 0 {
			return nil, ErrBadCredentials
		}
	}
	if password != nil {
		if err := conn.Bind(entry.DN, *password); err != nil {
			return nil, ErrBadCredentials
		}
	}
	return entry.GetEqualFoldAttributeValues(attr), nil
}
