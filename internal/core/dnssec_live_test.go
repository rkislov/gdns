// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"github.com/miekg/dns"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestDNSSECLive(t *testing.T) {
	if os.Getenv("GHOLE_DNSSEC_LIVE") == "" {
		t.Skip("opt-in Internet DNSSEC integration")
	}
	for _, mode := range []string{"forward", "recursive"} {
		t.Run(mode, func(t *testing.T) {
			c := DefaultConfig()
			c.Mode = mode
			c.DNSSECValidation = true
			e, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name string
				typ  uint16
				want int
				ad   bool
			}{{"cloudflare.com.", dns.TypeA, 0, true}, {"cloudflare.com.", dns.TypeDNSKEY, 0, true}, {"example.com.", dns.TypeA, 0, true}, {"dnssec-failed.org.", dns.TypeA, dns.RcodeServerFailure, false}, {"ghole-does-not-exist-20261105.cloudflare.com.", dns.TypeA, 0, true}, {"ghole-does-not-exist-20261105.se.", dns.TypeA, dns.RcodeNameError, true}, {"cloudflare.com.", dns.TypeDS, 0, true}, {"www.github.com.", dns.TypeA, 0, false}} {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				q := query(tc.name, tc.typ)
				q.SetEdns0(1232, true)
				m, result := e.Resolve(ctx, q, netip.MustParseAddr("127.0.0.1"))
				cancel()
				t.Logf("%s %s %s AD=%v answers=%d", tc.name, dns.TypeToString[tc.typ], result, m.AuthenticatedData, len(m.Answer))
				if m.Rcode != tc.want || m.AuthenticatedData != tc.ad {
					t.Errorf("unexpected result: %v", m)
				}
			}
		})
	}
}
