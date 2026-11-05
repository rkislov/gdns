// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"fmt"
	"gdns/internal/telemetry"
	"github.com/miekg/dns"
	"net/netip"
	"testing"
	"time"
)

// These benchmarks include the production accounting, Prometheus observer and
// optional journal. They intentionally exclude socket/TLS costs (measured separately).
func BenchmarkAnswerFastPath(b *testing.B) {
	for _, kind := range []string{"Primary", "Split", "Blocked", "Cache", "SecureCache"} {
		for _, logging := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/log=%t", kind, logging), func(b *testing.B) {
				c := DefaultConfig()
				c.QueryLog = logging
				c.DNSSECValidation = true
				name := "router.home.arpa."
				switch kind {
				case "Split":
					c.Zones[0].RecordViews = []RecordView{{Clients: []string{"127.0.0.0/28"}, Records: []string{"router.home.arpa. 300 IN A 10.28.0.1"}}}
				case "Blocked":
					c.Blocked = []string{"blocked.invalid."}
					name = "sub.blocked.invalid."
				case "Cache", "SecureCache":
					name = "cached.invalid."
				}
				e, err := New(c)
				if err != nil {
					b.Fatal(err)
				}
				e.SetObserver(telemetry.New(b.TempDir()))
				q := query(name, dns.TypeA)
				q.SetEdns0(1232, kind == "SecureCache")
				if kind == "Cache" || kind == "SecureCache" {
					m := new(dns.Msg)
					m.SetReply(q)
					a, _ := dns.NewRR(name + " 3600 IN A 192.0.2.1")
					m.Answer = []dns.RR{a}
					if kind == "SecureCache" {
						m.AuthenticatedData = true
						m.Answer = append(m.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 3600}, Expiration: uint32(time.Now().Add(time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix())})
					}
					e.state.Load().cache.put(fmt.Sprintf("%s/1/%t/false", name, kind == "SecureCache"), m)
				}
				ip := netip.MustParseAddr("127.0.0.1")
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						e.AnswerAs(context.Background(), q, ip, "udp")
					}
				})
			})
		}
	}
}
func BenchmarkJournalPage100000(b *testing.B) {
	c := DefaultConfig()
	c.QueryLogLimit = 100000
	e, err := New(c)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 100000; i++ {
		e.log(QueryLog{Time: "2026-11-05T12:00:00Z", Client: "192.0.2.1", Name: "example.", Type: "A", Result: "NOERROR"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.QueryLogs(2000, 25, 0)
	}
}
