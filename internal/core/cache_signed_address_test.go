// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"context"
	"gdns/internal/telemetry"
	"github.com/miekg/dns"
	"net/netip"
	"testing"
	"time"
)

func BenchmarkSignedAddressWithoutDO(b *testing.B) {
	for _, edns := range []bool{false, true} {
		name := "plain"
		if edns {
			name = "edns"
		}
		b.Run(name, func(b *testing.B) {
			c := DefaultConfig()
			c.DNSSECValidation = true
			c.QueryLog = false
			e, err := New(c)
			if err != nil {
				b.Fatal(err)
			}
			e.SetObserver(telemetry.New(b.TempDir()))
			q := query("cached.invalid.", dns.TypeA)
			q.AuthenticatedData = true
			if edns {
				q.SetEdns0(1232, false)
			}
			m := new(dns.Msg)
			m.SetReply(q)
			m.AuthenticatedData = true
			rr, _ := dns.NewRR("cached.invalid. 3600 IN A 192.0.2.1")
			sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "cached.invalid.", Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 3600}, TypeCovered: dns.TypeA, Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
			m.Answer = []dns.RR{rr, sig}
			e.state.Load().cache.put(responseCacheKey("cached.invalid.", dns.TypeA, false, false, nil), m)
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

func TestSignedAddressCacheClientFlagsAndExpiry(t *testing.T) {
	for _, text := range []string{"signed.invalid. 300 IN A 192.0.2.1", "signed.invalid. 300 IN AAAA 2001:db8::1"} {
		for _, do := range []bool{false, true} {
			for _, edns := range []bool{false, true} {
				if do && !edns {
					continue
				}
				rr, err := dns.NewRR(text)
				if err != nil {
					t.Fatal(err)
				}
				q := query("signed.invalid.", rr.Header().Rrtype)
				q.AuthenticatedData = true
				if edns {
					q.SetEdns0(1232, do)
				}
				m := new(dns.Msg)
				m.SetReply(q)
				m.AuthenticatedData = true
				sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 300}, TypeCovered: rr.Header().Rrtype, Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
				// Signature-first order and a rollover with two signatures must both work.
				m.Answer = []dns.RR{sig, rr, dns.Copy(sig)}
				c := newCache(64)
				k := cacheKey{name: q.Question[0].Name, qtype: q.Question[0].Qtype, do: do}
				c.put(k, m)
				for i := 0; i < 2; i++ {
					got := c.getReply(k, edns)
					if got == nil {
						t.Fatal("valid cache entry missing")
					}
					got.Question = q.Question
					got = clientResponse(got, q)
					want := 1
					if do {
						want = 3
					}
					if len(got.Answer) != want || !got.AuthenticatedData {
						t.Fatal("client flags/signatures changed", got)
					}
					for _, r := range got.Answer {
						if r.Header().Ttl != 300 {
							t.Fatal("cached TTL was mutated")
						}
						r.Header().Ttl = 1
						switch a := r.(type) {
						case *dns.A:
							if a.A.String() != "192.0.2.1" {
								t.Fatal("shared IPv4")
							}
							a.A[0] ^= 255
						case *dns.AAAA:
							if a.AAAA.String() != "2001:db8::1" {
								t.Fatal("shared IPv6")
							}
							a.AAAA[0] ^= 255
						}
					}
				}
				shard := c.shard(k)
				shard.Lock()
				entry := shard.items[k]
				entry.msg.Answer[0].(*dns.RRSIG).Expiration = uint32(time.Now().Add(-time.Minute).Unix())
				shard.Unlock()
				if c.getReply(k, edns) != nil {
					t.Fatal("expired signature bypassed by address fast path")
				}
				shard.Lock()
				entry.msg.Answer[0].(*dns.RRSIG).Expiration = uint32(time.Now().Add(time.Hour).Unix())
				entry.msg.Answer[0].(*dns.RRSIG).Inception = uint32(time.Now().Add(time.Minute).Unix())
				shard.Unlock()
				if c.getReply(k, edns) != nil {
					t.Fatal("future signature bypassed by address fast path")
				}
			}
		}
	}
}
