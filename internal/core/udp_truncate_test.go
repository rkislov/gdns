// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestUDPTruncationMatchesLibrary(t *testing.T) {
	names := []string{"a.test.", "a\\.b.test.", "a\\046b.test.", ".", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + "."}
	for _, name := range names {
		for _, kind := range []string{"A 192.0.2.1", "AAAA 2001:db8::1", "TXT \"fallback\""} {
			for _, size := range []int{0, 512, 1232} {
				for _, edns := range []bool{false, true} {
					for _, tc := range []bool{false, true} {
						rr, err := dns.NewRR(name + " 300 IN " + kind)
						if err != nil {
							t.Fatal(err)
						}
						m := new(dns.Msg)
						m.SetQuestion(name, dns.TypeA)
						m.Response = true
						m.Compress = true
						m.Truncated = tc
						m.Answer = []dns.RR{rr}
						if edns {
							m.SetEdns0(1232, true)
						}
						reference := m.Copy()
						reference.Truncate(size)
						truncateUDPReply(m, size)
						want, e1 := reference.Pack()
						got, e2 := m.Pack()
						if e1 != nil || e2 != nil || !bytes.Equal(got, want) {
							t.Fatalf("mismatch %q %s size=%d edns=%t: %v %v", name, kind, size, edns, e1, e2)
						}
					}
				}
			}
		}
	}
}
func BenchmarkUDPTruncation(b *testing.B) {
	for _, fast := range []bool{false, true} {
		name := "library"
		if fast {
			name = "bounded"
		}
		b.Run(name, func(b *testing.B) {
			m := new(dns.Msg)
			m.SetQuestion("n100.bench.test.", dns.TypeA)
			rr, _ := dns.NewRR("n100.bench.test. 300 IN A 192.0.2.1")
			m.Answer = []dns.RR{rr}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if fast {
					truncateUDPReply(m, 512)
				} else {
					m.Truncate(512)
				}
			}
		})
	}
}
