// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"testing"
)

func BenchmarkValidateChain(b *testing.B) {
	for _, cold := range []bool{false, true} {
		name := "cached-chain"
		if cold {
			name = "uncached-leaf"
		}
		b.Run(name, func(b *testing.B) {
			h := fixture(b)
			v, err := New(h.config)
			if err != nil {
				b.Fatal(err)
			}
			m := h.positive()
			q := new(dns.Msg)
			q.Question = m.Question
			if _, err = v.Validate(context.Background(), q, m, "fixture", h.fetch); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if cold {
					delete(v.cache, "fixture|www.secure.test.")
				}
				if _, err = v.Validate(context.Background(), q, m, "fixture", h.fetch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
