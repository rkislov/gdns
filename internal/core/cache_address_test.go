// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"github.com/miekg/dns"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAddressCacheOwnershipAndTTL(t *testing.T) {
	for index, record := range []string{"a.example. 300 IN A 192.0.2.1", "a.example. 300 IN AAAA 2001:db8::1", "a.example. 300 IN A 192.0.2.1"} {
		rr, _ := dns.NewRR(record)
		if index == 2 {
			rr.(*dns.A).A = net.IPv4(192, 0, 2, 1)
		}
		m := new(dns.Msg)
		m.Answer = []dns.RR{rr}
		c := newCache(64)
		k := cacheKey{name: "a.example.", qtype: rr.Header().Rrtype}
		c.put(k, m)
		s := c.shard(k)
		s.Lock()
		v := s.items[k]
		v.at = time.Now().Add(-10 * time.Second)
		s.items[k] = v
		s.Unlock()
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					r := c.getReply(k, j%2 == 0)
					if r == nil || r.Answer[0].Header().Ttl < 288 || r.Answer[0].Header().Ttl > 290 {
						t.Error("TTL mismatch")
						return
					}
					r.Answer[0].Header().Ttl = 0
					switch a := r.Answer[0].(type) {
					case *dns.A:
						if a.A.String() != "192.0.2.1" {
							t.Error("shared address")
						}
						a.A[0] = 99
					case *dns.AAAA:
						if a.AAAA.String() != "2001:db8::1" {
							t.Error("shared IPv6")
						}
						a.AAAA[0] = 99
					}
					if len(r.Extra) > 0 {
						r.Extra[0].(*dns.OPT).Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "abcd"}}
					}
				}
			}()
		}
		wg.Wait()
	}
}
