// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"sync"
	"testing"
)

func TestConcurrentValidationOwnsAnswerRecords(t *testing.T) {
	h := fixture(t)
	v, err := New(h.config)
	if err != nil {
		t.Fatal(err)
	}
	m := h.positive()
	before := m.String()
	q := new(dns.Msg)
	q.Question = m.Question
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := v.Validate(context.Background(), q, m, "view", h.fetch)
			if err != nil {
				t.Error(err)
				return
			}
			if !out.Message.AuthenticatedData {
				t.Error("missing AD")
				return
			}
			out.Message.Answer[0].(*dns.A).A[0] ^= 255
			out.Message.Answer[0].Header().Ttl = 0
		}()
	}
	wg.Wait()
	if m.String() != before {
		t.Fatal("concurrent validation mutated shared input")
	}
}

func TestFinishStillRemovesSameTypeDuplicates(t *testing.T) {
	h := fixture(t)
	a := h.positive().Answer[0]
	m := reply("www.secure.test.", dns.TypeA, []dns.RR{a, dns.Copy(a)}, nil, 0)
	r := &validationRun{}
	r.finish(m, m.Copy(), true, expiry(m))
	if len(m.Answer) != 1 {
		t.Fatal("duplicate address survived")
	}
}
