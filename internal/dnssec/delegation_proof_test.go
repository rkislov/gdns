// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package dnssec

import (
	"context"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestInternalDSProofAuthenticatesDenialOnly(t *testing.T) {
	h := fixture(t)
	v, err := New(h.config)
	if err != nil {
		t.Fatal(err)
	}
	r := &validationRun{v: v, ctx: context.Background(), fetch: h.fetch, route: "test", memo: map[string]zoneState{}}
	if _, err = r.state("secure.test.", 0); err != nil {
		t.Fatal(err)
	}
	r.signatures = 0
	m := h.messages[messageKey("www.secure.test.", dns.TypeDS)]
	m.Ns[0].(*dns.SOA).Serial++ // This SOA is not used to authenticate the delegation.
	s, err := r.state("www.secure.test.", 0)
	if err != nil || !s.secure {
		t.Fatalf("valid NSEC proof: %v", err)
	}
	if r.signatures != 1 {
		t.Fatalf("expected one NSEC signature check, got %d", r.signatures)
	}
	if time.Until(s.expires) > 60*time.Second {
		t.Fatal("conservative SOA lifetime bound lost")
	}
	answer := h.positive()
	q := new(dns.Msg)
	q.Question = answer.Question
	out, err := v.Validate(context.Background(), q, answer, "test", h.fetch)
	if err != nil || !out.Message.AuthenticatedData || len(out.Message.Ns) != 0 {
		t.Fatalf("internal SOA must not leak into authenticated client answer: %v", err)
	}
}

func TestInternalDSProofStillRejectsInvalidDenial(t *testing.T) {
	for _, kind := range []string{"tampered", "expired", "absent"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			m := h.messages[messageKey("www.secure.test.", dns.TypeDS)]
			switch kind {
			case "tampered":
				m.Ns[2].(*dns.NSEC).TypeBitMap = append(m.Ns[2].(*dns.NSEC).TypeBitMap, dns.TypeDS)
			case "expired":
				m.Ns[3].(*dns.RRSIG).Expiration = uint32(time.Now().Add(-time.Hour).Unix())
			case "absent":
				m.Ns = m.Ns[:2]
			}
			if _, err := h.validate(h.positive()); err == nil {
				t.Fatal("invalid delegation proof accepted")
			}
		})
	}
}

func TestClientNegativeAnswerStillAuthenticatesSOA(t *testing.T) {
	h := fixture(t)
	m := h.nodata("www.secure.test.", dns.TypeAAAA, []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG})
	m.Ns[0].(*dns.SOA).Serial++
	if _, err := h.validate(m); err == nil {
		t.Fatal("client received negative answer with invalid SOA signature")
	}
}

func TestInternalDSNSEC3ProofAuthenticity(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		h := fixture(t)
		ns := signed(t, h.child, h.soa(h.child))
		ns = append(ns, h.nsec3Set(h.child, []string{"secure.test.", "www.secure.test."}, 0, 0)...)
		if tamper {
			for _, rr := range ns {
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNSEC3 {
					sig.Signature = "AAAA"
				}
			}
		}
		h.put(reply("www.secure.test.", dns.TypeDS, nil, ns, 0))
		out, err := h.validate(h.positive())
		if tamper && err == nil {
			t.Fatal("tampered NSEC3 proof accepted")
		}
		if !tamper && (err != nil || !out.Message.AuthenticatedData) {
			t.Fatalf("valid NSEC3 proof failed: %v", err)
		}
	}
}
