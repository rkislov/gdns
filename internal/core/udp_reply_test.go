// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

type replyCapture struct {
	dns.ResponseWriter
	wire       []byte
	message    *dns.Msg
	writeError error
}

func (w *replyCapture) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (w *replyCapture) TsigStatus() error { return nil }
func (w *replyCapture) Write(b []byte) (int, error) {
	w.wire = append([]byte(nil), b...)
	return len(b), w.writeError
}
func (w *replyCapture) WriteMsg(m *dns.Msg) error { w.message = m.Copy(); return nil }

func TestUDPReplyPackingOwnership(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				m := new(dns.Msg)
				m.SetQuestion("example.test.", dns.TypeA)
				m.Id = uint16(id*100 + i)
				m.Response = true
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 123}, A: net.IPv4(192, 0, 2, byte(id+1))}}
				w := new(replyCapture)
				if err := writeUDPReply(w, m); err != nil {
					t.Error(err)
					return
				}
				got := new(dns.Msg)
				if err := got.Unpack(w.wire); err != nil {
					t.Error(err)
					return
				}
				if got.Id != m.Id || got.Answer[0].String() != m.Answer[0].String() {
					t.Error("pooled reply corrupted")
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	want := errors.New("write failed")
	if err := writeUDPReply(&replyCapture{writeError: want}, new(dns.Msg)); !errors.Is(err, want) {
		t.Fatalf("write error lost: %v", err)
	}
}

func TestUDPReplyKeepsTSIGSigningPath(t *testing.T) {
	c := DefaultConfig()
	c.DNSSECValidation = false
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []bool{false, true} {
		q := query("router.home.arpa.", dns.TypeA)
		if signed {
			q.SetTsig("test-key.", dns.HmacSHA256, 300, 1)
		}
		w := new(replyCapture)
		e.ServeDNSAs(w, q, "udp")
		if signed {
			if len(w.wire) != 0 || w.message == nil || w.message.IsTsig() == nil {
				t.Fatal("TSIG bypassed library signing")
			}
		} else if len(w.wire) == 0 || w.message != nil {
			t.Fatal("unsigned UDP did not use pooled packing")
		}
	}
}
