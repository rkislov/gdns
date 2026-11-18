//go:build linux && gdns_udp_addrport

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"bytes"
	"context"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUDPBatchAddressesTSIGAndConcurrency(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:0", "0.0.0.0:0", "[::1]:0", "[::]:0"} {
		t.Run(bind, func(t *testing.T) {
			conns, err := ListenUDP(bind, 1)
			if err != nil {
				t.Fatal(err)
			}
			ready := make(chan struct{})
			secret := "dGVzdC1zZWNyZXQ="
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				if _, ok := w.RemoteAddr().(*net.UDPAddr); !ok {
					t.Error("source IP type changed")
				}
				m := new(dns.Msg)
				m.SetReply(q)
				m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: 1, Ttl: 60}, Txt: []string{strings.Repeat("a", 200)}}}
				if tsig := q.IsTsig(); tsig != nil {
					if w.TsigStatus() != nil {
						t.Error(w.TsigStatus())
					}
					m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
				}
				if err := w.WriteMsg(m); err != nil {
					t.Error(err)
				}
			})
			server := NewUDPServer(conns[0], handler, nil)
			server.TsigSecret = map[string]string{"key.test.": secret}
			server.NotifyStartedFunc = func() { close(ready) }
			done := make(chan error, 1)
			go func() { done <- server.ActivateAndServe() }()
			<-ready
			host, port, _ := net.SplitHostPort(conns[0].LocalAddr().String())
			hosts := []string{host}
			if net.ParseIP(host).IsUnspecified() {
				hosts = []string{"127.0.0.1", "127.0.0.2"}
				if strings.Contains(host, ":") {
					hosts = append(hosts, "::1")
				}
			}
			var wg sync.WaitGroup
			for _, host := range hosts {
				for worker := 0; worker < 8; worker++ {
					wg.Add(1)
					go func(host string) {
						defer wg.Done()
						client := dns.Client{Timeout: 2 * time.Second, TsigSecret: map[string]string{"key.test.": secret}}
						for i := 0; i < 30; i++ {
							q := new(dns.Msg)
							q.SetQuestion("batch.test.", dns.TypeTXT)
							if i%2 == 0 {
								q.SetTsig("key.test.", dns.HmacSHA256, 300, time.Now().Unix())
							}
							r, _, err := client.Exchange(q, net.JoinHostPort(host, port))
							if err != nil {
								t.Error(err)
								return
							}
							if r.Id != q.Id || len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != strings.Repeat("a", 200) {
								t.Error("corrupt batched response")
								return
							}
						}
					}(host)
				}
			}
			wg.Wait()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPReplyControlMatchesSourceOnly(t *testing.T) {
	for _, ip := range []net.IP{net.ParseIP("192.0.2.21"), net.ParseIP("2001:db8::21"), net.ParseIP("::ffff:192.0.2.21")} {
		var incoming, want []byte
		if ip.To4() != nil {
			incoming = (&ipv4.ControlMessage{Src: net.ParseIP("192.0.2.99"), IfIndex: 42}).Marshal()
			copy(incoming[unix.CmsgLen(0)+8:], ip.To4())
			want = (&ipv4.ControlMessage{Src: ip}).Marshal()
		} else {
			incoming = (&ipv6.ControlMessage{Src: ip, IfIndex: 42}).Marshal()
			want = (&ipv6.ControlMessage{Src: ip}).Marshal()
		}
		p := new(udpPacketPeer)
		p.setReplyControl(incoming)
		clear(incoming)
		if !bytes.Equal(p.replyControl, want) {
			t.Fatalf("source control changed for %s", ip)
		}
	}
	for i := 0; i < 64; i++ {
		p := new(udpPacketPeer)
		p.setReplyControl(make([]byte, i))
		if len(p.replyControl) != 0 {
			t.Fatal("malformed control accepted")
		}
	}
}
