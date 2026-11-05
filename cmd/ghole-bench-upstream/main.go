// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// A loopback-only signed DNS fixture for reproducible performance tests.
// This helper is not included in release artifacts.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	address := flag.String("listen", "127.0.0.1:1154", "loopback UDP/TCP address")
	anchor := flag.String("anchor", "", "write the public DNSKEY trust anchor")
	flag.Parse()
	host, _, err := net.SplitHostPort(*address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("benchmark fixture requires a literal loopback address")
	}
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "cache.bench.invalid.", Rrtype: dns.TypeDNSKEY, Class: 1, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	private, err := key.Generate(256)
	if err != nil {
		log.Fatal(err)
	}
	sign := func(records []dns.RR) ([]dns.RR, error) {
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: records[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: 1, Ttl: 3600}, TypeCovered: records[0].Header().Rrtype, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(records[0].Header().Name)), OrigTtl: records[0].Header().Ttl, Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: key.Hdr.Name}
		if err := sig.Sign(private.(crypto.Signer), records); err != nil {
			return nil, err
		}
		return append(records, sig), nil
	}
	if *anchor != "" {
		if err := os.WriteFile(*anchor, []byte(key.String()+"\n"), 0600); err != nil {
			log.Fatal(err)
		}
	}
	soa, _ := dns.NewRR("cache.bench.invalid. 3600 IN SOA ns.cache.bench.invalid. hostmaster.cache.bench.invalid. 1 3600 600 86400 3600")
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		if len(q.Question) != 1 {
			m.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		question := q.Question[0]
		name := dns.CanonicalName(question.Name)
		if !strings.HasSuffix(name, ".cache.bench.invalid.") && name != "cache.bench.invalid." {
			m.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		var err error
		switch {
		case question.Qtype == dns.TypeDNSKEY && name == key.Hdr.Name:
			m.Answer, err = sign([]dns.RR{dns.Copy(key)})
		case question.Qtype == dns.TypeA:
			a := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: 1, Ttl: 3600}, A: net.ParseIP("192.0.2.77").To4()}
			m.Answer, err = sign([]dns.RR{a})
		default:
			n := &dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: 1, Ttl: 3600}, NextDomain: "zzzz.cache.bench.invalid.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}}
			a, e := sign([]dns.RR{dns.Copy(soa)})
			if e != nil {
				err = e
				break
			}
			b, e := sign([]dns.RR{n})
			err = e
			m.Ns = append(a, b...)
		}
		if err != nil {
			m.Answer = nil
			m.Ns = nil
			m.Rcode = dns.RcodeServerFailure
		}
		if opt := q.IsEdns0(); opt != nil {
			m.SetEdns0(1232, opt.Do())
		}
		_ = w.WriteMsg(m)
	})
	udp, err := net.ListenPacket("udp", *address)
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	defer tcp.Close()
	us := &dns.Server{PacketConn: udp, Handler: handler, UDPSize: 1232}
	ts := &dns.Server{Listener: tcp, Handler: handler, MaxTCPQueries: -1}
	go func() {
		if err := us.ActivateAndServe(); err != nil {
			log.Print(err)
		}
	}()
	go func() {
		if err := ts.ActivateAndServe(); err != nil {
			log.Print(err)
		}
	}()
	fmt.Println("Signed loopback fixture ready:", *address)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	_ = us.Shutdown()
	_ = ts.Shutdown()
}
