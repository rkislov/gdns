// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
// Open-loop DNS generator. One paced sender and eight independent receivers.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type pending struct {
	sent, scheduled time.Time
	name            string
	unique          bool
}
type result struct {
	Sent, OK, Errors, Timeouts     int
	Latencies, Lateness, Scheduled []float64
	Last                           time.Time
	UniqueNames, RepeatedNames     []float64
}
type worker struct {
	conn    net.Conn
	mu      sync.Mutex
	pending map[uint16]pending
	r       result
	done    chan struct{}
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	return v[int(float64(len(v)-1)*p)]
}
func spinUntil(deadline time.Time) {
	for time.Now().Before(deadline) {
	}
}

func main() {
	addr := flag.String("server", "127.0.0.1:53", "")
	rate := flag.Int("rate", 5000, "")
	seconds := flag.Int("seconds", 10, "")
	transport := flag.String("transport", "udp", "")
	mode := flag.String("mode", "warm", "warm/miss/mixed")
	prime := flag.Bool("prime", false, "")
	check := flag.Bool("check", false, "")
	pacing := flag.String("pacing", "spin", "spin or Linux high-resolution sleep")
	zone := flag.String("zone", "bench.test.", "fixture zone")
	expectedIP := flag.String("answer-ip", "192.0.2.1", "expected A answer")
	requireAD := flag.Bool("require-ad", false, "require validated AD responses")
	localPortBase := flag.Int("local-port-base", 0, "optional fixed UDP source ports for reproducible worker distribution")
	flag.Parse()
	*zone = dns.Fqdn(*zone)
	if *check {
		checkAnswers(*addr, *transport)
		return
	}
	if *prime {
		for i := 0; i < 512; i++ {
			q := new(dns.Msg)
			q.SetQuestion(fmt.Sprintf("n%d.%s", i, *zone), dns.TypeA)
			q.AuthenticatedData = *requireAD
			c := dns.Client{Net: *transport, Timeout: time.Second}
			r, _, err := c.Exchange(q, *addr)
			if err != nil || r.Rcode != 0 || len(r.Answer) != 1 || (*requireAD && !r.AuthenticatedData) {
				os.Exit(1)
			}
		}
		return
	}
	const count = 8
	if *rate <= 0 || *seconds <= 0 || *rate**seconds/count >= 65536 {
		panic("invalid rate/duration or transaction ID reuse")
	}
	workers := make([]*worker, count)
	for i := range workers {
		dialer := net.Dialer{Timeout: time.Second}
		if *localPortBase != 0 {
			if *transport != "udp" || *localPortBase < 1024 || *localPortBase+count-1 > 65535 {
				panic("invalid fixed UDP source-port range")
			}
			dialer.LocalAddr = &net.UDPAddr{Port: *localPortBase + i}
		}
		conn, err := dialer.Dial(*transport, *addr)
		if err != nil {
			panic(err)
		}
		conn.SetWriteDeadline(time.Now().Add(time.Duration(*seconds+2) * time.Second))
		w := &worker{conn: conn, pending: map[uint16]pending{}, done: make(chan struct{})}
		workers[i] = w
		go func() {
			defer close(w.done)
			buf := make([]byte, 65535)
			for {
				var n int
				var err error
				if *transport == "tcp" {
					_, err = io.ReadFull(w.conn, buf[:2])
					if err == nil {
						n = int(binary.BigEndian.Uint16(buf[:2]))
						_, err = io.ReadFull(w.conn, buf[:n])
					}
				} else {
					n, err = w.conn.Read(buf)
				}
				received := time.Now()
				if err != nil {
					return
				}
				m := new(dns.Msg)
				if m.Unpack(buf[:n]) != nil {
					w.mu.Lock()
					w.r.Errors++
					w.mu.Unlock()
					continue
				}
				w.mu.Lock()
				p, ok := w.pending[m.Id]
				if ok {
					delete(w.pending, m.Id)
					valid := m.Response && m.Rcode == 0 && !m.Truncated && len(m.Question) == 1 && m.Question[0].Name == p.name && len(m.Answer) == 1
					if valid {
						a, yes := m.Answer[0].(*dns.A)
						valid = yes && a.A.String() == *expectedIP && (!*requireAD || m.AuthenticatedData)
					}
					if valid {
						w.r.OK++
						w.r.Last = received
						latency := float64(received.Sub(p.sent).Nanoseconds()) / 1e6
						w.r.Latencies = append(w.r.Latencies, latency)
						if p.unique {
							w.r.UniqueNames = append(w.r.UniqueNames, latency)
						} else {
							w.r.RepeatedNames = append(w.r.RepeatedNames, latency)
						}
						w.r.Scheduled = append(w.r.Scheduled, float64(received.Sub(p.scheduled).Nanoseconds())/1e6)
					} else {
						w.r.Errors++
					}
				}
				w.mu.Unlock()
			}
		}()
	}
	pace, closePacer, err := packetPacer(*pacing)
	if err != nil {
		panic(err)
	}
	defer closePacer()
	start := time.Now().Add(50 * time.Millisecond)
	nonce := start.UnixNano()
	time.Sleep(time.Until(start))
	total := *rate * *seconds
	for i := 0; i < total; i++ {
		scheduled := start.Add(time.Duration(int64(i) * int64(time.Second) / int64(*rate)))
		name := fmt.Sprintf("n%d.%s", i%512, *zone)
		unique := uniqueQuery(*mode, i, count)
		if unique {
			name = fmt.Sprintf("u%d-%d.miss.%s", nonce, i, *zone)
		}
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		q.AuthenticatedData = *requireAD
		q.Id = uint16(i / count)
		data, err := q.Pack()
		if err != nil {
			panic(err)
		}
		if *transport == "tcp" {
			head := make([]byte, 2)
			binary.BigEndian.PutUint16(head, uint16(len(data)))
			data = append(head, data...)
		}
		// The same absolute schedule is used by both pacing implementations.
		pace(scheduled)
		w := workers[i%count]
		sent := time.Now()
		w.mu.Lock()
		w.pending[q.Id] = pending{sent, scheduled, name, unique}
		w.r.Sent++
		w.r.Lateness = append(w.r.Lateness, float64(sent.Sub(scheduled).Nanoseconds())/1e6)
		w.mu.Unlock()
		if _, err = w.conn.Write(data); err != nil {
			w.mu.Lock()
			delete(w.pending, q.Id)
			w.r.Errors++
			w.mu.Unlock()
		}
	}
	deadline := start.Add(time.Duration(*seconds)*time.Second + time.Second)
	for time.Now().Before(deadline) {
		left := 0
		for _, w := range workers {
			w.mu.Lock()
			left += len(w.pending)
			w.mu.Unlock()
		}
		if left == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	all := result{}
	for _, w := range workers {
		w.conn.Close()
		<-w.done
		w.r.Timeouts = len(w.pending)
		r := w.r
		all.Sent += r.Sent
		all.OK += r.OK
		all.Errors += r.Errors
		all.Timeouts += r.Timeouts
		all.Latencies = append(all.Latencies, r.Latencies...)
		all.UniqueNames = append(all.UniqueNames, r.UniqueNames...)
		all.RepeatedNames = append(all.RepeatedNames, r.RepeatedNames...)
		all.Lateness = append(all.Lateness, r.Lateness...)
		all.Scheduled = append(all.Scheduled, r.Scheduled...)
		if r.Last.After(all.Last) {
			all.Last = r.Last
		}
	}
	elapsed := max(float64(*seconds), all.Last.Sub(start).Seconds())
	json.NewEncoder(os.Stdout).Encode(map[string]any{"local_port_base": *localPortBase, "mixed_distribution": "per-flow-balanced", "unique_name_ok": len(all.UniqueNames), "unique_name_p95_ms": percentile(all.UniqueNames, .95), "repeated_name_ok": len(all.RepeatedNames), "repeated_name_p95_ms": percentile(all.RepeatedNames, .95), "zone": *zone, "answer_ip": *expectedIP, "require_ad": *requireAD, "pacing": *pacing, "target_qps": *rate, "seconds": *seconds, "elapsed_seconds": elapsed, "sent": all.Sent, "ok": all.OK, "errors": all.Errors, "timeouts": all.Timeouts, "qps": float64(all.OK) / elapsed, "p50_ms": percentile(all.Latencies, .50), "p95_ms": percentile(all.Latencies, .95), "p99_ms": percentile(all.Latencies, .99), "scheduled_p95_ms": percentile(all.Scheduled, .95), "send_lateness_p95_ms": percentile(all.Lateness, .95), "send_lateness_p99_ms": percentile(all.Lateness, .99), "send_lateness_max_ms": percentile(all.Lateness, 1), "transport": *transport, "mode": *mode})
}

func checkAnswers(addr, network string) {
	client := dns.Client{Net: network, Timeout: 2 * time.Second}
	first := map[string]uint32{}
	results := []string{}
	for _, tc := range []struct {
		name     string
		typ      uint16
		expected string
		rcode    int
	}{{"n0.bench.test.", dns.TypeA, "192.0.2.1", 0}, {"aaaa.bench.test.", dns.TypeAAAA, "2001:db8::1", 0}, {"alias.bench.test.", dns.TypeCNAME, "n0.bench.test.", 0}, {"_service._tcp.bench.test.", dns.TypeSRV, "0 100 389 n0.bench.test.", 0}, {"absent.bench.test.", dns.TypeA, "", dns.RcodeNameError}} {
		q := new(dns.Msg)
		q.SetQuestion(tc.name, tc.typ)
		r, _, err := client.Exchange(q, addr)
		if err != nil || r.Rcode != tc.rcode || !r.RecursionAvailable || r.Authoritative {
			panic("functional response failure")
		}
		if tc.rcode == 0 {
			if len(r.Answer) == 0 {
				panic("empty answer")
			}
			found := false
			for _, rr := range r.Answer {
				if rr.Header().Rrtype == tc.typ && strings.HasSuffix(rr.String(), "\t"+tc.expected) {
					found = true
					first[tc.name] = rr.Header().Ttl
				}
			}
			if !found {
				panic("wrong answer")
			}
		} else {
			if len(r.Ns) == 0 || r.Ns[0].Header().Rrtype != dns.TypeSOA {
				panic("negative SOA missing")
			}
			first[tc.name] = r.Ns[0].Header().Ttl
		}
		results = append(results, tc.name)
	}
	time.Sleep(1100 * time.Millisecond)
	for _, name := range []string{"n0.bench.test.", "absent.bench.test."} {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		r, _, err := client.Exchange(q, addr)
		if err != nil {
			panic(err)
		}
		rrs := r.Answer
		if len(rrs) == 0 {
			rrs = r.Ns
		}
		if len(rrs) == 0 || rrs[0].Header().Ttl >= first[name] {
			panic("cached TTL not aging")
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"transport": network, "checked": results, "positive_negative_ttl": "PASS"})
}

// Each flow gets one unique name per ten queries. Using i%10 with eight
// flows concentrates every cache miss onto the four even-numbered flows.
func uniqueQuery(mode string, sequence, flows int) bool {
	return mode == "miss" || mode == "mixed" && (sequence/flows)%10 == (sequence%flows)%10
}
