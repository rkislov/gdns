// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNSSECValidator is the boundary for a future local chain-of-trust validator.
// Implementations must validate denial of existence and chains to configured anchors.
// AD must never be set merely because an upstream sets it.
type DNSSECValidator interface {
	Validate(context.Context, *dns.Msg, *dns.Msg, []dns.RR) error
}
type runtimeState struct {
	snap    *snapshot
	cache   *cache
	flights singleflight.Group
}
type QueryLog struct {
	ID       uint64  `json:"id"`
	Time     string  `json:"time"`
	Client   string  `json:"client"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Result   string  `json:"result"`
	Duration float64 `json:"duration_ms"`
}
type Observer interface {
	ObserveDNS(string, string, time.Duration)
}
type observerSlot struct{ value Observer }
type Engine struct {
	observer    atomic.Pointer[observerSlot]
	state       atomic.Pointer[runtimeState]
	Queries     atomic.Uint64
	Blocked     atomic.Uint64
	Hits        atomic.Uint64
	Failures    atomic.Uint64
	logMu       sync.Mutex
	logs        []QueryLog
	next        int
	logLimit    int
	logSequence uint64
	slots       chan struct{}
}

func New(c Config) (*Engine, error) {
	e := &Engine{slots: make(chan struct{}, 256)}
	return e, e.Apply(c)
}
func (e *Engine) SetObserver(o Observer) { e.observer.Store(&observerSlot{o}) }
func (e *Engine) Apply(c Config) error   { return e.Update(c, nil) }

// Update prepares a new snapshot, persists it, then publishes it atomically.
// The persistence callback must not mutate the supplied configuration.
func (e *Engine) Update(c Config, persist func(Config) error) error {
	s, err := compile(c)
	if err != nil {
		return err
	}
	if persist != nil {
		if err := persist(s.config); err != nil {
			return err
		}
	}
	e.state.Store(&runtimeState{snap: s, cache: newCache(c.CacheSize)})
	e.resizeLogs(s.config.QueryLogLimit)
	return nil
}
func (e *Engine) Config() Config { return cloneConfig(e.state.Load().snap.config) }
func (e *Engine) NeedsRestart(r Config) bool {
	c := e.state.Load().snap.config
	return c.DNSListen != r.DNSListen || c.HTTPListen != r.HTTPListen || c.DoHListen != r.DoHListen || c.DoTListen != r.DoTListen || c.TLSCertFile != r.TLSCertFile || c.TLSKeyFile != r.TLSKeyFile
}
func (e *Engine) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	transport := "tcp"
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		transport = "udp"
	}
	e.ServeDNSAs(w, q, transport)
}
func (e *Engine) ServeDNSAs(w dns.ResponseWriter, q *dns.Msg, transport string) {
	host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	ip, _ := netip.ParseAddr(host)
	r := e.AnswerAs(context.Background(), q, ip.Unmap(), transport)

	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		size := uint16(512)
		if opt := q.IsEdns0(); opt != nil {
			size = opt.UDPSize()
			if size < 512 {
				size = 512
			}
			if size > 1232 {
				size = 1232
			}
		}
		r.Truncate(int(size))
	}
	_ = w.WriteMsg(r)
}

// Answer is the common entry point for UDP, TCP, DoH and DoT accounting and policy.
func (e *Engine) Answer(ctx context.Context, q *dns.Msg, ip netip.Addr) *dns.Msg {
	return e.AnswerAs(ctx, q, ip, "tcp")
}
func (e *Engine) AnswerAs(ctx context.Context, q *dns.Msg, ip netip.Addr, transport string) *dns.Msg {
	start := time.Now()
	e.Queries.Add(1)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	r, result := e.Resolve(ctx, q, ip.Unmap())
	if observer := e.observer.Load(); observer != nil && observer.value != nil {
		observer.value.ObserveDNS(transport, result, time.Since(start))
	}
	if len(q.Question) > 0 && e.state.Load().snap.config.QueryLog {
		e.log(QueryLog{Time: time.Now().UTC().Format(time.RFC3339), Client: ip.String(), Name: q.Question[0].Name, Type: dns.TypeToString[q.Question[0].Qtype], Result: result, Duration: float64(time.Since(start).Microseconds()) / 1000})
	}
	return r
}

func (e *Engine) Resolve(ctx context.Context, q *dns.Msg, ip netip.Addr) (*dns.Msg, string) {
	st := e.state.Load()
	s := st.snap
	r := new(dns.Msg)
	r.SetReply(q)
	r.RecursionAvailable = true
	r.AuthenticatedData = false
	if len(q.Question) != 1 || q.Opcode != dns.OpcodeQuery {
		r.Rcode = dns.RcodeFormatError
		return r, "FORMERR"
	}
	allowed := false
	for _, p := range s.allowed {
		if p.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		r.Rcode = dns.RcodeRefused
		return r, "REFUSED"
	}
	question := q.Question[0]
	name := canonical(question.Name)
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		r.Rcode = dns.RcodeRefused
		return r, "REFUSED"
	}
	z := s.zone(name, ip)
	if z != nil && z.Kind == "primary" {
		r.Authoritative = true
		// A delegation belongs to the parent; DS remains authoritative there.
		cut := ""
		for n := name; n != z.Name && dns.IsSubDomain(z.Name, n); {
			sets, _ := z.recordsFor(n, ip)
			if len(sets[dns.TypeNS]) > 0 {
				cut = n
			}
			i := strings.IndexByte(n, '.')
			if i < 0 {
				break
			}
			n = n[i+1:]
		}
		if cut != "" && !(name == cut && question.Qtype == dns.TypeDS) {
			r.Authoritative = false
			sets, _ := z.recordsFor(cut, ip)
			r.Ns = copyRRs(sets[dns.TypeNS], "")
			for _, rr := range r.Ns {
				ns := canonical(rr.(*dns.NS).Ns)
				if dns.IsSubDomain(cut, ns) {
					glue, _ := z.recordsFor(ns, ip)
					r.Extra = append(r.Extra, copyRRs(glue[dns.TypeA], "")...)
					r.Extra = append(r.Extra, copyRRs(glue[dns.TypeAAAA], "")...)
				}
			}
			return r, "DELEGATION"
		}

		records, exists := z.recordsFor(name, ip)
		if !exists && !z.nodeExists(name, ip) {
			// Wildcards only at the closest existing ancestor; empty non-terminals exist.
			ancestor := name
			for {
				i := strings.IndexByte(ancestor, '.')
				if i < 0 || i == len(ancestor)-1 {
					break
				}
				ancestor = ancestor[i+1:]
				if z.nodeExists(ancestor, ip) {
					records, exists = z.recordsFor("*."+ancestor, ip)
					break
				}
			}
		}
		if exists {
			if question.Qtype == dns.TypeANY {
				for _, set := range records {
					r.Answer = append(r.Answer, copyRRs(set, name)...)
				}
			} else {
				r.Answer = copyRRs(records[question.Qtype], name)
				if len(r.Answer) == 0 && question.Qtype != dns.TypeCNAME {
					r.Answer = copyRRs(records[dns.TypeCNAME], name)
				}
			}
		}
		if len(r.Answer) == 0 {
			if !exists && !z.nodeExists(name, ip) {
				r.Rcode = dns.RcodeNameError
			}
			r.Ns = copyRRs(z.soa, "")
			for _, rr := range r.Ns {
				soa := rr.(*dns.SOA)
				if soa.Minttl < soa.Hdr.Ttl {
					soa.Hdr.Ttl = soa.Minttl
				}
			}
		}
		return r, dns.RcodeToString[r.Rcode]
	}
	if s.isBlocked(name) {
		e.Blocked.Add(1)
		r.Rcode = dns.RcodeNameError
		return r, "BLOCKED"
	}
	if !q.RecursionDesired {
		r.Rcode = dns.RcodeRefused
		return r, "REFUSED"
	}
	do := q.IsEdns0() != nil && q.IsEdns0().Do()
	key := fmt.Sprintf("%s/%d/%t/%t", name, question.Qtype, do, q.CheckingDisabled)
	if z != nil {
		key += "/view/" + z.viewKey
	}
	if cached := st.cache.get(key); cached != nil {
		cached.Id = q.Id
		cached.Question = q.Question
		cached.Authoritative = false
		cached.AuthenticatedData = false
		cached.RecursionAvailable = true
		cached.RecursionDesired = q.RecursionDesired
		cached.CheckingDisabled = q.CheckingDisabled
		e.Hits.Add(1)
		return cached, "CACHE"
	}
	value, err, _ := st.flights.Do(key, func() (any, error) {
		if cached := st.cache.get(key); cached != nil {
			return cached, nil
		}

		select {
		case e.slots <- struct{}{}:
			defer func() { <-e.slots }()
		default:
			return nil, fmt.Errorf("resolver busy")
		}
		request := new(dns.Msg)
		request.SetQuestion(name, question.Qtype)
		request.CheckingDisabled = q.CheckingDisabled
		request.SetEdns0(1232, do)
		var answer *dns.Msg
		var err error
		budget := 80
		switch {
		case z != nil && z.Kind == "forward":
			request.RecursionDesired = true
			answer, err = exchange(ctx, request, z.Servers, &budget)
		case z != nil && z.Kind == "stub":
			answer, err = iterate(ctx, request, z.Servers, z.Name, 0, &budget)
		case s.config.Mode == "forward":
			request.RecursionDesired = true
			answer, err = exchange(ctx, request, s.config.Upstreams, &budget)
		default:
			answer, err = iterate(ctx, request, roots, ".", 0, &budget)
		}
		if err != nil || answer == nil {
			return nil, err
		}
		answer.AuthenticatedData = false
		// Blocked CNAME responses are not cached.
		blocked := false
		for _, rr := range answer.Answer {
			if c, ok := rr.(*dns.CNAME); ok && s.isBlocked(canonical(c.Target)) {
				blocked = true
			}
		}
		if !blocked {
			st.cache.put(key, answer)
		}
		return answer, nil
	})
	var answer *dns.Msg
	if value != nil {
		answer = value.(*dns.Msg).Copy()
	}

	if err != nil || answer == nil {
		r.Rcode = dns.RcodeServerFailure
		e.Failures.Add(1)
		return r, "SERVFAIL"
	}
	for _, rr := range answer.Answer {
		if c, ok := rr.(*dns.CNAME); ok && s.isBlocked(canonical(c.Target)) {
			e.Blocked.Add(1)
			r.Rcode = dns.RcodeNameError
			return r, "BLOCKED"
		}
	}

	answer.Id = q.Id
	answer.Question = q.Question
	answer.RecursionDesired = q.RecursionDesired
	answer.RecursionAvailable = true
	answer.Authoritative = false
	answer.AuthenticatedData = false
	answer.CheckingDisabled = q.CheckingDisabled
	if answer.Rcode == dns.RcodeServerFailure {
		e.Failures.Add(1)
	}
	return answer, dns.RcodeToString[answer.Rcode]
}
func copyRRs(in []dns.RR, name string) []dns.RR {
	out := make([]dns.RR, 0, len(in))
	for _, rr := range in {
		r := dns.Copy(rr)
		if name != "" {
			r.Header().Name = name
		}
		out = append(out, r)
	}
	return out
}

var roots = []string{"198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53", "199.7.91.13:53", "192.203.230.10:53"} // IPv4 roots are sufficient for bootstrap.
func exchange(ctx context.Context, q *dns.Msg, servers []string, budget *int) (*dns.Msg, error) {
	var last error
	for _, server := range servers {
		if *budget <= 0 {
			return nil, fmt.Errorf("exchange budget exceeded")
		}
		*budget--
		c := &dns.Client{Net: "udp", Timeout: 800 * time.Millisecond}
		m, _, err := c.ExchangeContext(ctx, q, server)
		if err == nil && m.Truncated {
			c.Net = "tcp"
			m, _, err = c.ExchangeContext(ctx, q, server)
		}
		if err == nil && (!m.Response || m.Opcode != q.Opcode || len(m.Question) != 1 || canonical(m.Question[0].Name) != canonical(q.Question[0].Name) || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass) {
			err = fmt.Errorf("upstream response question mismatch")
		}
		if err == nil && m.Rcode != dns.RcodeServerFailure && m.Rcode != dns.RcodeRefused {
			return m, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("no DNS server answered: %v", last)
}
func iterate(ctx context.Context, q *dns.Msg, servers []string, cut string, depth int, budget *int) (*dns.Msg, error) {
	if depth > 12 {
		return nil, fmt.Errorf("recursive dependency limit")
	}
	q = q.Copy()
	q.RecursionDesired = false
	for hop := 0; hop < 32; hop++ {
		m, err := exchange(ctx, q, servers, budget)
		if err != nil {
			return nil, err
		}
		if len(m.Answer) > 0 {
			if !m.Authoritative {
				return nil, fmt.Errorf("non-authoritative final answer")
			}
			// Complete CNAME chains even when the authoritative server only returns aliases.
			target := ""
			hasType := false
			for _, rr := range m.Answer {
				if rr.Header().Rrtype == q.Question[0].Qtype {
					hasType = true
				}
				if c, ok := rr.(*dns.CNAME); ok {
					target = c.Target
				}
			}
			if !hasType && target != "" && q.Question[0].Qtype != dns.TypeCNAME {
				next := q.Copy()
				next.SetQuestion(target, q.Question[0].Qtype)
				tail, e := iterate(ctx, next, roots, ".", depth+1, budget)
				if e != nil {
					return nil, e
				}
				m.Answer = append(m.Answer, tail.Answer...)
				m.Ns = tail.Ns
				m.Rcode = tail.Rcode
			}
			return m, nil
		}
		if m.Authoritative && (m.Rcode == dns.RcodeNameError || hasSOA(m.Ns)) {
			return m, nil
		}
		delegation := ""
		var names []string
		for _, rr := range m.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				owner := canonical(ns.Hdr.Name)
				if dns.IsSubDomain(cut, owner) && owner != cut && dns.IsSubDomain(owner, q.Question[0].Name) {
					if delegation == "" || len(owner) > len(delegation) {
						delegation = owner
						names = nil
					}
					if owner == delegation {
						names = append(names, canonical(ns.Ns))
					}
				}
			}
		}
		if delegation == "" {
			return nil, fmt.Errorf("invalid delegation")
		}
		nextServers := glueServers(m.Extra, names, cut)
		if len(nextServers) == 0 {
			for _, ns := range names {
				nq := new(dns.Msg)
				nq.SetQuestion(ns, dns.TypeA)
				nq.SetEdns0(1232, false)
				a, e := iterate(ctx, nq, roots, ".", depth+1, budget)
				if e == nil {
					for _, rr := range a.Answer {
						if ar, ok := rr.(*dns.A); ok {
							nextServers = append(nextServers, net.JoinHostPort(ar.A.String(), "53"))
						}
					}
				}
				if len(nextServers) > 0 {
					break
				}
			}
		}
		if len(nextServers) == 0 {
			return nil, fmt.Errorf("delegation has no reachable servers")
		}
		servers = nextServers
		cut = delegation
	}
	return nil, fmt.Errorf("delegation limit")
}
func hasSOA(rrs []dns.RR) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// Glue must match a delegated nameserver and lie within the responding parent zone.
// Root referrals commonly carry sibling glue (e.g. com -> gtld-servers.net).
func glueServers(records []dns.RR, names []string, cut string) []string {
	nextServers := []string{}
	for _, ns := range names {
		if !dns.IsSubDomain(cut, ns) {
			continue
		}
		for _, rr := range records {
			if canonical(rr.Header().Name) != ns {
				continue
			}
			switch a := rr.(type) {
			case *dns.A:
				nextServers = append(nextServers, net.JoinHostPort(a.A.String(), "53"))
			case *dns.AAAA:
				nextServers = append(nextServers, net.JoinHostPort(a.AAAA.String(), "53"))
			}
		}
	}
	return nextServers
}
