// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"hash/maphash"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	name   string
	zone   *compiledZone
	qtype  uint16
	do, cd bool
}

// singleflight uses a string key on misses. Cache lookups use the tuple
// directly, so a hit doesn't have to format or allocate this string.
func (k cacheKey) flightKey() string {
	key := k.name + "/" + strconv.Itoa(int(k.qtype)) + "/" + strconv.FormatBool(k.do) + "/" + strconv.FormatBool(k.cd)
	if k.zone != nil {
		key += "/view/" + k.zone.viewKey
	}
	return key
}

type cacheEntry struct {
	msg *dns.Msg
	at  time.Time
	ttl uint32
}
type cacheShard struct {
	sync.RWMutex
	items    map[cacheKey]cacheEntry
	capacity int
}
type cache struct {
	seed   maphash.Seed
	shards [64]cacheShard
	limit  int
}

func newCache(limit int) *cache {
	c := &cache{seed: maphash.MakeSeed(), limit: limit}
	for i := range c.shards {
		c.shards[i].items = map[cacheKey]cacheEntry{}
		c.shards[i].capacity = limit / 64
		if i < limit%64 {
			c.shards[i].capacity++
		}
	}
	return c
}
func (c *cache) shard(k cacheKey) *cacheShard { return &c.shards[maphash.Comparable(c.seed, k)%64] }

// A cache hit owns its message, OPT and Additional slice in one allocation.
// RR payloads still receive the library's deep copy before TTL adjustment.
type cachedReply struct {
	msg   dns.Msg
	opt   dns.OPT
	extra [1]dns.RR
}

type cachedAddressReply[T any] struct {
	msg     dns.Msg
	record  T
	answer  [1]dns.RR
	address [16]byte
}

type cachedAddressEDNSReply[T any] struct {
	cachedAddressReply[T]
	opt   dns.OPT
	extra [1]dns.RR
}

func (r *cachedAddressReply[T]) init(message *dns.Msg, record dns.RR) *dns.Msg {
	r.msg.MsgHdr, r.msg.Compress = message.MsgHdr, message.Compress
	r.answer[0] = record
	r.msg.Answer = r.answer[:]
	return &r.msg
}

func addressReply[T any](edns bool) *cachedAddressReply[T] {
	if !edns {
		return new(cachedAddressReply[T])
	}
	reply := new(cachedAddressEDNSReply[T])
	reply.opt.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}
	reply.extra[0] = &reply.opt
	reply.msg.Extra = reply.extra[:]
	return &reply.cachedAddressReply
}

// Cached records are immutable. A single address and its TTL fit in the
// reply allocation, including private IP bytes and a per-client OPT.
func copyCachedAddress(message *dns.Msg, age uint32, edns, stripSignatures bool) *dns.Msg {
	if len(message.Ns) != 0 || (!stripSignatures && len(message.Answer) != 1) {
		return nil
	}
	var record dns.RR
	for _, rr := range message.Answer {
		if stripSignatures && rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		if record != nil {
			return nil
		}
		record = rr
	}
	switch rr := record.(type) {
	case *dns.A:
		if len(rr.A) != 4 && len(rr.A) != 16 {
			return nil
		}
		reply := addressReply[dns.A](edns)
		reply.record = *rr
		copy(reply.address[:], rr.A)
		reply.record.A = reply.address[:len(rr.A)]
		reply.record.Hdr.Ttl -= age
		return reply.init(message, &reply.record)
	case *dns.AAAA:
		if len(rr.AAAA) != 16 {
			return nil
		}
		reply := addressReply[dns.AAAA](edns)
		reply.record = *rr
		copy(reply.address[:], rr.AAAA)
		reply.record.AAAA = reply.address[:]
		reply.record.Hdr.Ttl -= age
		return reply.init(message, &reply.record)
	}
	return nil
}

func (c *cache) get(k cacheKey) *dns.Msg { return c.getReply(k, false) }
func (c *cache) getReply(k cacheKey, edns bool) *dns.Msg {
	s := c.shard(k)
	s.RLock()
	e, ok := s.items[k]
	s.RUnlock()
	if !ok {
		return nil
	}
	now := time.Now()
	elapsed := now.Sub(e.at)
	if elapsed < 0 {
		return nil
	}
	age := uint32(elapsed / time.Second)
	if age >= e.ttl {
		return nil
	}
	if e.msg.AuthenticatedData {
		for _, records := range [][]dns.RR{e.msg.Answer, e.msg.Ns} {
			for _, rr := range records {
				if sig, ok := rr.(*dns.RRSIG); ok && !sig.ValidityPeriod(now) {
					return nil
				}
			}
		}
	}
	// Signature validity above is checked against the complete immutable entry.
	// Non-DO address clients do not need copies of signatures they cannot receive.
	if m := copyCachedAddress(e.msg, age, edns, signedAddressCacheFastPath && !k.do && (k.qtype == dns.TypeA || k.qtype == dns.TypeAAAA)); m != nil {
		return m
	}
	var m *dns.Msg
	if edns {
		reply := new(cachedReply)
		reply.opt.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}
		m = e.msg.CopyTo(&reply.msg)
		reply.extra[0] = &reply.opt
		m.Extra = reply.extra[:]
	} else {
		m = e.msg.Copy()
	}
	for _, set := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range set {
			if rr.Header().Rrtype != dns.TypeOPT {
				if rr.Header().Ttl > age {
					rr.Header().Ttl -= age
				} else {
					rr.Header().Ttl = 0
				}
			}
		}
	}
	return m
}
func (c *cache) put(k cacheKey, m *dns.Msg) {
	if c.limit == 0 || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) || m.Truncated || (len(m.Answer) == 0 && !hasSOA(m.Ns)) {
		return
	}
	ttl := uint32(86400)
	if len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < ttl {
				ttl = soa.Minttl
			}
		}
	}
	for _, set := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range set {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	if ttl == 0 {
		return
	}
	s := c.shard(k)
	if s.capacity == 0 {
		return
	}
	s.Lock()
	defer s.Unlock()
	if len(s.items) >= s.capacity {
		for key := range s.items {
			delete(s.items, key)
			break
		}
	}
	// The request question is restored by Resolve; Additional is rebuilt for
	// the client. Do not allocate copies of either on every cache hit.
	stored := *m
	stored.Question = nil
	stored.Extra = nil
	s.items[k] = cacheEntry{stored.Copy(), time.Now(), ttl}
}
