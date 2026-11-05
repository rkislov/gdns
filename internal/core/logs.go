// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package core

import (
	"github.com/miekg/dns"
	"net/netip"
	"time"
)

type LogPage struct {
	Items    []QueryLog `json:"items"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Total    int        `json:"total"`
	Pages    int        `json:"pages"`
	Anchor   uint64     `json:"anchor"`
	Capacity int        `json:"capacity"`
}

// Strings needed by the API are formatted only for the requested page, outside
// the journal lock. DNS workers retain numeric timestamps, IPs and RR types.
type logEntry struct {
	id       uint64
	at       int64
	client   netip.Addr
	name     string
	qtype    uint16
	result   string
	duration float64
}

func renderLogs(entries []logEntry) []QueryLog {
	out := make([]QueryLog, len(entries))
	for i, q := range entries {
		out[i] = QueryLog{ID: q.id, Time: time.Unix(0, q.at).UTC().Format(time.RFC3339), Client: q.client.String(), Name: q.name, Type: dns.TypeToString[q.qtype], Result: q.result, Duration: q.duration}
	}
	return out
}
func (e *Engine) resizeLogs(capacity int) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	if capacity == e.logLimit {
		return
	}
	n := min(capacity, len(e.logs))
	ordered := make([]logEntry, n, capacity)
	for i := 0; i < n; i++ {
		idx := (e.next - 1 - i + len(e.logs)) % len(e.logs)
		ordered[n-1-i] = e.logs[idx]
	}
	e.logs = ordered
	e.logLimit = capacity
	e.next = n % capacity
}
func (e *Engine) appendLog(q logEntry) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	e.logSequence++
	q.id = e.logSequence
	if len(e.logs) < e.logLimit {
		e.logs = append(e.logs, q)
		e.next = len(e.logs) % e.logLimit
	} else {
		e.logs[e.next] = q
		e.next = (e.next + 1) % e.logLimit
	}
}

// log is retained for internal callers supplying already formatted events.
func (e *Engine) log(q QueryLog) {
	at, _ := time.Parse(time.RFC3339, q.Time)
	ip, _ := netip.ParseAddr(q.Client)
	e.appendLog(logEntry{at: at.UnixNano(), client: ip, name: q.Name, qtype: dns.StringToType[q.Type], result: q.Result, duration: q.Duration})
}
func (e *Engine) RecentLogs(limit int) []QueryLog {
	e.logMu.Lock()
	n := max(0, min(limit, len(e.logs)))
	entries := make([]logEntry, n)
	for i := 0; i < n; i++ {
		entries[i] = e.logs[(e.next-1-i+len(e.logs))%len(e.logs)]
	}
	e.logMu.Unlock()
	return renderLogs(entries)
}
func (e *Engine) Logs() []QueryLog { return e.RecentLogs(100000) }

// IDs in the bounded ring are contiguous, even after a resize. Compute eligible
// rows and offsets from IDs instead of scanning up to 100,000 entries under lock.
func (e *Engine) QueryLogs(page, size int, anchor uint64) LogPage {
	e.logMu.Lock()
	page = max(1, page)
	size = max(1, min(100, size))
	n := len(e.logs)
	newest := e.logSequence
	if anchor == 0 && n > 0 {
		anchor = newest
	}
	total := 0
	eligibleNewest := min(anchor, newest)
	if n > 0 {
		oldest := newest - uint64(n) + 1
		if eligibleNewest >= oldest {
			total = int(eligibleNewest - oldest + 1)
		}
	}
	pages := max(1, (total+size-1)/size)
	page = min(page, pages)
	skip := (page - 1) * size
	count := min(size, total-skip)
	entries := make([]logEntry, count)
	offset := int(newest-eligibleNewest) + skip
	for i := 0; i < count; i++ {
		entries[i] = e.logs[(e.next-1-offset-i+n)%n]
	}
	capacity := e.logLimit
	e.logMu.Unlock()
	return LogPage{Items: renderLogs(entries), Page: page, PageSize: size, Total: total, Pages: pages, Anchor: anchor, Capacity: capacity}
}
