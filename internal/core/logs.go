// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package core

type LogPage struct {
	Items    []QueryLog `json:"items"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Total    int        `json:"total"`
	Pages    int        `json:"pages"`
	Anchor   uint64     `json:"anchor"`
	Capacity int        `json:"capacity"`
}

func (e *Engine) resizeLogs(capacity int) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	if capacity == e.logLimit {
		return
	}
	n := min(capacity, len(e.logs))
	ordered := make([]QueryLog, n)
	for i := 0; i < n; i++ {
		idx := (e.next - 1 - i + len(e.logs)) % len(e.logs)
		ordered[n-1-i] = e.logs[idx]
	}
	e.logs = ordered
	e.logLimit = capacity
	e.next = n % capacity
}
func (e *Engine) log(q QueryLog) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	e.logSequence++
	q.ID = e.logSequence
	if len(e.logs) < e.logLimit {
		e.logs = append(e.logs, q)
		e.next = len(e.logs) % e.logLimit
	} else {
		e.logs[e.next] = q
		e.next = (e.next + 1) % e.logLimit
	}
}
func (e *Engine) RecentLogs(limit int) []QueryLog {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	n := min(limit, len(e.logs))
	out := make([]QueryLog, 0, n)
	for i := 0; i < n; i++ {
		idx := (e.next - 1 - i + len(e.logs)) % len(e.logs)
		out = append(out, e.logs[idx])
	}
	return out
}
func (e *Engine) Logs() []QueryLog { return e.RecentLogs(100000) }

// QueryLogs pins the newest eligible ID so incoming queries do not move pages.
// Old records may still expire when the bounded ring wraps.
func (e *Engine) QueryLogs(page, size int, anchor uint64) LogPage {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	page = max(1, page)
	size = max(1, min(100, size))
	if anchor == 0 && len(e.logs) > 0 {
		anchor = e.logs[(e.next-1+len(e.logs))%len(e.logs)].ID
	}
	total := 0
	for i := 0; i < len(e.logs); i++ {
		q := e.logs[(e.next-1-i+len(e.logs))%len(e.logs)]
		if q.ID <= anchor {
			total++
		}
	}
	pages := max(1, (total+size-1)/size)
	page = min(page, pages)
	out := LogPage{Items: []QueryLog{}, Page: page, PageSize: size, Total: total, Pages: pages, Anchor: anchor, Capacity: e.logLimit}
	skip := (page - 1) * size
	eligible := 0
	for i := 0; i < len(e.logs) && len(out.Items) < size; i++ {
		q := e.logs[(e.next-1-i+len(e.logs))%len(e.logs)]
		if q.ID > anchor {
			continue
		}
		if eligible >= skip {
			out.Items = append(out.Items, q)
		}
		eligible++
	}
	return out
}
