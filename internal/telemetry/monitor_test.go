// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	validation "gdns/internal/dnssec"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricsAndHistory(t *testing.T) {
	m := New(t.TempDir())
	m.ObserveDNS("doh", "NOERROR", time.Millisecond)
	m.ObserveDNSSEC("secure")
	m.ObserveDNSSEC("bogus")
	m.ObserveDNSSEC("unbounded.example")
	m.ObserveDNS("dot", "BLOCKED", 3*time.Millisecond)
	now := m.last.Add(SampleInterval)
	m.record(now, System{LogicalCores: 4})
	s := m.Snapshot()
	if len(s.History) != 1 || s.History[0].Queries != 2 || s.History[0].Blocked != 1 || s.History[0].AverageMS == nil || *s.History[0].AverageMS != 2 {
		t.Fatalf("incorrect graph sample: %+v", s.History)
	}
	m.ObserveDNS("unknown", "unbounded.example", time.Millisecond)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{`gdns_dns_queries_total{result="NOERROR",transport="doh"} 1`, `gdns_dns_blocked_total{transport="dot"} 1`, `gdns_dns_response_duration_seconds_count{transport="dot"} 1`, `go_goroutines`, `gdns_dnssec_validation_total{state="secure"} 1`, `gdns_dnssec_validation_total{state="bogus"} 1`} {
		if !strings.Contains(body, want) {
			t.Fatalf("metric missing: %s", want)
		}
	}
	if strings.Contains(body, "unbounded.example") {
		t.Fatal("unbounded metric labels")
	}
	for i := 1; i <= HistoryLimit+10; i++ {
		m.record(now.Add(time.Duration(i)*SampleInterval), System{})
	}
	s = m.Snapshot()
	if len(s.History) != HistoryLimit {
		t.Fatal("unbounded history")
	}
	if s.History[len(s.History)-1].AverageMS != nil {
		t.Fatal("fabricated latency without queries")
	}
	s.History[0].Queries = 999
	if m.Snapshot().History[0].Queries == 999 {
		t.Fatal("mutable history snapshot")
	}
}
func TestConcurrentObservation(t *testing.T) {
	m := New(t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 1000; n++ {
				m.ObserveDNS("udp", "NOERROR", time.Microsecond)
			}
		}()
	}
	wg.Wait()
	m.record(m.last.Add(SampleInterval), System{})
	if m.Snapshot().History[0].Queries != 8000 {
		t.Fatal("lost observations")
	}
	m.Sample(context.Background())
	s := m.Snapshot().System
	if s.SampledAt.IsZero() || s.LogicalCores == 0 {
		t.Fatal("system sampling did not run")
	}
}
func BenchmarkObserveDNS(b *testing.B) {
	m := New(b.TempDir())
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.ObserveDNS("udp", "NOERROR", time.Microsecond)
		}
	})
}

func TestRFC5011Metrics(t *testing.T) {
	m := New(t.TempDir())
	m.RegisterRFC5011(func() validation.ManagedStatus {
		return validation.ManagedStatus{Enabled: true, Initialized: true, State: "healthy", ActiveAnchors: 2, LastSuccess: time.Unix(100, 0), Keys: []validation.ManagedKey{{State: validation.Valid}, {State: validation.AddPending}}}
	})
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`gdns_dnssec_rfc5011_enabled 1`, `gdns_dnssec_rfc5011_active_anchors 2`, `gdns_dnssec_rfc5011_last_success_timestamp_seconds 100`, `gdns_dnssec_rfc5011_keys{state="AddPend"} 1`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatal("missing RFC 5011 metric", want)
		}
	}
}
