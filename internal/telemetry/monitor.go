// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"math"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const HistoryLimit = 180
const SampleInterval = 5 * time.Second

type System struct {
	SampledAt       time.Time `json:"sampled_at"`
	CPUPercent      *float64  `json:"cpu_percent"`
	LogicalCores    int       `json:"logical_cores"`
	Kernel          string    `json:"kernel"`
	Platform        string    `json:"platform"`
	MemoryTotal     uint64    `json:"memory_total_bytes"`
	MemoryUsed      uint64    `json:"memory_used_bytes"`
	MemoryAvailable uint64    `json:"memory_available_bytes"`
	DiskPath        string    `json:"disk_path"`
	DiskTotal       uint64    `json:"disk_total_bytes"`
	DiskUsed        uint64    `json:"disk_used_bytes"`
	DiskFree        uint64    `json:"disk_free_bytes"`
	Errors          []string  `json:"errors"`
}
type Point struct {
	Time      time.Time `json:"time"`
	Interval  float64   `json:"interval_seconds"`
	Queries   uint64    `json:"queries"`
	Blocked   uint64    `json:"blocked"`
	AverageMS *float64  `json:"average_ms"`
}
type Snapshot struct {
	System          System            `json:"system"`
	History         []Point           `json:"history"`
	IntervalSeconds int               `json:"interval_seconds"`
	DNSSEC          map[string]uint64 `json:"dnssec"`
}
type totals struct{ queries, blocked, nanos uint64 }
type Monitor struct {
	dnssecCounters          map[string]prometheus.Counter
	dnssecTotals            [8]atomic.Uint64
	systemInfo              *prometheus.GaugeVec
	registry                *prometheus.Registry
	queryMetrics            [4]map[string]prometheus.Counter
	blockedMetrics          [4]prometheus.Counter
	durations               [4]prometheus.Observer
	queries, blocked, nanos atomic.Uint64
	mu                      sync.RWMutex
	sampleMu                sync.Mutex
	system                  System
	history                 []Point
	previous                totals
	last                    time.Time
	gauges                  map[string]prometheus.Gauge
	diskPath                string
}

var transports = []string{"udp", "tcp", "dot", "doh"}
var results = []string{"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "BLOCKED", "CACHE", "BUSY", "DELEGATION", "DNSSEC_BOGUS", "OTHER"}

var securityStates = []string{"secure", "insecure", "bogus", "indeterminate", "disabled", "bypass", "exempt", "other"}

func New(diskPath string) *Monitor {
	m := &Monitor{registry: prometheus.NewRegistry(), gauges: map[string]prometheus.Gauge{}, diskPath: diskPath, last: time.Now()}
	security := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ghole_dnssec_validation_total", Help: "Local DNSSEC outcomes; policy bypasses are explicitly separated."}, []string{"state"})
	m.registry.MustRegister(security)
	m.dnssecCounters = map[string]prometheus.Counter{}
	for _, state := range securityStates {
		m.dnssecCounters[state] = security.WithLabelValues(state)
	}

	m.systemInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "ghole_system_info", Help: "Operating system and kernel version."}, []string{"os", "kernel_version"})
	m.registry.MustRegister(m.systemInfo)
	query := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ghole_dns_queries_total", Help: "Completed DNS queries by transport and result."}, []string{"transport", "result"})
	blocked := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "ghole_dns_blocked_total", Help: "Queries blocked by domain policy, including CNAME targets."}, []string{"transport"})
	latency := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "ghole_dns_response_duration_seconds", Help: "DNS processing time, including resolution, excluding response socket write.", Buckets: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8}}, []string{"transport"})
	m.registry.MustRegister(query, blocked, latency, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	// Cache bounded label handles; no vector lookup, allocation or arbitrary labels per query.
	for i, t := range transports {
		m.queryMetrics[i] = map[string]prometheus.Counter{}
		for _, r := range results {
			m.queryMetrics[i][r] = query.WithLabelValues(t, r)
		}
		m.blockedMetrics[i] = blocked.WithLabelValues(t)
		m.durations[i] = latency.WithLabelValues(t)
	}
	for name, help := range map[string]string{"cpu_usage_ratio": "Host CPU utilization (0 to 1).", "logical_cpus": "Number of logical CPU cores.", "memory_total_bytes": "Total host memory bytes.", "memory_used_bytes": "Used host memory bytes.", "memory_available_bytes": "Available host memory bytes.", "disk_total_bytes": "Total bytes on the filesystem containing GHole data.", "disk_used_bytes": "Used bytes on the filesystem containing GHole data.", "disk_free_bytes": "Free bytes available on the filesystem containing GHole data.", "system_metrics_success": "Whether the latest host metrics collection succeeded."} {
		g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "ghole_system_" + name, Help: help})
		m.gauges[name] = g
		m.registry.MustRegister(g)
	}
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "ghole_system_sample_timestamp_seconds", Help: "Unix time of the latest host metrics sample."}, func() float64 {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.system.SampledAt.IsZero() {
			return 0
		}
		return float64(m.system.SampledAt.Unix())
	}))
	return m
}
func transportIndex(t string) int {
	switch t {
	case "tcp":
		return 1
	case "dot":
		return 2
	case "doh":
		return 3
	default:
		return 0
	}
}

// ObserveDNS satisfies core.Observer. It never collects host metrics or accesses SQL.
func (m *Monitor) ObserveDNS(transport, result string, duration time.Duration) {
	i := transportIndex(transport)
	counter := m.queryMetrics[i][result]
	if counter == nil {
		counter = m.queryMetrics[i]["OTHER"]
	}
	counter.Inc()
	m.durations[i].Observe(duration.Seconds())
	m.nanos.Add(uint64(max(duration, 0)))
	m.queries.Add(1)
	if result == "BLOCKED" {
		m.blocked.Add(1)
		m.blockedMetrics[i].Inc()
	}
}
func (m *Monitor) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{MaxRequestsInFlight: 4, Timeout: 5 * time.Second})
}
func (m *Monitor) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.system
	s.Errors = append([]string{}, s.Errors...)
	security := map[string]uint64{}
	for i, state := range securityStates {
		security[state] = m.dnssecTotals[i].Load()
	}
	return Snapshot{System: s, History: append([]Point{}, m.history...), IntervalSeconds: int(SampleInterval / time.Second), DNSSEC: security}
}
func (m *Monitor) Run(ctx context.Context) {
	m.Sample(ctx)
	ticker := time.NewTicker(SampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Sample(ctx)
		}
	}
}
func (m *Monitor) Sample(ctx context.Context) {
	m.sampleMu.Lock()
	defer m.sampleMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	now := time.Now()
	system := System{SampledAt: now, LogicalCores: runtime.NumCPU(), DiskPath: m.diskPath, Errors: []string{}}
	if values, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(values) > 0 && !math.IsNaN(values[0]) {
		v := max(0, min(100, values[0]))
		system.CPUPercent = &v
	} else {
		system.Errors = append(system.Errors, "CPU statistics unavailable")
	}
	if info, err := host.InfoWithContext(ctx); err == nil {
		system.Kernel = info.KernelVersion
		system.Platform = info.OS + " / " + info.Platform
		m.systemInfo.WithLabelValues(info.OS, info.KernelVersion).Set(1)
	} else {
		system.Errors = append(system.Errors, "kernel statistics unavailable")
	}
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		system.MemoryTotal = v.Total
		system.MemoryUsed = v.Used
		system.MemoryAvailable = v.Available
	} else {
		system.Errors = append(system.Errors, "memory statistics unavailable")
	}
	if d, err := disk.UsageWithContext(ctx, m.diskPath); err == nil {
		system.DiskTotal = d.Total
		system.DiskUsed = d.Used
		system.DiskFree = d.Free
	} else {
		system.Errors = append(system.Errors, "disk statistics unavailable")
	}
	if system.CPUPercent != nil {
		m.gauges["cpu_usage_ratio"].Set(*system.CPUPercent / 100)
	} else {
		m.gauges["cpu_usage_ratio"].Set(math.NaN())
	}
	m.gauges["logical_cpus"].Set(float64(system.LogicalCores))
	for k, v := range map[string]uint64{"memory_total_bytes": system.MemoryTotal, "memory_used_bytes": system.MemoryUsed, "memory_available_bytes": system.MemoryAvailable, "disk_total_bytes": system.DiskTotal, "disk_used_bytes": system.DiskUsed, "disk_free_bytes": system.DiskFree} {
		m.gauges[k].Set(float64(v))
	}
	success := 1.
	if len(system.Errors) > 0 {
		success = 0
	}
	m.gauges["system_metrics_success"].Set(success)
	m.record(now, system)
}
func (m *Monitor) record(now time.Time, system System) {
	current := totals{m.queries.Load(), m.blocked.Load(), m.nanos.Load()}
	p := Point{Time: now, Interval: now.Sub(m.last).Seconds(), Queries: current.queries - m.previous.queries, Blocked: current.blocked - m.previous.blocked}
	if p.Queries > 0 {
		v := float64(current.nanos-m.previous.nanos) / float64(p.Queries) / 1e6
		p.AverageMS = &v
	}
	m.mu.Lock()
	m.system = system
	if len(m.history) == HistoryLimit {
		copy(m.history, m.history[1:])
		m.history[len(m.history)-1] = p
	} else {
		m.history = append(m.history, p)
	}
	m.mu.Unlock()
	m.previous = current
	m.last = now
}

func (m *Monitor) ObserveDNSSEC(state string) {
	i := len(securityStates) - 1
	for j, s := range securityStates {
		if s == state {
			i = j
			break
		}
	}
	m.dnssecTotals[i].Add(1)
	m.dnssecCounters[securityStates[i]].Inc()
}
