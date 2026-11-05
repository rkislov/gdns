// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	validation "ghole/internal/dnssec"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

type managedCollector struct {
	source func() validation.ManagedStatus
	desc   []*prometheus.Desc
	keys   *prometheus.Desc
}

func (m *Monitor) RegisterRFC5011(source func() validation.ManagedStatus) {
	c := &managedCollector{source: source, keys: prometheus.NewDesc("ghole_dnssec_rfc5011_keys", "Managed root key states.", []string{"state"}, nil)}
	for _, metric := range []struct{ name, help string }{{"enabled", "Automatic root anchor polling is enabled."}, {"initialized", "Managed root state is persisted."}, {"active_anchors", "Currently usable managed root anchors."}, {"last_success_timestamp_seconds", "Last authenticated root DNSKEY observation."}, {"next_probe_timestamp_seconds", "Next scheduled root DNSKEY probe."}, {"error", "Root anchor management requires attention."}} {
		c.desc = append(c.desc, prometheus.NewDesc("ghole_dnssec_rfc5011_"+metric.name, metric.help, nil, nil))
	}
	m.registry.MustRegister(c)
}
func (c *managedCollector) Describe(out chan<- *prometheus.Desc) {
	for _, desc := range c.desc {
		out <- desc
	}
	out <- c.keys
}
func (c *managedCollector) Collect(out chan<- prometheus.Metric) {
	s := c.source()
	flag := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	timestamp := func(t time.Time) float64 {
		if t.IsZero() {
			return 0
		}
		return float64(t.Unix())
	}
	failed := s.State == "error" || s.State == "trust_lost" || s.State == "storage_error" || s.State == "clock_error" || s.State == "recovery_required"
	values := []float64{flag(s.Enabled), flag(s.Initialized), float64(s.ActiveAnchors), timestamp(s.LastSuccess), timestamp(s.NextProbe), flag(failed)}
	for i, desc := range c.desc {
		out <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, values[i])
	}
	counts := map[string]int{}
	for _, key := range s.Keys {
		counts[key.State]++
	}
	for _, state := range []string{validation.AddPending, validation.Valid, validation.Missing, validation.Revoked, validation.Removed} {
		out <- prometheus.MustNewConstMetric(c.keys, prometheus.GaugeValue, float64(counts[state]), state)
	}
}
