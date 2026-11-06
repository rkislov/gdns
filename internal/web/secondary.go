// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"context"
	"fmt"
	"gdns/internal/core"
	"reflect"
	"time"
)

// RunSecondaries serializes background publications with web configuration writes.
// Network I/O runs outside the lock; changed configurations discard stale results.
func (s *Server) RunSecondaries(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for i, next := range s.Engine.SecondarySchedule() {
			if time.Now().Before(next) {
				continue
			}
			_ = s.refreshSecondary(ctx, i, false)
			if ctx.Err() != nil {
				return
			}
		}
	}
}
func (s *Server) refreshSecondary(ctx context.Context, id int, force bool) error {
	s.mu.Lock()
	cfg := s.Engine.Config()
	if id < 0 || id >= len(cfg.Zones) || cfg.Zones[id].Kind != "secondary" {
		s.mu.Unlock()
		return fmt.Errorf("secondary zone not found")
	}
	old := cfg.Zones[id]
	if !force && time.Now().Before(old.Secondary.NextRefresh) {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	updated, err := core.FetchSecondary(ctx, old)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		updated = old
		updated.Secondary.NextRefresh = time.Now().UTC().Add(core.SecondaryRetry(old))
		updated.Secondary.LastError = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg = s.Engine.Config()
	if id >= len(cfg.Zones) || !reflect.DeepEqual(cfg.Zones[id], old) {
		return fmt.Errorf("zone changed during transfer; result discarded")
	}
	cfg.Zones[id] = updated
	if saveErr := s.commit(cfg); saveErr != nil {
		return saveErr
	}
	return err
}

// A configuration edit cannot forge transfer freshness or alter a received snapshot.
func preserveSecondary(c *core.Config, old core.Config) {
	for i := range c.Zones {
		z := &c.Zones[i]
		if z.Kind != "secondary" {
			z.Secondary = core.SecondaryState{}
			continue
		}
		z.Records = nil
		z.RecordViews = nil
		z.Secondary = core.SecondaryState{}
		for _, previous := range old.Zones {
			if previous.Kind == "secondary" && previous.Name == z.Name && reflect.DeepEqual(previous.Clients, z.Clients) && reflect.DeepEqual(previous.Servers, z.Servers) && previous.Transfer.KeyName == z.Transfer.KeyName && previous.Transfer.Secret == z.Transfer.Secret {
				z.Records = previous.Records
				z.Secondary = previous.Secondary
				break
			}
		}
	}
}
