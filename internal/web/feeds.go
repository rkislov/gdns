// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"gdns/internal/core"
	"log"
	"reflect"
	"time"
)

type feedAttempt struct {
	source   core.FeedInfo
	finished time.Time
	failed   bool
}

type feedStatus struct {
	Count       int    `json:"count"`
	Updated     string `json:"updated,omitempty"`
	NextRefresh string `json:"next_refresh,omitempty"`
	LastAttempt string `json:"last_attempt,omitempty"`
	Failed      bool   `json:"failed"`
	Running     bool   `json:"running"`
}

func nextFeedRefresh(source core.FeedInfo, attempt feedAttempt) time.Time {
	last, _ := time.Parse(time.RFC3339, source.Updated)
	if attempt.source == source && attempt.finished.After(last) {
		last = attempt.finished
	}
	return last.Add(time.Duration(source.Interval) * time.Minute)
}

func (s *Server) feedStatuses() []feedStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	sources := s.Engine.FeedInfo()
	status := make([]feedStatus, len(sources))
	now := time.Now().UTC()
	for i, source := range sources {
		row := &status[i]
		row.Count, row.Updated, row.Running = source.Count, source.Updated, s.feedBusy[i]
		attempt := s.feedAttempts[i]
		if attempt.source == source && !attempt.finished.IsZero() {
			row.LastAttempt, row.Failed = attempt.finished.Format(time.RFC3339), attempt.failed
		}
		if source.Enabled && source.Interval > 0 {
			next := nextFeedRefresh(source, attempt)
			if next.Before(now) {
				next = now
			}
			row.NextRefresh = next.Format(time.RFC3339)
		}
	}
	return status
}

func (s *Server) RunFeeds(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshDueFeeds(ctx)
		}
	}
}

func (s *Server) refreshDueFeeds(ctx context.Context) {
	s.mu.Lock()
	sources := s.Engine.FeedInfo()
	for i, attempt := range s.feedAttempts {
		if i >= len(sources) || sources[i] != attempt.source {
			delete(s.feedAttempts, i)
		}
	}
	var due []int
	now := time.Now()
	for i, source := range sources {
		if source.Enabled && source.Interval > 0 && !now.Before(nextFeedRefresh(source, s.feedAttempts[i])) {
			due = append(due, i)
		}
	}
	s.mu.Unlock()
	for _, i := range due {
		if ctx.Err() != nil {
			return
		}
		_, _ = s.refreshFeed(ctx, i, true)
	}
}

func (s *Server) refreshFeed(ctx context.Context, id int, scheduled bool) (int, error) {
	s.mu.Lock()
	sources := s.Engine.FeedInfo()
	if id < 0 || id >= len(sources) {
		s.mu.Unlock()
		return 0, fmt.Errorf("invalid feed id")
	}
	source := sources[id]
	if scheduled && (!source.Enabled || source.Interval == 0 || time.Now().Before(nextFeedRefresh(source, s.feedAttempts[id]))) {
		s.mu.Unlock()
		return 0, nil
	}
	if s.feedBusy[id] {
		s.mu.Unlock()
		return 0, fmt.Errorf("feed refresh already in progress")
	}
	if s.feedBusy == nil {
		s.feedBusy = make(map[int]bool)
	}
	s.feedBusy[id] = true
	old := s.Engine.Config().Feeds[id]
	s.mu.Unlock()

	domains, err := core.DownloadFeed(ctx, old)

	s.mu.Lock()
	defer s.mu.Unlock()
	defer delete(s.feedBusy, id)
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	c := s.Engine.Config()
	if id >= len(c.Feeds) || !reflect.DeepEqual(c.Feeds[id], old) {
		return 0, fmt.Errorf("feed changed during download; result discarded")
	}
	if err == nil {
		c.Feeds[id].Domains = domains
		c.Feeds[id].Updated = time.Now().UTC().Format(time.RFC3339Nano)
		err = s.commit(c)
		if err == nil {
			source = s.Engine.FeedInfo()[id]
		}
	}
	if s.feedAttempts == nil {
		s.feedAttempts = make(map[int]feedAttempt)
	}
	s.feedAttempts[id] = feedAttempt{source: source, finished: time.Now().UTC(), failed: err != nil}
	if err != nil {
		if scheduled {
			log.Printf("automatic refresh of domain feed %d failed; previous list retained", id)
		}
		return 0, err
	}
	return len(domains), nil
}
