// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"gdns/internal/core"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduledRefreshPreservesFeedOnFailure(t *testing.T) {
	var requests atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch requests.Add(1) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			fmt.Fprintln(w, "# empty feed")
		default:
			fmt.Fprintln(w, "new.example")
		}
	}))
	defer source.Close()

	config := core.DefaultConfig()
	old := core.Feed{
		Name: "test", URL: source.URL, Enabled: true, RefreshIntervalMinutes: 1,
		Domains: []string{"old.example"}, Updated: time.Now().Add(-time.Hour).Format(time.RFC3339),
	}
	config.Feeds = []core.Feed{old}
	engine, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	var saved []core.Feed
	server := &Server{Engine: engine, Persist: func(c core.Config) error { saved = c.Feeds; return nil }}
	for attempt := int32(1); attempt <= 2; attempt++ {
		server.refreshDueFeeds(context.Background())
		if !reflect.DeepEqual(engine.Config().Feeds[0], old) || saved != nil {
			t.Fatal("failed refresh changed published or persisted feed")
		}
		status := server.feedStatuses()[0]
		if !status.Failed || status.Updated != old.Updated || status.Count != 1 || status.NextRefresh == "" {
			t.Fatalf("unexpected failure status: %+v", status)
		}
		server.refreshDueFeeds(context.Background())
		if requests.Load() != attempt {
			t.Fatal("failure retried before the interval elapsed")
		}
		previous := server.feedAttempts[0]
		previous.finished = time.Now().Add(-time.Minute)
		server.feedAttempts[0] = previous
	}
	server.refreshDueFeeds(context.Background())
	published := engine.Config().Feeds
	if !reflect.DeepEqual(published, saved) || !reflect.DeepEqual(published[0].Domains, []string{"new.example"}) ||
		published[0].Updated == old.Updated || published[0].RefreshIntervalMinutes != 1 || server.feedStatuses()[0].Failed {
		t.Fatal("successful retry did not persist and publish the new list")
	}
}

func TestRefreshDiscardsDownloadAfterSourceEdit(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-finish
		fmt.Fprintln(w, "stale.example")
	}))
	defer source.Close()
	defer close(finish)
	config := core.DefaultConfig()
	config.Feeds = []core.Feed{{Name: "test", URL: source.URL, Enabled: true, Domains: []string{"old.example"}}}
	engine, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Engine: engine, Persist: func(core.Config) error { return nil }}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _, err := server.refreshFeed(ctx, 0, false); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("download did not start")
	}
	server.mu.Lock()
	config.Feeds[0].Enabled = false
	err = server.commit(config)
	server.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Release the handler without publishing any data from the outdated source.
	finish <- struct{}{}
	if err := <-done; err == nil || !reflect.DeepEqual(engine.Config().Feeds, config.Feeds) {
		t.Fatal("outdated result was published")
	}
}
