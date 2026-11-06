// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package web

import (
	"context"
	"fmt"
	"gdns/internal/core"
	"github.com/miekg/dns"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestSecondaryPublicationAndFailure(t *testing.T) {
	pc := core.DefaultConfig()
	pc.Zones[0].Transfer.Allow = []string{"127.0.0.0/8"}
	primary, err := core.New(pc)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	ds := &dns.Server{Listener: l, Handler: primary, TsigProvider: primary, NotifyStartedFunc: func() { close(ready) }}
	go ds.ActivateAndServe()
	<-ready
	defer ds.Shutdown()
	c := core.DefaultConfig()
	c.Zones = []core.Zone{{Name: "home.arpa.", Kind: "secondary", Servers: []string{l.Addr().String()}}}
	e, err := core.New(c)
	if err != nil {
		t.Fatal(err)
	}
	var saved core.Config
	s := &Server{Engine: e, Persist: func(c core.Config) error { saved = c; return nil }}
	if err = s.refreshSecondary(context.Background(), 0, true); err != nil {
		t.Fatal(err)
	}
	got := e.Config()
	if len(got.Zones[0].Records) == 0 || !reflect.DeepEqual(saved, got) {
		t.Fatal("snapshot not persisted atomically")
	}
	edited := got
	edited.Zones = append([]core.Zone{}, got.Zones...)
	edited.Zones[0].Records = []string{"forged"}
	edited.Zones[0].Secondary.LastSuccess = time.Now().Add(time.Hour)
	preserveSecondary(&edited, got)
	if !reflect.DeepEqual(edited.Zones[0], got.Zones[0]) {
		t.Fatal("web can forge secondary snapshot")
	}
	edited.Zones[0].Servers = []string{"127.0.0.1:1"}
	preserveSecondary(&edited, got)
	if len(edited.Zones[0].Records) != 0 || !edited.Zones[0].Secondary.LastSuccess.IsZero() {
		t.Fatal("changed primary retained stale snapshot")
	}
	// A failed database transaction must not publish a refreshed timestamp.
	s.Persist = func(core.Config) error { return fmt.Errorf("disk failure") }
	if err = s.refreshSecondary(context.Background(), 0, true); err == nil {
		t.Fatal("persistence failure hidden")
	}
	if !reflect.DeepEqual(e.Config(), got) {
		t.Fatal("failed save published state")
	}
	// Restart from the persisted configuration retains freshness and records.
	restored, err := core.New(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.SecondaryStatus()[0].Available {
		t.Fatal("restart lost snapshot")
	}
	ds.Shutdown()
	s.Persist = func(c core.Config) error { saved = c; return nil }
	if err = s.refreshSecondary(context.Background(), 0, true); err == nil {
		t.Fatal("unreachable primary accepted")
	}
	failed := e.Config().Zones[0]
	if !failed.Secondary.LastSuccess.Equal(got.Zones[0].Secondary.LastSuccess) || !reflect.DeepEqual(failed.Records, got.Zones[0].Records) || failed.Secondary.LastError == "" {
		t.Fatal("failed refresh damaged last good snapshot")
	}
}
