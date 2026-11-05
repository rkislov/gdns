// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"ghole/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSQLite(t *testing.T) { testStore(t, "sqlite", filepath.Join(t.TempDir(), "ghole.db")) }
func TestPostgreSQL(t *testing.T) {
	dsn := os.Getenv("GHOLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set GHOLE_TEST_POSTGRES_DSN for PostgreSQL integration tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema := fmt.Sprintf("ghole_test_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("DROP SCHEMA " + schema + " CASCADE")
	testStore(t, "postgres", dsn+" search_path="+schema)
}
func testStore(t *testing.T, driver, dsn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	open := func() *Store {
		s, e := Open(ctx, driver, dsn)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	s := open()
	if _, err := s.Load(ctx); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: %v", err)
	}
	c := core.DefaultConfig()
	c.DNSSECValidation = true
	c.DNSSEC.ExemptZones = []string{"corp.internal."}
	c.DNSSEC.IgnoreCD = true
	zero := uint16(0)
	c.DNSSEC.MaxNSEC3Iterations = &zero
	c.Blocked = []string{"bad.example"}
	c.Zones[0].RecordViews = []core.RecordView{{Clients: []string{"10.0.0.0/8"}, Records: []string{"router.home.arpa. 300 IN A 10.0.0.1"}}}
	domains := make([]string, 600)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%d.example", i)
	}
	c.Feeds = []core.Feed{{Name: "offline", Enabled: true, Domains: domains}}
	if err := s.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	other := open()
	got, err := other.Load(ctx)
	if err != nil || !reflect.DeepEqual(c, got) {
		t.Fatalf("roundtrip: %v\nwant=%+v\ngot=%+v", err, c, got)
	}
	broken := core.DefaultConfig()
	broken.Zones[0].Records = []string{"invalid record"}
	broken.Blocked = []string{"must-not-persist.example"}
	if err = s.Save(ctx, broken); err == nil {
		t.Fatal("invalid records persisted")
	}
	got, err = s.Load(ctx)
	if err != nil || !reflect.DeepEqual(c, got) {
		t.Fatal("failed write was not rolled back", err)
	}
	c.Feeds[0].Name = "renamed"
	c.Zones[0].Clients = []string{"127.0.0.0/8"}
	if err = s.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err = other.Save(ctx, got); !errors.Is(err, ErrConflict) {
		t.Fatalf("lost update: %v", err)
	}
	got, err = other.Load(ctx)
	if err != nil || !reflect.DeepEqual(c, got) {
		t.Fatal("metadata update", err)
	}
	c.Zones = []core.Zone{}
	c.Feeds = []core.Feed{}
	c.Blocked = []string{}
	if err = s.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	restarted := open()
	got, err = restarted.Load(ctx)
	if err != nil || !reflect.DeepEqual(c, got) {
		t.Fatal("delete or restart", err)
	}
	for _, table := range []string{"ghole_records", "ghole_record_views", "ghole_view_records", "ghole_feed_domains", "ghole_blocked"} {
		var n int
		if err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("orphan rows in %s: %d %v", table, n, err)
		}
	}
}

func TestSchemaMigrationPreservesRecords(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Load(ctx)
	c := core.DefaultConfig()
	if err = s.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE ghole_state SET version=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Load(ctx)
	if err != nil || !reflect.DeepEqual(c, got) {
		t.Fatal("migration lost data", err)
	}
	var version int
	_ = s.db.QueryRow("SELECT version FROM ghole_state").Scan(&version)
	if version != 2 {
		t.Fatal("schema not upgraded")
	}
}
