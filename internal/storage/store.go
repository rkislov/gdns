// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

// Package storage keeps administrative data in SQL. DNS resolution never queries SQL.
package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"ghole/internal/core"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/miekg/dns"
	"hash"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrEmpty = errors.New("database has no configuration")
var ErrConflict = errors.New("database changed in another process; restart to reload before saving")

type Store struct {
	db           *sql.DB
	driver       string
	mu           sync.Mutex
	revision     int64
	zones, feeds [][32]byte
	blocked      [32]byte
	loaded       bool
	views        map[[2]int][32]byte
}

func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	switch driver {
	case "sqlite":
		// A path, rather than an arbitrary SQLite URI, prevents accidental shared/in-memory databases.
		if dsn == "" || strings.ContainsAny(dsn, "?\x00") || strings.HasPrefix(dsn, "file:") || dsn == ":memory:" {
			return nil, fmt.Errorf("SQLite requires a filesystem path")
		}
		if err := os.MkdirAll(filepath.Dir(dsn), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(dsn, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Chmod(0600); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
	case "postgres":
		if dsn == "" {
			return nil, fmt.Errorf("PostgreSQL requires GHOLE_DATABASE_URL or -database")
		}
	default:
		return nil, fmt.Errorf("storage must be sqlite or postgres")
	}
	name := driver
	if driver == "postgres" {
		name = "pgx"
	}
	db, err := sql.Open(name, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database failed", driver)
	}
	s := &Store{db: db, driver: driver}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		for _, stmt := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
			if _, err = db.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("configure SQLite: %w", err)
			}
		}
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(3)
		db.SetConnMaxLifetime(30 * time.Minute)
	}
	if err = db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connect to %s database failed (check address, credentials and TLS)", driver)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// State-row writes serialize schema initialization in PostgreSQL as well.
	if driver == "postgres" {
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(7348101961)"); err != nil {
			return nil, err
		}
	}
	schema := []string{
		`CREATE TABLE IF NOT EXISTS ghole_state (id INTEGER PRIMARY KEY CHECK (id=1), version INTEGER NOT NULL, revision BIGINT NOT NULL, config TEXT NOT NULL)`,
		`INSERT INTO ghole_state(id,version,revision,config) VALUES(1,1,0,'') ON CONFLICT(id) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS ghole_zones (id INTEGER PRIMARY KEY, metadata TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS ghole_records (zone_id INTEGER NOT NULL, position INTEGER NOT NULL, owner TEXT NOT NULL, rrtype INTEGER NOT NULL, ttl BIGINT NOT NULL, rr TEXT NOT NULL, PRIMARY KEY(zone_id,position))`,
		`CREATE INDEX IF NOT EXISTS ghole_records_owner_type ON ghole_records(zone_id,owner,rrtype)`,
		`CREATE TABLE IF NOT EXISTS ghole_feeds (id INTEGER PRIMARY KEY, metadata TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS ghole_feed_domains (feed_id INTEGER NOT NULL, position INTEGER NOT NULL, domain TEXT NOT NULL, PRIMARY KEY(feed_id,position))`,
		`CREATE TABLE IF NOT EXISTS ghole_blocked (position INTEGER PRIMARY KEY, domain TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS ghole_record_views (zone_id INTEGER NOT NULL,id INTEGER NOT NULL,metadata TEXT NOT NULL,PRIMARY KEY(zone_id,id))`,
		`CREATE TABLE IF NOT EXISTS ghole_view_records (zone_id INTEGER NOT NULL,view_id INTEGER NOT NULL,position INTEGER NOT NULL,owner TEXT NOT NULL,rrtype INTEGER NOT NULL,ttl BIGINT NOT NULL,rr TEXT NOT NULL,PRIMARY KEY(zone_id,view_id,position))`,
		`CREATE INDEX IF NOT EXISTS ghole_view_records_owner_type ON ghole_view_records(zone_id,view_id,owner,rrtype)`,
	}
	for _, stmt := range schema {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("initialize %s schema: %w", driver, err)
		}
	}
	var version int
	if err = tx.QueryRowContext(ctx, "SELECT version FROM ghole_state WHERE id=1").Scan(&version); err != nil {
		return nil, err
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("unsupported database schema version %d", version)
	}
	if version == 1 {
		if _, err = tx.ExecContext(ctx, "UPDATE ghole_state SET version=2 WHERE id=1"); err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func hashes(c core.Config) (zones, feeds [][32]byte, blocked [32]byte) {
	for _, z := range c.Zones {
		zones = append(zones, hashStrings(z.Records))
	}
	for _, f := range c.Feeds {
		feeds = append(feeds, hashStrings(f.Domains))
	}
	return zones, feeds, hashStrings(c.Blocked)
}
func hashStrings(values []string) [32]byte {
	var h hash.Hash = sha256.New()
	for _, v := range values {
		h.Write([]byte(strconv.Itoa(len(v))))
		h.Write([]byte{':'})
		h.Write([]byte(v))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func (s *Store) Load(ctx context.Context) (core.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c core.Config
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	query := "SELECT version,revision,config FROM ghole_state WHERE id=1"
	if s.driver == "postgres" {
		query += " FOR SHARE"
	}
	var version int
	var revision int64
	var data string
	if err = tx.QueryRowContext(ctx, query).Scan(&version, &revision, &data); err != nil {
		return c, err
	}
	if version != 2 {
		return c, fmt.Errorf("unsupported database schema version %d", version)
	}
	if data == "" {
		s.revision = revision
		s.loaded = true
		return c, ErrEmpty
	}
	if err = json.Unmarshal([]byte(data), &c); err != nil {
		return c, err
	}
	read := func(query string, fn func(*sql.Rows) error) error {
		rows, e := tx.QueryContext(ctx, query)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			if e = fn(rows); e != nil {
				return e
			}
		}
		return rows.Err()
	}
	if err = read("SELECT id,metadata FROM ghole_zones ORDER BY id", func(r *sql.Rows) error {
		var i int
		var data string
		if e := r.Scan(&i, &data); e != nil {
			return e
		}
		if i != len(c.Zones) {
			return fmt.Errorf("invalid zone sequence")
		}
		var z core.Zone
		if e := json.Unmarshal([]byte(data), &z); e != nil {
			return e
		}
		z.Records = []string{}
		c.Zones = append(c.Zones, z)
		return nil
	}); err != nil {
		return c, err
	}
	if err = read("SELECT zone_id,rr FROM ghole_records ORDER BY zone_id,position", func(r *sql.Rows) error {
		var i int
		var rr string
		if e := r.Scan(&i, &rr); e != nil {
			return e
		}
		if i < 0 || i >= len(c.Zones) {
			return fmt.Errorf("orphan zone record")
		}
		c.Zones[i].Records = append(c.Zones[i].Records, rr)
		return nil
	}); err != nil {
		return c, err
	}
	if err = loadViews(ctx, tx, &c); err != nil {
		return c, err
	}
	if err = read("SELECT id,metadata FROM ghole_feeds ORDER BY id", func(r *sql.Rows) error {
		var i int
		var data string
		if e := r.Scan(&i, &data); e != nil {
			return e
		}
		if i != len(c.Feeds) {
			return fmt.Errorf("invalid feed sequence")
		}
		var f core.Feed
		if e := json.Unmarshal([]byte(data), &f); e != nil {
			return e
		}
		f.Domains = []string{}
		c.Feeds = append(c.Feeds, f)
		return nil
	}); err != nil {
		return c, err
	}
	if err = read("SELECT feed_id,domain FROM ghole_feed_domains ORDER BY feed_id,position", func(r *sql.Rows) error {
		var i int
		var d string
		if e := r.Scan(&i, &d); e != nil {
			return e
		}
		if i < 0 || i >= len(c.Feeds) {
			return fmt.Errorf("orphan feed domain")
		}
		c.Feeds[i].Domains = append(c.Feeds[i].Domains, d)
		return nil
	}); err != nil {
		return c, err
	}
	if err = read("SELECT domain FROM ghole_blocked ORDER BY position", func(r *sql.Rows) error {
		var d string
		if e := r.Scan(&d); e != nil {
			return e
		}
		c.Blocked = append(c.Blocked, d)
		return nil
	}); err != nil {
		return c, err
	}
	if err = tx.Commit(); err != nil {
		return c, err
	}
	s.revision = revision
	s.loaded = true
	s.zones, s.feeds, s.blocked = hashes(c)
	s.views = viewHashes(c)
	return c, nil
}

// Save uses a revision compare-and-swap, so a stale process cannot overwrite another writer.
func (s *Store) Save(ctx context.Context, c core.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return fmt.Errorf("Load must precede Save")
	}
	zones, feeds, blocked := hashes(c)
	views := viewHashes(c)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	meta := c
	meta.Zones = []core.Zone{}
	meta.Feeds = []core.Feed{}
	meta.Blocked = []string{}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE ghole_state SET config=$1,revision=revision+1 WHERE id=1 AND version=2 AND revision=$2", string(b), s.revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_zones"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_feeds"); err != nil {
		return err
	}
	for i, z := range c.Zones {
		records := z.Records
		z.Records = nil
		z.RecordViews = nil
		b, err = json.Marshal(z)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO ghole_zones(id,metadata) VALUES($1,$2)", i, string(b)); err != nil {
			return err
		}
		if i < len(s.zones) && s.zones[i] == zones[i] {
			continue
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_records WHERE zone_id=$1", i); err != nil {
			return err
		}
		for start := 0; start < len(records); start += 250 {
			end := min(start+250, len(records))
			rows := make([][]any, 0, end-start)
			for j := start; j < end; j++ {
				line := records[j]
				rr, e := dns.NewRR(line)
				if e != nil {
					return e
				}
				h := rr.Header()
				rows = append(rows, []any{i, j, strings.ToLower(h.Name), int(h.Rrtype), int64(h.Ttl), line})
			}
			if err = insert(ctx, tx, "ghole_records", "zone_id,position,owner,rrtype,ttl,rr", rows); err != nil {
				return err
			}
		}

	}
	if err = saveViews(ctx, tx, c, s.views, views); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_records WHERE zone_id >= $1", len(c.Zones)); err != nil {
		return err
	}
	for i, f := range c.Feeds {
		domains := f.Domains
		f.Domains = nil
		b, err = json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO ghole_feeds(id,metadata) VALUES($1,$2)", i, string(b)); err != nil {
			return err
		}
		if i < len(s.feeds) && s.feeds[i] == feeds[i] {
			continue
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_feed_domains WHERE feed_id=$1", i); err != nil {
			return err
		}
		if err = insertStrings(ctx, tx, "ghole_feed_domains", "feed_id,position,domain", domains, &i); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_feed_domains WHERE feed_id >= $1", len(c.Feeds)); err != nil {
		return err
	}
	if blocked != s.blocked {
		if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_blocked"); err != nil {
			return err
		}
		if err = insertStrings(ctx, tx, "ghole_blocked", "position,domain", c.Blocked, nil); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.revision++
	s.zones = zones
	s.feeds = feeds
	s.blocked = blocked
	s.views = views
	return nil
}
func insertStrings(ctx context.Context, tx *sql.Tx, table, columns string, values []string, id *int) error {
	for start := 0; start < len(values); start += 250 {
		end := min(start+250, len(values))
		rows := make([][]any, 0, end-start)
		for i := start; i < end; i++ {
			r := []any{i, values[i]}
			if id != nil {
				r = append([]any{*id}, r...)
			}
			rows = append(rows, r)
		}
		if err := insert(ctx, tx, table, columns, rows); err != nil {
			return err
		}
	}
	return nil
}
func insert(ctx context.Context, tx *sql.Tx, table, columns string, rows [][]any) error {
	for start := 0; start < len(rows); start += 250 {
		end := min(start+250, len(rows))
		var q strings.Builder
		q.WriteString("INSERT INTO " + table + "(" + columns + ") VALUES ")
		args := []any{}
		for i := start; i < end; i++ {
			if i > start {
				q.WriteByte(',')
			}
			q.WriteByte('(')
			for j, v := range rows[i] {
				if j > 0 {
					q.WriteByte(',')
				}
				args = append(args, v)
				q.WriteString("$" + strconv.Itoa(len(args)))
			}
			q.WriteByte(')')
		}
		if _, err := tx.ExecContext(ctx, q.String(), args...); err != nil {
			return err
		}
	}
	return nil
}
