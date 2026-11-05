// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"gdns/internal/core"
	"github.com/miekg/dns"
	"strings"
)

func viewHashes(c core.Config) map[[2]int][32]byte {
	out := map[[2]int][32]byte{}
	for i, z := range c.Zones {
		for j, v := range z.RecordViews {
			out[[2]int{i, j}] = hashStrings(v.Records)
		}
	}
	return out
}
func loadViews(ctx context.Context, tx *sql.Tx, c *core.Config) error {
	rows, err := tx.QueryContext(ctx, "SELECT zone_id,id,metadata FROM ghole_record_views ORDER BY zone_id,id")
	if err != nil {
		return err
	}
	for rows.Next() {
		var z, i int
		var data string
		if err = rows.Scan(&z, &i, &data); err != nil {
			rows.Close()
			return err
		}
		if z < 0 || z >= len(c.Zones) || i != len(c.Zones[z].RecordViews) {
			rows.Close()
			return fmt.Errorf("invalid record view sequence")
		}
		var v core.RecordView
		if err = json.Unmarshal([]byte(data), &v); err != nil {
			rows.Close()
			return err
		}
		v.Records = []string{}
		c.Zones[z].RecordViews = append(c.Zones[z].RecordViews, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT zone_id,view_id,rr FROM ghole_view_records ORDER BY zone_id,view_id,position")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var z, v int
		var rr string
		if err = rows.Scan(&z, &v, &rr); err != nil {
			return err
		}
		if z < 0 || z >= len(c.Zones) || v < 0 || v >= len(c.Zones[z].RecordViews) {
			return fmt.Errorf("orphan split record")
		}
		c.Zones[z].RecordViews[v].Records = append(c.Zones[z].RecordViews[v].Records, rr)
	}
	return rows.Err()
}
func saveViews(ctx context.Context, tx *sql.Tx, c core.Config, previous, current map[[2]int][32]byte) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM ghole_record_views"); err != nil {
		return err
	}
	for zi, z := range c.Zones {
		for vi, v := range z.RecordViews {
			records := v.Records
			v.Records = nil
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO ghole_record_views(zone_id,id,metadata) VALUES($1,$2,$3)", zi, vi, string(b)); err != nil {
				return err
			}
			key := [2]int{zi, vi}
			if old, ok := previous[key]; ok && old == current[key] {
				continue
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM ghole_view_records WHERE zone_id=$1 AND view_id=$2", zi, vi); err != nil {
				return err
			}
			for start := 0; start < len(records); start += 250 {
				end := min(start+250, len(records))
				rows := make([][]any, 0, end-start)
				for i := start; i < end; i++ {
					rr, e := dns.NewRR(records[i])
					if e != nil {
						return e
					}
					h := rr.Header()
					rows = append(rows, []any{zi, vi, i, strings.ToLower(h.Name), int(h.Rrtype), int64(h.Ttl), records[i]})
				}
				if err = insert(ctx, tx, "ghole_view_records", "zone_id,view_id,position,owner,rrtype,ttl,rr", rows); err != nil {
					return err
				}
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM ghole_view_records WHERE zone_id=$1 AND view_id >= $2", zi, len(z.RecordViews)); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM ghole_view_records WHERE zone_id >= $1", len(c.Zones))
	return err
}
