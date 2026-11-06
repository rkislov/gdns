// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"gdns/internal/access"
)

func (s *Store) LoadAccess(ctx context.Context) (access.Config, uint64, error) {
	var c access.Config
	var revision uint64
	var data string
	if err := s.db.QueryRowContext(ctx, "SELECT revision,state FROM gdns_auth_state WHERE id=1").Scan(&revision, &data); err != nil {
		return c, 0, err
	}
	if data == "" {
		return c, revision, access.ErrEmpty
	}
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return c, revision, err
	}
	return c, revision, nil
}
func (s *Store) SaveAccess(ctx context.Context, c access.Config, revision uint64) (uint64, error) {
	if err := access.Validate(c); err != nil {
		return 0, err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, "UPDATE gdns_auth_state SET state=$1,revision=revision+1 WHERE id=1 AND revision=$2", string(data), revision)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, ErrConflict
	}
	return revision + 1, nil
}
