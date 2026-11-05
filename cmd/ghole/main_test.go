// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"ghole/internal/core"
	"ghole/internal/storage"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONBootstrapAndExplicitImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := core.DefaultConfig()
	c.Blocked = []string{"initial.example"}
	write := func() {
		t.Helper()
		b, _ := json.Marshal(c)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	s, err := storage.Open(ctx, "sqlite", path+".db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := loadConfig(ctx, path, s, false)
	if err != nil || got.Blocked[0] != "initial.example" {
		t.Fatal("bootstrap", err)
	}
	c.Blocked = []string{"new.example"}
	write()
	got, err = loadConfig(ctx, path, s, false)
	if err != nil || got.Blocked[0] != "initial.example" {
		t.Fatal("file silently overrides SQL", err)
	}
	got, err = loadConfig(ctx, path, s, true)
	if err != nil || got.Blocked[0] != "new.example" {
		t.Fatal("explicit import", err)
	}
	c.DNSSECValidation = true
	c.DNSSEC.TrustAnchors = []string{"invalid"}
	write()
	if _, err = loadConfig(ctx, path, s, true); err == nil {
		t.Fatal("invalid import succeeded")
	}
	got, err = s.Load(ctx)
	if err != nil || got.DNSSECValidation {
		t.Fatal("invalid import changed database", err)
	}
}
