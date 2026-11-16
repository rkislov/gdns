//go:build !linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"time"
)

func packetPacer(mode string) (func(time.Time), func(), error) {
	if mode != "spin" {
		return nil, nil, fmt.Errorf("sleep pacing requires Linux")
	}
	return spinUntil, func() {}, nil
}
