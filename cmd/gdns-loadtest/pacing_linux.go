//go:build linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func packetPacer(mode string) (func(time.Time), func(), error) {
	if mode == "spin" {
		return spinUntil, func() {}, nil
	}
	if mode != "sleep" {
		return nil, nil, fmt.Errorf("unknown pacing mode %q", mode)
	}
	runtime.LockOSThread()
	old, err := unix.PrctlRetInt(unix.PR_GET_TIMERSLACK, 0, 0, 0, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, nil, err
	}
	if err = unix.Prctl(unix.PR_SET_TIMERSLACK, 1, 0, 0, 0); err != nil {
		runtime.UnlockOSThread()
		return nil, nil, err
	}
	cleanup := func() { _ = unix.Prctl(unix.PR_SET_TIMERSLACK, uintptr(old), 0, 0, 0); runtime.UnlockOSThread() }
	var clock unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		cleanup()
		return nil, nil, err
	}
	origin := time.Now()
	wait := func(deadline time.Time) {
		if !time.Now().Before(deadline) {
			return
		}
		target := unix.NsecToTimespec(clock.Nano() + deadline.Sub(origin).Nanoseconds())
		for {
			err := unix.ClockNanosleep(unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME, &target, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				panic(err)
			}
			break
		}
		// Clock calibration can differ by a fraction of a microsecond. Never send
		// before the requested Go monotonic deadline.
		spinUntil(deadline)
	}
	return wait, cleanup, nil
}
