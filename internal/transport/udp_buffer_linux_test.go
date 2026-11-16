//go:build linux

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestUDPReceiveBuffer(t *testing.T) {
	data, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		t.Skip(err)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	expected := 2 * min(1<<20, limit)
	for _, workers := range []int{1, 2} {
		conns, err := ListenUDP("127.0.0.1:0", workers)
		if err != nil {
			t.Fatal(err)
		}
		for _, conn := range conns {
			udp := conn.(*net.UDPConn)
			raw, err := udp.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			size := 0
			var socketErr error
			err = raw.Control(func(fd uintptr) { size, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) })
			conn.Close()
			if err != nil || socketErr != nil || size < expected {
				t.Fatalf("invalid receive buffer %d %v %v", size, err, socketErr)
			}
			t.Logf("workers=%d actual SO_RCVBUF=%d (kernel may cap request)", workers, size)
		}
	}
}
