//go:build linux && gdns_udp_addrport

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestUDPWriterDeadlineAndClose(t *testing.T) {
	if !parallelUDPWriter {
		t.Skip("parallel writer experiment disabled")
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := wrapUDPPacketConn(listener).(*packetUDPConn)
	defer c.Close()
	if c.writer == nil {
		t.Fatal("writer duplication failed")
	}
	dst, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	for _, set := range []func(time.Time) error{c.SetWriteDeadline, c.SetDeadline} {
		if err := set(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := c.WriteTo([]byte("test"), dst.LocalAddr()); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("deadline: %v", err)
			}
		}
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := c.WriteTo([]byte("test"), dst.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			dst.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 32)
			n, source, err := dst.ReadFromUDP(b)
			if err != nil || string(b[:n]) != "test" || source.String() != listener.LocalAddr().String() {
				t.Fatalf("source/data: %v %v", source, err)
			}
		}
	}
	address := listener.LocalAddr().String()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.WriteTo([]byte("test"), dst.LocalAddr()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed writer: %v", err)
		}
	}
	rebound, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatalf("descriptor leaked: %v", err)
	}
	rebound.Close()
}
