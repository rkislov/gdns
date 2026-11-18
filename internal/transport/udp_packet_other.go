//go:build !linux || !gdns_udp_addrport

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"github.com/miekg/dns"
	"net"
)

func wrapUDPPacketConn(conn net.PacketConn) net.PacketConn { return conn }
func udpHandler(handler dns.Handler) dns.Handler           { return handler }
