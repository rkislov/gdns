//go:build linux && gdns_udp_addrport

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"github.com/miekg/dns"
	"net"
	"testing"
)

// Includes both client and server syscalls. One outstanding datagram prevents
// socket overflow; differences in allocations isolate the session adapter.
func BenchmarkUDPSessionRoundTrip(b *testing.B) {
	for _, fast := range []bool{false, true} {
		label := "library"
		if fast {
			label = "addrport"
		}
		b.Run(label, func(b *testing.B) {
			raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer raw.Close()
			conn := wrapUDPPacketConn(raw)
			client, err := net.Dial("udp4", raw.LocalAddr().String())
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			data := []byte("packet")
			buf := make([]byte, 128)
			reply := make([]byte, 128)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err = client.Write(data); err != nil {
					b.Fatal(err)
				}
				if fast {
					n, peer, e := conn.ReadFrom(buf)
					if e != nil {
						b.Fatal(e)
					}
					_, err = conn.WriteTo(buf[:n], peer)
				} else {
					n, peer, e := dns.ReadFromSessionUDP(raw.(*net.UDPConn), buf)
					if e != nil {
						b.Fatal(e)
					}
					_, err = dns.WriteToSessionUDP(raw.(*net.UDPConn), buf[:n], peer)
				}
				if err != nil {
					b.Fatal(err)
				}
				if _, err = client.Read(reply); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
