//go:build linux && gdns_udp_addrport

// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
package transport

import (
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
)

type udpPacketPeer struct {
	addr         net.UDPAddr
	remote       netip.AddrPort
	ip           [16]byte
	replyControl []byte
	control      [64]byte
	receive      [128]byte
}

func (p *udpPacketPeer) Network() string { return "udp" }
func (p *udpPacketPeer) String() string  { return p.addr.String() }

type packetUDPConn struct{ *net.UDPConn }

func wrapUDPPacketConn(conn net.PacketConn) net.PacketConn {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return conn
	}
	err4 := ipv4.NewPacketConn(udp).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	err6 := ipv6.NewPacketConn(udp).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	if err4 != nil && err6 != nil {
		return conn
	}
	return &packetUDPConn{udp}
}

// Each request owns both receive scratch and outgoing packet-info.
// No batching, queue, deadline override, or scheduling change is introduced.
func (c *packetUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	peer := new(udpPacketPeer)
	n, nn, _, addr, err := c.UDPConn.ReadMsgUDPAddrPort(b, peer.receive[:])
	if err != nil {
		return n, nil, err
	}
	peer.remote = addr
	peer.addr.Port = int(addr.Port())
	peer.addr.Zone = addr.Addr().Zone()
	if addr.Addr().Is4() {
		ip := addr.Addr().As4()
		copy(peer.ip[:4], ip[:])
		peer.addr.IP = peer.ip[:4]
	} else {
		peer.ip = addr.Addr().As16()
		peer.addr.IP = peer.ip[:]
	}
	peer.setReplyControl(peer.receive[:nn])
	return n, peer, nil
}
func (c *packetUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if peer, ok := addr.(*udpPacketPeer); ok {
		n, _, err := c.UDPConn.WriteMsgUDPAddrPort(b, peer.replyControl, peer.remote)
		return n, err
	}
	return c.UDPConn.WriteTo(b, addr)
}
func (p *udpPacketPeer) setReplyControl(oob []byte) {
	original := oob
	for len(oob) >= unix.CmsgLen(0) {
		h, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			break
		}
		size := unix.CmsgSpace(len(data))
		if size <= len(p.control) && size <= len(oob) {
			offset := unix.CmsgLen(0)
			if h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO && len(data) == 12 {
				copy(p.control[:], oob[:size])
				clear(p.control[offset : offset+12])
				copy(p.control[offset+4:offset+8], data[8:12])
				p.replyControl = p.control[:size]
				return
			}
			if h.Level == unix.IPPROTO_IPV6 && h.Type == unix.IPV6_PKTINFO && len(data) == 20 && net.IP(data[:16]).To4() == nil {
				copy(p.control[:], oob[:size])
				clear(p.control[offset+16 : offset+20])
				p.replyControl = p.control[:size]
				return
			}
		}
		oob = rest
	}
	p.replyControl = replyUDPControl(original)
}

func replyUDPControl(oob []byte) []byte {
	var v6 ipv6.ControlMessage
	if v6.Parse(oob) == nil && v6.Dst != nil && v6.Dst.To4() == nil {
		return (&ipv6.ControlMessage{Src: v6.Dst}).Marshal()
	}
	var v4 ipv4.ControlMessage
	if v4.Parse(oob) == nil && v4.Dst != nil {
		return (&ipv4.ControlMessage{Src: v4.Dst}).Marshal()
	}
	// Dual-stack sockets can report an IPv4-mapped destination in IPV6_PKTINFO.
	if v6.Dst != nil && v6.Dst.To4() != nil {
		return (&ipv4.ControlMessage{Src: v6.Dst.To4()}).Marshal()
	}
	return nil
}

type udpPeerWriter struct {
	dns.ResponseWriter
	peer *udpPacketPeer
}

func (w udpPeerWriter) RemoteAddr() net.Addr { return &w.peer.addr }
func udpHandler(handler dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if peer, ok := w.RemoteAddr().(*udpPacketPeer); ok {
			handler.ServeDNS(udpPeerWriter{w, peer}, q)
			return
		}
		handler.ServeDNS(w, q)
	})
}
