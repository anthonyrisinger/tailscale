// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

// Package gro implements GRO for the receive (write) path into gVisor.
package gro

import (
	"bytes"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// RXChecksumOffload validates IPv4, TCP, and UDP header checksums in p,
// returning an equivalent *stack.PacketBuffer if they are valid, otherwise nil.
// The returned buffer carries per-packet TCP/UDP checksum status for
// stack.CapabilityRXChecksumOffloadPerPacket. Other protocols with checksum
// fields, e.g. ICMP{v6}, are still validated by gVisor. Fragments cannot have
// their L4 checksums validated before reassembly. IPv4 fragments still have
// their header checksum validated.
func RXChecksumOffload(p *packet.Parsed) *stack.PacketBuffer {
	var (
		pn        tcpip.NetworkProtocolNumber
		csumStart int
		fragment  bool
	)
	buf := p.Buffer()

	switch p.IPVersion {
	case 4:
		if len(buf) < header.IPv4MinimumSize {
			return nil
		}
		csumStart = int((buf[0] & 0x0F) * 4)
		if csumStart < header.IPv4MinimumSize || csumStart > header.IPv4MaximumHeaderSize || len(buf) < csumStart {
			return nil
		}
		if ^tun.Checksum(buf[:csumStart], 0) != 0 {
			return nil
		}
		fragment = header.IPv4(buf).More() || header.IPv4(buf).FragmentOffset() != 0
		pn = header.IPv4ProtocolNumber
	case 6:
		if len(buf) < header.IPv6FixedHeaderSize {
			return nil
		}
		packetLen := header.IPv6FixedHeaderSize + int(header.IPv6(buf).PayloadLength())
		if packetLen > len(buf) {
			return nil
		}
		buf = buf[:packetLen]
		csumStart = header.IPv6FixedHeaderSize
		pn = header.IPv6ProtocolNumber
		hasExtensionHeader := ipproto.Proto(buf[6]) != p.IPProto
		if hasExtensionHeader || (p.IPProto != ipproto.ICMPv6 && p.IPProto != ipproto.TCP && p.IPProto != ipproto.UDP) {
			// buf could have extension headers before a UDP or TCP header, but
			// packet.Parsed may already have advanced through a Fragment header.
			// Find the transport offset and distinguish fragments from atomic
			// fragments before validating L4. Make use of gVisor's existing
			// extension header parsing via parse.IPv6() in order to unpack the
			// L4 csumStart index. This is not particularly efficient as we have
			// to allocate a short-lived stack.PacketBuffer that cannot be
			// re-used. parse.IPv6() "consumes" the IPv6 headers, so we can't
			// inject this stack.PacketBuffer into the stack at a later point.
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buf)),
			})
			defer packetBuf.DecRef()
			// The rightmost bool returns false only if packetBuf is too short,
			// which we've already accounted for above.
			transportProto, _, fragOffset, fragMore, _ := parse.IPv6(packetBuf)
			fragment = fragOffset != 0 || fragMore
			if transportProto == header.TCPProtocolNumber || transportProto == header.UDPProtocolNumber {
				csumLen := packetBuf.Data().Size()
				if len(buf) < csumLen {
					return nil
				}
				csumStart = len(buf) - csumLen
				p.IPProto = ipproto.Proto(transportProto)
			}
		}
	}

	if !fragment && (p.IPProto == ipproto.TCP || p.IPProto == ipproto.UDP) {
		lenForPseudo := len(buf) - csumStart
		csum := tun.PseudoHeaderChecksum(
			uint8(p.IPProto),
			p.Src.Addr().AsSlice(),
			p.Dst.Addr().AsSlice(),
			uint16(lenForPseudo))
		csum = tun.Checksum(buf[csumStart:], csum)
		if ^csum != 0 {
			return nil
		}
	}

	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(bytes.Clone(buf)),
	})
	packetBuf.NetworkProtocolNumber = pn
	// A non-atomic fragment cannot validate the full transport checksum.
	packetBuf.RXChecksumValidated = !fragment
	return packetBuf
}
