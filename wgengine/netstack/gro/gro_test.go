// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package gro

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

func Test_RXChecksumOffload(t *testing.T) {
	payloadLen := 100

	tcpFields := &header.TCPFields{
		SrcPort:    1,
		DstPort:    1,
		SeqNum:     1,
		AckNum:     1,
		DataOffset: 20,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 3000,
	}
	tcp4 := make([]byte, 20+20+payloadLen)
	ipv4H := header.IPv4(tcp4)
	ipv4H.Encode(&header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.1").AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.2").AsSlice()),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		TotalLength: uint16(len(tcp4)),
	})
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	tcpH := header.TCP(tcp4[20:])
	tcpH.Encode(tcpFields)
	pseudoCsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(20+payloadLen))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))

	tcp6ExtHeader := make([]byte, 40+8+20+payloadLen)
	ipv6H := header.IPv6(tcp6ExtHeader)
	ipv6H.Encode(&header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		TransportProtocol: 60, // really next header; destination options ext header
		HopLimit:          64,
		PayloadLength:     uint16(8 + 20 + payloadLen),
	})
	tcp6ExtHeader[40] = uint8(header.TCPProtocolNumber) // next header
	tcp6ExtHeader[41] = 0                               // length of ext header in 8-octet units, exclusive of first 8 octets.
	// 42-47 options and padding
	tcpH = header.TCP(tcp6ExtHeader[48:])
	tcpH.Encode(tcpFields)
	pseudoCsum = header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(20+payloadLen))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))

	tcp4InvalidCsum := make([]byte, len(tcp4))
	copy(tcp4InvalidCsum, tcp4)
	at := 20 + 16
	tcp4InvalidCsum[at] = ^tcp4InvalidCsum[at]

	tcp4FirstFragment := make([]byte, 20+20+60)
	copy(tcp4FirstFragment, tcp4[:len(tcp4FirstFragment)])
	ipv4H = header.IPv4(tcp4FirstFragment)
	ipv4H.SetTotalLength(uint16(len(tcp4FirstFragment)))
	ipv4H.SetFlagsFragmentOffset(header.IPv4FlagMoreFragments, 0)
	ipv4H.SetChecksum(0)
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())

	tcp4SecondFragment := make([]byte, 20+40)
	copy(tcp4SecondFragment, tcp4[:20])
	copy(tcp4SecondFragment[20:], tcp4[20+80:])
	ipv4H = header.IPv4(tcp4SecondFragment)
	ipv4H.SetTotalLength(uint16(len(tcp4SecondFragment)))
	ipv4H.SetFlagsFragmentOffset(0, 80)
	ipv4H.SetChecksum(0)
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())

	tcp6ExtHeaderInvalidCsum := make([]byte, len(tcp6ExtHeader))
	copy(tcp6ExtHeaderInvalidCsum, tcp6ExtHeader)
	at = 40 + 8 + 16
	tcp6ExtHeaderInvalidCsum[at] = ^tcp6ExtHeaderInvalidCsum[at]

	type testCase struct {
		name          string
		input         []byte
		wantPB        bool
		wantValidated bool
	}
	tests := []testCase{
		{
			"tcp4 packet valid csum",
			tcp4,
			true,
			true,
		},
		{
			"tcp6 with ext header valid csum",
			tcp6ExtHeader,
			true,
			true,
		},
		{
			"tcp4 packet invalid csum",
			tcp4InvalidCsum,
			false,
			false,
		},
		{
			"tcp4 first fragment skips L4 csum",
			tcp4FirstFragment,
			true,
			false,
		},
		{
			"tcp4 second fragment skips L4 csum",
			tcp4SecondFragment,
			true,
			false,
		},
		{
			"tcp6 with ext header invalid csum",
			tcp6ExtHeaderInvalidCsum,
			false,
			false,
		},
	}
	udp6ExtHeader := bytes.Clone(tcp6ExtHeader)
	udp6ExtHeader[40] = uint8(ipproto.UDP)
	udpH := header.UDP(udp6ExtHeader[48:])
	udpH.Encode(&header.UDPFields{SrcPort: 1, DstPort: 1, Length: uint16(len(udpH))})
	sum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(len(udpH)))
	udpH.SetChecksum(^tun.Checksum(udpH, sum))

	corrupt := func(buf []byte) []byte {
		buf = bytes.Clone(buf)
		buf[len(buf)-1] ^= 1
		return buf
	}
	for _, base := range [][]byte{tcp6ExtHeader, udp6ExtHeader} {
		proto := ipproto.Proto(base[40])
		transportLen := len(base) - 48
		fragment := func(start, end int, more bool) []byte {
			buf := append(bytes.Clone(base[:48]), base[48+start:48+end]...)
			buf[6] = uint8(header.IPv6FragmentExtHdrIdentifier)
			header.IPv6(buf).SetPayloadLength(uint16(len(buf) - 40))
			offset := uint16(start)
			if more {
				offset |= 1
			}
			binary.BigEndian.PutUint16(buf[42:44], offset)
			return buf
		}
		padded := func(packet []byte) []byte {
			buf := append(bytes.Clone(packet), make([]byte, 8)...)
			sum := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(proto), ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(transportLen))
			// Match an incorrect checksum starting eight bytes late and including padding.
			binary.BigEndian.PutUint16(buf[len(buf)-2:], ^tun.Checksum(buf[56:], sum))
			return buf
		}
		plain := append(bytes.Clone(base[:40]), base[48:]...)
		plain[6] = uint8(proto)
		header.IPv6(plain).SetPayloadLength(uint16(transportLen))
		atomic := fragment(0, transportLen, false)
		for _, test := range []testCase{
			{"plain", plain, true, true},
			{"plain invalid checksum", corrupt(plain), false, false},
			{"first fragment", fragment(0, 64, true), true, false},
			{"middle fragment", fragment(64, 96, true), true, false},
			{"last fragment", fragment(96, transportLen, false), true, false},
			{"atomic fragment", atomic, true, true},
			{"atomic invalid checksum", corrupt(atomic), false, false},
			{"atomic with padding", padded(atomic), true, true},
			{"atomic invalid checksum with compensating padding", padded(corrupt(atomic)), false, false},
			{"options with padding", padded(base), true, true},
			{"options invalid checksum with compensating padding", padded(corrupt(base)), false, false},
		} {
			test.name = proto.String() + "6 " + test.name
			tests = append(tests, test)
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packet.Parsed{}
			p.Decode(tt.input)
			got := RXChecksumOffload(p)
			if tt.wantPB != (got != nil) {
				t.Fatalf("wantPB = %v != (got != nil): %v", tt.wantPB, got != nil)
			}
			if tt.wantPB {
				defer got.DecRef()
				if got.RXChecksumValidated != tt.wantValidated {
					t.Errorf("RXChecksumValidated = %v, want %v", got.RXChecksumValidated, tt.wantValidated)
				}
				gotBuf := got.ToBuffer()
				defer gotBuf.Release()
				want := tt.input
				if p.IPVersion == 6 {
					want = want[:header.IPv6MinimumSize+int(header.IPv6(want).PayloadLength())]
				}
				if !bytes.Equal(want, gotBuf.Flatten()) {
					t.Fatal("output packet unequal to input")
				}
			}
		})
	}
}
