//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	encoderSrcMAC = net.HardwareAddr{2, 3, 4, 5, 6, 7}
	encoderDstMAC = net.HardwareAddr{8, 9, 10, 11, 12, 13}
	encoderSrcIP  = net.IPv4(192, 0, 2, 19)
	encoderDstIP  = net.IPv4(198, 51, 100, 29)
)

// encoderOracle preserves the previous production serializer as an independent
// byte-for-byte oracle, including transport pseudoheader protocol and padding.
func encoderOracle(buffer gopacket.SerializeBuffer, payload []byte, proto uint8, tcp bool, tcpFlags uint8,
	srcPort, dstPort, id, ipFlags, fragOffset uint16, transport bool) error {
	eth := &layers.Ethernet{SrcMAC: encoderSrcMAC, DstMAC: encoderDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocol(proto), SrcIP: encoderSrcIP, DstIP: encoderDstIP,
		Id: id, Flags: layers.IPv4Flag(ipFlags >> 13), FragOffset: fragOffset}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if !transport {
		return gopacket.SerializeLayers(buffer, opts, eth, ip, gopacket.Payload(payload))
	}
	if tcp {
		header := newFakeTCPHeader(dstPort, tcpFlags)
		header.SrcPort = layers.TCPPort(srcPort)
		if err := header.SetNetworkLayerForChecksum(ip); err != nil {
			return err
		}
		return gopacket.SerializeLayers(buffer, opts, eth, ip, header, gopacket.Payload(payload))
	}
	header := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := header.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}
	return gopacket.SerializeLayers(buffer, opts, eth, ip, header, gopacket.Payload(payload))
}

func TestTunnelEncoderMatchesSerializer(t *testing.T) {
	oracle := gopacket.NewSerializeBufferExpectedSize(64, 1500)
	dst := make([]byte, 1600)
	for _, proto := range []uint8{200, 6, 17} {
		for _, tcp := range []bool{false, true} {
			for _, flags := range []uint8{0, 0x18, 0x02, 0xff} {
				e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, proto, tcp, flags)
				if err != nil {
					t.Fatal(err)
				}
				for _, size := range []int{0, 1, 2, 7, 8, 9, 63, 64, 511, 512, 1399, 1400} {
					payload := make([]byte, size)
					for i := range payload {
						payload[i] = byte(i*17 + size)
					}
					for _, transport := range []bool{true, false} {
						for _, fragment := range []struct{ flags, offset uint16 }{{0x4000, 0}, {0x2000, 0}, {0, 0x1fff}} {
							got, err := e.Encode(dst[:0], payload, 54321, 12345, 65000, fragment.flags, fragment.offset, transport)
							if err != nil {
								t.Fatal(err)
							}
							if err := encoderOracle(oracle, payload, proto, tcp, flags, 54321, 12345, 65000, fragment.flags, fragment.offset, transport); err != nil {
								t.Fatal(err)
							}
							if !bytes.Equal(got, oracle.Bytes()) {
								t.Fatalf("proto=%d tcp=%t flags=%#x size=%d L4=%t fragment=%+v\ngot %x\nwant%x", proto, tcp, flags, size, transport, fragment, got, oracle.Bytes())
							}
							if encoderFoldChecksum(encoderChecksumSum(got[14:34], 0)) != 0 {
								t.Fatal("invalid IPv4 checksum")
							}
							if transport {
								ipLen := int(binary.BigEndian.Uint16(got[16:18]))
								pseudo := uint32(17)
								if tcp {
									pseudo = 6
								}
								pseudo += uint32(ipLen - 20)
								pseudo = encoderChecksumSum(got[26:34], pseudo)
								if encoderFoldChecksum(encoderChecksumSum(got[34:14+ipLen], pseudo)) != 0 {
									t.Fatal("invalid transport checksum")
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestTunnelEncoderFakeFragmentPair(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 200, tcp, 0x18)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{0, 1, 1399, 1400} {
			payload := padData(bytes.Repeat([]byte{0xa5}, size), 8, e.transportLen)
			dst := make([]byte, 1600)
			first, err := e.Encode(dst, payload, 65001, 8080, 123, 0x2000, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			pkt, ok := parseEthIPv4(first)
			if !ok {
				t.Fatal("invalid first fake fragment")
			}
			_, _, padded, ok := parseFakeTransport(pkt.payload, tcp)
			if !ok || !bytes.Equal(unpadData(padded), bytes.Repeat([]byte{0xa5}, size)) {
				t.Fatal("fake fragment payload mismatch")
			}
			offset := uint16((e.transportLen + len(payload)) / 8)
			last, err := e.Encode(dst, []byte("0"), 0, 0, 123, 0, offset, false)
			if err != nil {
				t.Fatal(err)
			}
			pkt, ok = parseEthIPv4(last)
			if !ok || pkt.fragOffset != offset || !bytes.Equal(pkt.payload, []byte("0")) || binary.BigEndian.Uint16(last[18:20]) != 123 {
				t.Fatal("invalid final fake fragment")
			}
		}
	}
}

func TestTunnelEncoderValidationAndReuse(t *testing.T) {
	for _, test := range []struct {
		srcMAC, dstMAC net.HardwareAddr
		srcIP, dstIP   net.IP
	}{
		{nil, encoderDstMAC, encoderSrcIP, encoderDstIP},
		{encoderSrcMAC, nil, encoderSrcIP, encoderDstIP},
		{encoderSrcMAC, encoderDstMAC, nil, encoderDstIP},
		{encoderSrcMAC, encoderDstMAC, encoderSrcIP, net.ParseIP("2001:db8::1")},
	} {
		if _, err := newTunnelEncoder(test.srcMAC, test.dstMAC, test.srcIP, test.dstIP, 200, false, 0); !errors.Is(err, errEncoderAddress) {
			t.Fatalf("invalid addresses: %v", err)
		}
	}
	e, _ := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 200, false, 0)
	storage := bytes.Repeat([]byte{0xa5}, 65549)
	if _, err := e.Encode(storage[:59:59], nil, 0, 0, 0, 0, 0, true); !errors.Is(err, errEncoderBuffer) {
		t.Fatalf("short output: %v", err)
	}
	for _, transport := range []bool{false, true} {
		limit := 65515
		if transport {
			limit -= e.transportLen
		}
		if _, err := e.Encode(storage, make([]byte, limit), 0, 65535, 65535, 0, 0, transport); err != nil {
			t.Fatalf("maximum IPv4 length: %v", err)
		}
		if _, err := e.Encode(storage, make([]byte, limit+1), 0, 0, 0, 0, 0, transport); !errors.Is(err, errEncoderPacket) {
			t.Fatalf("oversize: %v", err)
		}
	}
	if _, err := e.Encode(storage, nil, 0, 0, 0, 1, 0, true); !errors.Is(err, errEncoderPacket) {
		t.Fatalf("invalid flags: %v", err)
	}
	if _, err := e.Encode(storage, nil, 0, 0, 0, 0, 8192, true); !errors.Is(err, errEncoderPacket) {
		t.Fatalf("invalid offset: %v", err)
	}
	if _, err := e.Encode(storage, bytes.Repeat([]byte{0xa5}, 1400), 123, 456, 1, 0x4000, 0, true); err != nil {
		t.Fatal(err)
	}
	frame, err := e.Encode(storage[:0], nil, 0, 65535, 2, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[42:], make([]byte, 18)) {
		t.Fatal("reused output leaked packet bytes into Ethernet padding")
	}
	payload := []byte{1, 2, 3, 4, 5}
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := e.Encode(storage[:0], payload, 123, 456, 2, 0x4000, 0, true); err != nil {
			panic(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("Encode allocated %g objects per packet", allocs)
	}
}

func TestTunnelEncoderUDPZeroChecksum(t *testing.T) {
	e, _ := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 200, false, 0)
	// Choose the only payload word that makes the computed checksum zero.
	sum := e.l4Sum + 1234 + 8080 + 10 + 10
	word := encoderFoldChecksum(sum)
	payload := []byte{byte(word >> 8), byte(word)}
	frame, err := e.Encode(make([]byte, 60), payload, 1234, 8080, 0, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(frame[40:42]) != 0xffff {
		t.Fatal("computed zero UDP checksum was not transmitted as 0xffff")
	}
}

// Both benchmarks reuse equivalent production buffers and headers. Run with
// -bench BenchmarkTunnelEncoding -benchmem -cpuprofile encoder.cpu to profile
// serialization without changing product behavior or enabling an HTTP server.
func BenchmarkTunnelEncoding(b *testing.B) {
	for _, size := range []int{64, 512, 1400} {
		for _, tcp := range []bool{false, true} {
			for _, direct := range []bool{false, true} {
				name := fmt.Sprintf("size=%d/tcp=%t/direct=%t", size, tcp, direct)
				b.Run(name, func(b *testing.B) {
					payload := bytes.Repeat([]byte{0xa5}, size)
					dst := make([]byte, 1600)
					e, _ := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 200, tcp, 0x18)
					eth := &layers.Ethernet{SrcMAC: encoderSrcMAC, DstMAC: encoderDstMAC, EthernetType: layers.EthernetTypeIPv4}
					ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: 200, SrcIP: encoderSrcIP, DstIP: encoderDstIP, Flags: layers.IPv4DontFragment}
					var header gopacket.SerializableLayer
					if tcp {
						t := newFakeTCPHeader(8080, 0x18)
						t.SrcPort = 1234
						_ = t.SetNetworkLayerForChecksum(ip)
						header = t
					} else {
						u := &layers.UDP{SrcPort: 1234, DstPort: 8080}
						_ = u.SetNetworkLayerForChecksum(ip)
						header = u
					}
					buffer := gopacket.NewSerializeBufferExpectedSize(64, 1500)
					opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if direct {
							if _, err := e.Encode(dst[:0], payload, 1234, 8080, uint16(i), 0x4000, 0, true); err != nil {
								b.Fatal(err)
							}
						} else {
							ip.Id = uint16(i)
							if err := gopacket.SerializeLayers(buffer, opts, eth, ip, header, gopacket.Payload(payload)); err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		}
	}
}
