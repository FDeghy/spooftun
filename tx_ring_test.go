//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestTXRingLayout(t *testing.T) {
	if txRingHeaderSize != 32 || unsafe.Offsetof(unix.Tpacket2Hdr{}.Status) != 0 {
		t.Fatal("unexpected TPACKET_V2 ABI")
	}
	for _, page := range []int{4096, 65536} {
		for _, mtu := range []int{68, 1500, 9000, 65535} {
			frame, block, blocks, err := txRingLayout(mtu, page)
			if err != nil {
				t.Fatal(err)
			}
			if frame < txRingHeaderSize+mtu+14 || frame%unix.TPACKET_ALIGNMENT != 0 || block%page != 0 || block%frame != 0 || blocks < 1 {
				t.Fatalf("invalid geometry mtu=%d page=%d: %d %d %d", mtu, page, frame, block, blocks)
			}
		}
	}
	for _, mtu := range []int{-1, 0, 67, 65536} {
		if _, _, _, err := txRingLayout(mtu, 4096); err == nil {
			t.Fatalf("accepted MTU %d", mtu)
		}
	}
}

func TestTXRingValidationAndClose(t *testing.T) {
	s := &txRingSender{fd: -1, maxFrame: 1514}
	for _, packets := range [][][]byte{{nil}, {make([]byte, 13)}, {make([]byte, 1515)}, {make([]byte, 64), make([]byte, 1515)}} {
		if n, err := s.WriteBatch(packets); n != 0 || err == nil {
			t.Fatalf("invalid batch accepted: %d %v", n, err)
		}
	}
	if n, err := s.WriteBatch(nil); n != 0 || err != nil {
		t.Fatalf("empty batch: %d %v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := s.WriteBatch([][]byte{make([]byte, 64)}); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed sender: %d %v", n, err)
	}
}

func TestTXRingWrongFormatRecovery(t *testing.T) {
	s := &txRingSender{fd: -1, ring: make([]byte, 2048), frameSize: 2048, frameCount: 1}
	h := s.header(0)
	atomic.StoreUint32(&h.Status, unix.TP_STATUS_WRONG_FORMAT)
	if err := s.waitAvailable(h); err == nil {
		t.Fatal("missing format error")
	}
	if atomic.LoadUint32(&h.Status) != unix.TP_STATUS_AVAILABLE {
		t.Fatal("bad frame not released")
	}
	if err := s.waitAvailable(h); err != nil {
		t.Fatal(err)
	}
	s.closing.Store(true)
	if err := s.waitAvailable(h); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestTXRingSubmissionFailure(t *testing.T) {
	s := &txRingSender{fd: -1, ring: make([]byte, 2048), frameSize: 2048, frameCount: 1, maxFrame: 1514}
	packet := bytes.Repeat([]byte{0x5a}, 64)
	n, err := s.WriteBatch([][]byte{packet})
	if n != 1 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("queued count/error: %d %v", n, err)
	}
	if s.header(0).Len != uint32(len(packet)) || !bytes.Equal(s.ring[txRingHeaderSize:txRingHeaderSize+len(packet)], packet) {
		t.Fatal("incorrect TX ring metadata or payload offset")
	}
	if n, err := s.WriteBatch([][]byte{packet}); n != 0 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("broken sender must reject future submissions: %d %v", n, err)
	}
}

// Opt-in test on an isolated, pre-created veth pair in the same namespace:
// ip link add sttx0 type veth peer name sttx1
// ip link set sttx0 up; ip link set sttx1 up
// SPOOFTUN_TX_TEST_IFACE=sttx0 SPOOFTUN_TX_TEST_PEER=sttx1 go test -run TestTXRingKernel
// Never point this test at a production interface; it transmits test EtherType 0x88b5.
func TestTXRingKernel(t *testing.T) {
	ifaceName, peerName := os.Getenv("SPOOFTUN_TX_TEST_IFACE"), os.Getenv("SPOOFTUN_TX_TEST_PEER")
	if ifaceName == "" || peerName == "" {
		t.Skip("requires explicitly selected isolated veth interfaces and CAP_NET_RAW")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	// Socket protocol is network byte order even on little-endian hosts.
	var protocol [2]byte
	binary.BigEndian.PutUint16(protocol[:], 0x88b5)
	proto := int(*(*uint16)(unsafe.Pointer(&protocol[0])))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: uint16(proto)}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20); err != nil {
		t.Fatal(err)
	}
	s, err := newTXRingSender(ifaceName, iface.MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for start := 0; start < s.frameCount+64; start += 16 {
		packets := make([][]byte, 16)
		for i := range packets {
			frame := make([]byte, 256)
			copy(frame, peer.HardwareAddr)
			copy(frame[6:], iface.HardwareAddr)
			binary.BigEndian.PutUint16(frame[12:], 0x88b5)
			binary.BigEndian.PutUint32(frame[14:], uint32(start+i))
			packets[i] = frame
		}
		if n, err := s.WriteBatch(packets); n != len(packets) || err != nil {
			t.Fatalf("batch %d: %d %v", start, n, err)
		}
		for i, expected := range packets {
			deadline := time.Now().Add(2 * time.Second)
			var buf [2048]byte
			for {
				n, _, err := unix.Recvfrom(fd, buf[:], 0)
				if err == unix.EINTR {
					continue
				}
				if err == unix.EAGAIN {
					if time.Now().After(deadline) {
						t.Fatalf("timeout receiving frame %d", start+i)
					}
					fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					unix.Poll(fds, 100)
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], expected) {
					t.Fatalf("frame %d differs: len=%d", start+i, n)
				}
				break
			}
		}
	}
}

// BenchmarkTXBackends uses actual AF_PACKET sockets, never AF_UNIX stand-ins.
// Select an isolated veth with SPOOFTUN_TX_BENCH_IFACE. This measures submission
// cost only; use the namespace end-to-end benchmark for delivered throughput.
func BenchmarkTXBackends(b *testing.B) {
	ifaceName := os.Getenv("SPOOFTUN_TX_BENCH_IFACE")
	if ifaceName == "" {
		b.Skip("set SPOOFTUN_TX_BENCH_IFACE to an isolated veth")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{64, 512, 1400} {
		for _, mode := range []string{"sendmmsg", "ring"} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				var sender interface {
					WriteBatch([][]byte) (int, error)
					Close() error
				}
				var err error
				if mode == "ring" {
					sender, err = newTXRingSender(ifaceName, iface.MTU)
				} else {
					sender, err = newPacketSender(ifaceName)
				}
				if err != nil {
					b.Fatal(err)
				}
				defer sender.Close()
				packets := make([][]byte, 64)
				for i := range packets {
					packets[i] = make([]byte, size)
					copy(packets[i], []byte{2, 0, 0, 0, 0, 1})
					copy(packets[i][6:], iface.HardwareAddr)
					binary.BigEndian.PutUint16(packets[i][12:], 0x88b5)
				}
				b.SetBytes(int64(size * len(packets)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if n, err := sender.WriteBatch(packets); n != len(packets) || err != nil {
						b.Fatalf("%d %v", n, err)
					}
				}
			})
		}
	}
}
