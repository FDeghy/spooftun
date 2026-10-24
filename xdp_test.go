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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func fakeXDPRing(stride int) xdpRing {
	m := make([]byte, 64+xdpRingSize*stride)
	return xdpRing{m, (*uint32)(unsafe.Pointer(&m[0])), (*uint32)(unsafe.Pointer(&m[4])), (*uint32)(unsafe.Pointer(&m[8])), unsafe.Pointer(&m[64])}
}

func TestXDPRingWrapAndCompletionOwnership(t *testing.T) {
	r := fakeXDPRing(8)
	*r.address(xdpRingSize + 7) = 123
	if *r.address(7) != 123 {
		t.Fatal("ring did not wrap")
	}
	q := &xdpQueue{umem: make([]byte, 2*xdpRingSize*xdpFrameSize), completion: fakeXDPRing(8)}
	*q.completion.address(0) = xdpRingSize * xdpFrameSize
	atomic.StoreUint32(q.completion.producer, 1)
	if err := q.reap(); err != nil {
		t.Fatal(err)
	}
	if len(q.freeTX) != 1 || *q.completion.consumer != 1 {
		t.Fatal("completion not reclaimed")
	}
	if err := q.reap(); err != nil || len(q.freeTX) != 1 {
		t.Fatal("completion reclaimed twice")
	}
	*q.completion.address(1) = 0
	atomic.StoreUint32(q.completion.producer, 2)
	if q.reap() == nil {
		t.Fatal("RX frame incorrectly returned to TX allocator")
	}
}

func TestXDPRXSliceLifetimeAndQueueCoverage(t *testing.T) {
	q0 := &xdpQueue{rx: fakeXDPRing(16), fill: fakeXDPRing(8), umem: make([]byte, 2*xdpRingSize*xdpFrameSize)}
	q1 := &xdpQueue{rx: fakeXDPRing(16), fill: fakeXDPRing(8), umem: make([]byte, 2*xdpRingSize*xdpFrameSize)}
	for i, q := range []*xdpQueue{q0, q1} {
		q.umem[256] = byte(41 + i)
		*q.rx.packet(0) = unix.XDPDesc{Addr: 256, Len: 1}
		*q.rx.producer = 1
	}
	x := &xdpIO{queues: []*xdpQueue{q0, q1}}
	a, err := x.ReadPacket()
	if err != nil || a[0] != 41 {
		t.Fatalf("first queue: %v %v", a, err)
	}
	if *q0.fill.producer != 0 {
		t.Fatal("frame recycled before next ReadPacket")
	}
	b, err := x.ReadPacket()
	if err != nil || b[0] != 42 {
		t.Fatalf("second queue: %v %v", b, err)
	}
	if *q0.fill.producer != 1 || *q0.fill.address(0) != 0 {
		t.Fatal("held RX frame not recycled by base address")
	}
}

// xsk_flush publishes RX before releasing the FILL consumer. Model that
// ordering explicitly instead of relying on the scheduler to hit the race.
func TestXDPRXWaitsForFillConsumer(t *testing.T) {
	for _, p := range []uint32{xdpRingSize, ^uint32(0)} {
		t.Run(fmt.Sprintf("producer-%d", p), func(t *testing.T) {
			wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(wake)
			q := &xdpQueue{rx: fakeXDPRing(16), fill: fakeXDPRing(8), umem: make([]byte, 2*xdpFrameSize)}
			*q.fill.producer, *q.fill.consumer = p, p-xdpRingSize
			*q.fill.address(p) = 12345
			for i := uint32(0); i < 2; i++ {
				addr := i*xdpFrameSize + 256
				q.umem[addr] = byte(41 + i)
				*q.rx.packet(i) = unix.XDPDesc{Addr: uint64(addr), Len: 1}
			}
			*q.rx.producer = 2
			x := &xdpIO{wake: wake, queues: []*xdpQueue{q}}
			a, err := x.ReadPacket()
			if err != nil || len(a) != 1 || a[0] != 41 {
				t.Fatalf("first RX: %v %v", a, err)
			}
			done := make(chan error, 1)
			go func() {
				b, err := x.ReadPacket()
				if err == nil && (len(b) != 1 || b[0] != 42) {
					err = fmt.Errorf("second RX: %v", b)
				}
				done <- err
			}()
			// Release even on failure so the test never leaks a blocked reader.
			defer func() { atomic.StoreUint32(q.fill.consumer, p-xdpRingSize+1) }()
			select {
			case err := <-done:
				t.Fatalf("reader did not wait for FILL release: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if atomic.LoadUint32(q.fill.producer) != p {
				t.Fatal("published into a full FILL ring")
			}
			atomic.StoreUint32(q.fill.consumer, p-xdpRingSize+1)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("reader did not resume after FILL release")
			}
			if *q.fill.producer != p+1 || *q.fill.address(p) != 0 || x.heldAddrs[0] != xdpFrameSize || x.heldCount != 1 {
				t.Fatal("RX frame was lost, duplicated, or recycled with the wrong address")
			}
		})
	}
}

func TestXDPCloseInterruptsFillWait(t *testing.T) {
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	q := &xdpQueue{fill: fakeXDPRing(8)}
	*q.fill.producer = xdpRingSize
	// No mapped queues: Close must still wake a reader returning its held frame.
	x := &xdpIO{wake: wake, held: q, heldCount: batchSize}
	defer x.Close()
	done := make(chan error, 1)
	go func() { _, err := x.ReadPacket(); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("reader did not wait for FILL release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	closed := make(chan struct{})
	go func() { x.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt FILL wait")
	}
	if err := <-done; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadPacket after Close: %v", err)
	}
	if *q.fill.producer != xdpRingSize {
		t.Fatal("Close published a frame into a full ring")
	}
}

func TestXDPInvalidBatchDoesNotPublishOrConsumeFrames(t *testing.T) {
	q := &xdpQueue{tx: fakeXDPRing(16), freeTX: []uint64{4096}}
	x := &xdpIO{queues: []*xdpQueue{q}}
	n, err := x.WriteBatch([][]byte{{1}, make([]byte, xdpFrameSize+1)})
	if !errors.Is(err, unix.EMSGSIZE) || n != 0 || len(q.freeTX) != 1 || *q.tx.producer != 0 {
		t.Fatalf("invalid batch changed ownership: %d %v", n, err)
	}
}

func TestXDPFallbackOnlyForUnsupportedBindOrAttach(t *testing.T) {
	for _, e := range []error{unix.EINVAL, unix.EPERM, unix.ENOMEM, &xdpModeError{unix.EPERM}, &xdpModeError{unix.EBUSY}} {
		if xdpUnsupported(e) {
			t.Fatalf("unexpected fallback for %v", e)
		}
	}
	if !xdpUnsupported(&xdpModeError{unix.EOPNOTSUPP}) {
		t.Fatal("unsupported bind must fall back")
	}
}

func TestXDPInstructionsAssemble(t *testing.T) {
	mac := net.HardwareAddr{0xfe, 0x11, 0x22, 0x33, 0x44, 0x55}
	for _, proto := range []uint8{6, 17, 200} {
		for _, client := range []bool{false, true} {
			i := xdpInstructions(0, proto, mac, net.IPv4(192, 0, 2, 1), 8080, client)
			for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
				var out bytes.Buffer
				if err := i.Marshal(&out, order); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// Kernel verifier/test-run checks the actual generated filter, with the
// redirect helper replaced by a sentinel return so no packet leaves the test.
func TestXDPKernelFilter(t *testing.T) {
	if os.Getenv("SPOOFTUN_XDP_TEST") != "1" {
		t.Skip("set SPOOFTUN_XDP_TEST=1 for privileged XDP verifier tests")
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	ip := net.IPv4(192, 0, 2, 2)
	for _, client := range []bool{false, true} {
		ins := xdpInstructions(0, 17, mac, ip, 9000, client)
		ins = append(ins[:len(ins)-7], asm.Mov.Imm(asm.R0, 4), asm.Return(), asm.Mov.Imm(asm.R0, 2).WithSymbol("pass"), asm.Return())
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: ins})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		frame := make([]byte, 14+24+8)
		copy(frame[6:12], []byte{2, 0, 0, 0, 0, 3})
		binary.BigEndian.PutUint16(frame[12:], 0x800)
		frame[14] = 0x46
		frame[23] = 17
		copy(frame[30:], ip.To4())
		binary.BigEndian.PutUint16(frame[38:], 9000)
		binary.BigEndian.PutUint16(frame[40:], 9000)
		cases := []struct {
			name   string
			mutate func([]byte)
			want   uint32
		}{
			{"match", func([]byte) {}, 4},
			{"other IP", func(f []byte) { f[33]++ }, 2},
			{"SSH", func(f []byte) { f[23] = 6; binary.BigEndian.PutUint16(f[40:], 22) }, 2},
			{"fragment", func(f []byte) { f[21] = 1 }, 2},
			{"own MAC", func(f []byte) { copy(f[6:12], mac) }, 2},
			{"wrong directional port", func(f []byte) {
				if client {
					f[39]++
				} else {
					f[41]++
				}
			}, 2},
		}
		for _, tc := range cases {
			f := bytes.Clone(frame)
			tc.mutate(f)
			ret, _, err := p.Test(f)
			if err != nil || ret != tc.want {
				t.Fatalf("client=%t %s: got %d want %d: %v", client, tc.name, ret, tc.want, err)
			}
		}
		for n := 14; n < 34; n++ {
			ret, _, err := p.Test(frame[:n])
			if err != nil || ret != 2 {
				t.Fatalf("truncated packet %d: %d %v", n, ret, err)
			}
		}
	}
}

// Use only an isolated veth supplied by the namespace harness. This ensures
// generic copy mode and orderly cleanup independently of NIC native support.
func TestXDPGenericCopyLifecycle(t *testing.T) {
	iface := os.Getenv("SPOOFTUN_XDP_TEST_IFACE")
	if iface == "" {
		t.Skip("set SPOOFTUN_XDP_TEST_IFACE to an isolated veth")
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := xdpQueueIDs(iface)
	if err != nil {
		t.Fatal(err)
	}
	x, err := openXDPIO(dev, ids, 200, dev.HardwareAddr, nil, 0, false, false, link.XDPGenericMode)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	for _, q := range x.queues {
		if q.zeroCopy {
			t.Fatal("generic mode reported zero-copy")
		}
	}
	if peer := os.Getenv("SPOOFTUN_XDP_TEST_PEER"); peer != "" {
		testXDPFrames(t, x, dev, peer)
	}
	// A second owner must fail rather than replace this attachment.
	_, err = openXDPIO(dev, ids, 200, dev.HardwareAddr, nil, 0, false, false, link.XDPGenericMode)
	if err == nil {
		t.Fatal("second XDP owner replaced existing program")
	}
	if err = x.Close(); err != nil {
		t.Fatal(err)
	}
	if err = x.Close(); err != nil {
		t.Fatal(err)
	}
	x, err = openXDPIO(dev, ids, 200, dev.HardwareAddr, nil, 0, false, false, link.XDPGenericMode)
	if err != nil {
		t.Fatalf("reopen after cleanup: %v", err)
	}
	x.Close()
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer pass.Close()
	owner, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: dev.Index, Flags: link.XDPGenericMode})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	_, _, err = newXDPIO(iface, 200, dev.HardwareAddr, nil, 0, false)
	if err == nil {
		t.Fatal("backend replaced unrelated existing XDP program")
	}
	info, err := owner.Info()
	if err != nil {
		t.Fatalf("existing XDP program disappeared: %v", err)
	}
	progInfo, err := pass.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := progInfo.ID()
	if !ok || info.Program != id {
		t.Fatal("existing XDP program changed")
	}
}

func TestXDPNativeCopyReceiveBursts(t *testing.T) {
	iface, peer := os.Getenv("SPOOFTUN_XDP_TEST_IFACE"), os.Getenv("SPOOFTUN_XDP_TEST_PEER")
	if iface == "" || peer == "" {
		t.Skip("set SPOOFTUN_XDP_TEST_IFACE and SPOOFTUN_XDP_TEST_PEER to isolated veth peers")
	}
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := xdpQueueIDs(iface)
	if err != nil {
		t.Fatal(err)
	}
	x, err := openXDPIO(dev, ids, 200, dev.HardwareAddr, nil, 0, false, false, link.XDPDriverMode)
	if xdpUnsupported(err) {
		t.Skipf("native-copy unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	testXDPFrames(t, x, dev, peer)
}

func testXDPFrames(t *testing.T, x *xdpIO, dev *net.Interface, peerName string) {
	t.Helper()
	peer, err := net.InterfaceByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(binary.NativeEndian.Uint16([]byte{8, 0})))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: peer.Index}); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 64)
	copy(frame[:6], dev.HardwareAddr)
	copy(frame[6:12], peer.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:], 0x800)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:], 50)
	frame[22] = 64
	frame[23] = 200
	copy(frame[26:], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	copy(frame[34:], "spooftun-xdp-rx-test")
	if _, err = unix.Write(fd, frame); err != nil {
		t.Fatal(err)
	}
	type result struct {
		frame []byte
		err   error
	}
	ch := make(chan result, 1)
	go func() { f, e := x.ReadPacket(); ch <- result{bytes.Clone(f), e} }()
	select {
	case got := <-ch:
		if got.err != nil || !bytes.Equal(got.frame, frame) {
			t.Fatalf("XDP RX got %x err=%v", got.frame, got.err)
		}
	case <-time.After(2 * time.Second):
		x.Close()
		t.Fatal("XDP RX timed out")
	}
	testXDPReceiveBursts(t, x, fd, frame)
	out := bytes.Clone(frame)
	copy(out[:6], peer.HardwareAddr)
	copy(out[6:12], dev.HardwareAddr)
	copy(out[34:], "spooftun-xdp-tx-test")
	if n, e := x.WriteBatch([][]byte{out}); n != 1 || e != nil {
		t.Fatalf("XDP TX: %d %v", n, e)
	}
	buf := make([]byte, 4096)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, err = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100)
		if err != nil && err != unix.EINTR {
			t.Fatal(err)
		}
		n, _, e := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if e == unix.EAGAIN {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Equal(buf[:n], out) {
			return
		}
	}
	t.Fatal("AF_XDP TX frame did not reach veth peer")
}

func testXDPReceiveBursts(t *testing.T, x *xdpIO, fd int, frame []byte) {
	t.Helper()
	const burst, rounds = 64, 128 // Reuse every RX frame across many ring wraps.
	want := bytes.Clone(frame)
	send := bytes.Clone(frame)
	done := make(chan error, 1)
	go func() {
		reader := newPacketReader(x)
		for round := 0; round < rounds; round++ {
			for i := 0; i < burst; i++ {
				got, err := reader.ReadPacket()
				if err != nil {
					done <- err
					return
				}
				binary.BigEndian.PutUint32(want[54:], uint32(round*burst+i))
				if !bytes.Equal(got, want) {
					done <- fmt.Errorf("RX burst %d packet %d: got %x, want %x", round, i, got, want)
					return
				}
			}
			done <- nil
		}
	}()
	complete := false
	defer func() {
		if !complete {
			x.Close() // Interrupt the reader if a send or comparison fails.
		}
	}()
	for round := 0; round < rounds; round++ {
		for i := 0; i < burst; i++ {
			binary.BigEndian.PutUint32(send[54:], uint32(round*burst+i))
			if _, err := unix.Write(fd, send); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("RX burst %d timed out", round)
		}
	}
	complete = true
	t.Logf("verified %d ordered RX frames across ring wraps", burst*rounds)
}
