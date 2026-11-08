//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestLocalUDPReaderDatagramBoundaries(t *testing.T) {
	for _, gro := range []bool{false, true} {
		t.Run(fmt.Sprintf("gro-%t", gro), func(t *testing.T) {
			rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
			r, err := newLocalUDPReader(rx, 1400, gro)
			if err != nil {
				t.Fatal(err)
			}
			writer := newLocalUDPWriter()
			var want []localUDPMessage
			for i, size := range []int{0, 1200, 1200, 1200, 37, 1400, 1400, 0, 1, 1, 100, 200} {
				want = append(want, localUDPMessage{bytes.Repeat([]byte{byte(i + 1)}, size), tx, rx.LocalAddr().(*net.UDPAddr).AddrPort()})
			}
			if n, err := writer.WriteBatch(want); n != len(want) || err != nil {
				t.Fatalf("send = %d, %v", n, err)
			}
			var got [2]localUDPDatagram // Split GRO records across calls.
			index := 0
			for index < len(want) {
				n, err := r.ReadBatch(got[:])
				if err != nil || n == 0 {
					t.Fatalf("read = %d, %v", n, err)
				}
				for _, msg := range got[:n] {
					if index >= len(want) || !bytes.Equal(msg.payload, want[index].payload) || msg.addr != tx.LocalAddr().(*net.UDPAddr).AddrPort() || cap(msg.payload) != len(msg.payload) {
						t.Fatalf("datagram %d: length=%d cap=%d addr=%v", index, len(msg.payload), cap(msg.payload), msg.addr)
					}
					// An append must not overwrite a pending adjacent GRO segment.
					_ = append(msg.payload, 0xee)
					index++
				}
			}
		})
	}
}

func TestLocalUDPReaderActualGRO(t *testing.T) {
	rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
	r, err := newLocalUDPReader(rx, 1400, true)
	if err != nil {
		t.Fatal(err)
	}
	if !r.gro {
		t.Skip("kernel UDP_GRO unavailable")
	}
	writer := newLocalUDPWriter()
	var msgs []localUDPMessage
	for i := 0; i < 33; i++ {
		size := 1200
		if i == 32 {
			size = 37
		}
		msgs = append(msgs, localUDPMessage{bytes.Repeat([]byte{byte(i + 1)}, size), tx, rx.LocalAddr().(*net.UDPAddr).AddrPort()})
	}
	socket, err := writer.socket(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !socket.gso {
		t.Skip("kernel UDP_SEGMENT unavailable")
	}
	if err := writer.sendGSO(socket, msgs); err != nil {
		if localGSOUnsupported(err) {
			t.Skipf("UDP_SEGMENT unsupported: %v", err)
		}
		t.Fatal(err)
	}
	var got [batchSize]localUDPDatagram
	index, aggregated := 0, false
	for index < len(msgs) {
		n, err := r.ReadBatch(got[:])
		if err != nil {
			t.Fatal(err)
		}
		for i := range r.messages[:r.count] {
			if r.messages[i].length > 1400 {
				aggregated = true
			}
		}
		for _, msg := range got[:n] {
			if index >= len(msgs) || !bytes.Equal(msg.payload, msgs[index].payload) || cap(msg.payload) != len(msg.payload) {
				t.Fatalf("GRO datagram %d changed", index)
			}
			index++
		}
	}
	if !aggregated {
		t.Fatal("UDP_GRO enabled but no aggregated record received from loopback GSO")
	}
}

func TestLocalUDPReaderOversize(t *testing.T) {
	for _, gro := range []bool{false, true} {
		t.Run(fmt.Sprintf("gro-%t", gro), func(t *testing.T) {
			rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
			r, err := newLocalUDPReader(rx, 1200, gro)
			if err != nil {
				t.Fatal(err)
			}
			writer := newLocalUDPWriter()
			addr := rx.LocalAddr().(*net.UDPAddr).AddrPort()
			socket, err := writer.socket(tx)
			if err != nil {
				t.Fatal(err)
			}
			// Oversized standalone and GRO records must not leak prefixes or
			// a valid-looking final short segment into the tunnel.
			msgs := []localUDPMessage{{make([]byte, 4096), tx, addr}, {make([]byte, 1400), tx, addr}, {make([]byte, 1400), tx, addr}, {make([]byte, 37), tx, addr}}
			if gro && r.gro {
				if n, err := writer.WriteBatch(msgs); n != len(msgs) || err != nil {
					t.Fatalf("oversize send: %d %v", n, err)
				}
				if !socket.gso {
					t.Skip("kernel GSO unavailable; standalone limit tested separately")
				}
			} else {
				// Without GRO, a short datagram is independently valid.
				socket.gso = false
				if n, err := writer.WriteBatch(msgs[:3]); n != 3 || err != nil {
					t.Fatalf("oversize send: %d %v", n, err)
				}
			}
			if n, err := writer.WriteBatch([]localUDPMessage{{[]byte("valid"), tx, addr}}); n != 1 || err != nil {
				t.Fatalf("valid send: %d %v", n, err)
			}
			var got [batchSize]localUDPDatagram
			n, err := r.ReadBatch(got[:])
			if n != 1 || err != nil || !bytes.Equal(got[0].payload, []byte("valid")) {
				t.Fatalf("oversize leaked data: n=%d err=%v payload=%x", n, err, got[0].payload)
			}
		})
	}
}

func TestLocalUDPReaderDeadlineAndClose(t *testing.T) {
	rx := localUDPListener(t, "udp4")
	r, err := newLocalUDPReader(rx, 1400, false)
	if err != nil {
		t.Fatal(err)
	}
	var got [1]localUDPDatagram
	if n, err := r.ReadBatch(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	if err := rx.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := r.ReadBatch(got[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %d %v", n, err)
	}
	if err := rx.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := r.ReadBatch(got[:])
		done <- err
	}()
	if err := rx.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake the reader")
	}
}

func TestLocalUDPGROFallback(t *testing.T) {
	rx := localUDPListener(t, "udp4")
	raw, err := rx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for _, optionErr := range []error{nil, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EINVAL, unix.EPERM, unix.EBADF} {
		got, err := configureLocalUDPGRO(raw, true, func(_, _, _, value int) error {
			if value != 1 {
				t.Fatal("GRO was not enabled")
			}
			return optionErr
		})
		fallback := optionErr == unix.ENOPROTOOPT || optionErr == unix.EOPNOTSUPP || optionErr == unix.EINVAL
		if got != (optionErr == nil) || (err == nil) != (optionErr == nil || fallback) {
			t.Fatalf("option %v: gro=%t err=%v", optionErr, got, err)
		}
	}
}

func testGROControl(size uint32) []byte {
	b := make([]byte, unix.CmsgSpace(4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.IPPROTO_UDP, unix.UDP_GRO
	h.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(b[unix.CmsgLen(0):], size)
	return b
}

func TestLocalUDPReaderMalformedRecords(t *testing.T) {
	rx := localUDPListener(t, "udp4")
	r, err := newLocalUDPReader(rx, 1200, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		flags   int32
		length  uint32
		control []byte
	}{
		{"truncated", unix.MSG_TRUNC, 100, nil},
		{"control-truncated", unix.MSG_CTRUNC, 100, nil},
		{"invalid-control", 0, 100, []byte{1}},
		{"zero-segment", 0, 100, testGROControl(0)},
		{"oversize-segment", 0, 1437, testGROControl(1400)},
		{"short-record", 0, 100, testGROControl(1200)},
		{"duplicate-gro", 0, 100, append(testGROControl(50), testGROControl(50)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.messages[0].length = tc.length
			hdr := &r.messages[0].header
			hdr.Flags, hdr.Namelen = tc.flags, unix.SizeofSockaddrInet4
			hdr.SetControllen(len(tc.control))
			copy(r.controls[0][:], tc.control)
			r.addresses[0].Family = unix.AF_INET
			if r.loadRecord() {
				t.Fatal("malformed record accepted")
			}
		})
	}
	if n, ok := localUDPGROSize(testGROControl(1200)); !ok || n != 1200 {
		t.Fatalf("valid GRO control: %d %t", n, ok)
	}
}

func TestLocalUDPReaderNoSteadyStateAllocations(t *testing.T) {
	rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
	r, err := newLocalUDPReader(rx, 1400, false)
	if err != nil {
		t.Fatal(err)
	}
	addr := rx.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte("payload")
	var got [1]localUDPDatagram
	if allocations := testing.AllocsPerRun(100, func() {
		if _, err := tx.WriteToUDPAddrPort(payload, addr); err != nil {
			panic(err)
		}
		if n, err := r.ReadBatch(got[:]); n != 1 || err != nil {
			panic(fmt.Sprintf("read: %d %v", n, err))
		}
	}); allocations != 0 {
		t.Fatalf("steady-state UDP read allocated %g objects", allocations)
	}
}
