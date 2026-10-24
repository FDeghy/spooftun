//go:build linux

package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

type overwritingBatchReceiver struct {
	storage [8]byte
	calls   int
}

func (r *overwritingBatchReceiver) ReadPacket() ([]byte, error) {
	panic("batch receiver used as a single-packet source")
}
func (r *overwritingBatchReceiver) Close() error { return nil }
func (r *overwritingBatchReceiver) ReadPacketBatch(dst [][]byte) (int, error) {
	clear(r.storage[:]) // Model kernel reuse immediately after the next read.
	r.calls++
	if r.calls == 3 {
		return 0, os.ErrClosed
	}
	copy(r.storage[:], []byte{byte(r.calls), 2, 3, 4, 5, 6, 7, 8})
	dst[0], dst[1], dst[2] = r.storage[:4], r.storage[4:4], r.storage[4:]
	return 3, nil
}

func TestLocalUDPDeliveryFlushesBeforeRecycleAndReadError(t *testing.T) {
	rx := localUDPListener(t, "udp4")
	tx := localUDPListener(t, "udp4")
	checkAddr := rx.LocalAddr().(*net.UDPAddr).AddrPort()
	r := &overwritingBatchReceiver{}
	d := newLocalUDPDelivery(r, 1500)
	defer d.Close()
	for batch := 1; batch <= 2; batch++ {
		for i := 0; i < 3; i++ {
			packet, err := d.ReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			// A discarded last packet must not prevent flushing earlier ones.
			if i != 2 && !d.Send(tx, checkAddr, packet) {
				t.Fatal("valid datagram rejected")
			}
		}
	}
	if _, err := d.ReadPacket(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read error: %v", err)
	}
	if err := rx.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	for _, want := range [][]byte{{1, 2, 3, 4}, {}, {2, 2, 3, 4}, {}} {
		n, _, err := rx.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("delivered %x, want %x: %v", buf[:n], want, err)
		}
	}
}

func TestLocalUDPDeliveryCloseFlushesSparseTail(t *testing.T) {
	rx := localUDPListener(t, "udp4")
	tx := localUDPListener(t, "udp4")
	d := newLocalUDPDelivery(&overwritingBatchReceiver{}, 4)
	packet, err := d.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if d.Send(tx, netip.AddrPort{}, make([]byte, 5)) {
		t.Fatal("oversize datagram accepted")
	}
	d.Send(tx, rx.LocalAddr().(*net.UDPAddr).AddrPort(), packet)
	d.Close()
	if err := rx.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := rx.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte{1, 2, 3, 4}) {
		t.Fatalf("sparse tail: %x %v", buf[:n], err)
	}
}
