//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLocalForwarderOwnsQueuedPayloads(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	receiver.SetReadBuffer(socketBufSize)
	receiver.SetReadDeadline(time.Now().Add(5 * time.Second))
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	f := newLocalUDPForwarder(1500)
	const count = 256
	done := make(chan error, 1)
	progress := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1500)
		for i := 0; i < count; i++ {
			n, _, err := receiver.ReadFromUDP(buf)
			if err != nil {
				done <- err
				return
			}
			want := bytes.Repeat([]byte{byte(i)}, (i%4)*400)
			if !bytes.Equal(buf[:n], want) {
				done <- fmt.Errorf("datagram %d changed: len=%d want=%d", i, n, len(want))
				return
			}
			if i%batchSize == batchSize-1 {
				progress <- struct{}{}
			}
		}
		done <- nil
	}()
	buf := make([]byte, 1500)
	for i := 0; i < count; i++ {
		n := (i % 4) * 400
		for j := range buf {
			buf[j] = byte(i)
		}
		if !f.Send(sender, netip.AddrPort{}, buf[:n]) {
			t.Fatal("valid payload rejected")
		}
		clear(buf) // Model the packet backend recycling the original frame.
		if i%batchSize == batchSize-1 {
			select {
			case <-progress:
			case err := <-done:
				t.Fatal(err)
			case <-time.After(5 * time.Second):
				t.Fatal("bounded receive window timed out")
			}
		}
	}
	if f.Send(sender, netip.AddrPort{}, make([]byte, 1501)) {
		t.Fatal("oversized payload accepted")
	}
	f.Close() // Drains sparse tails without requiring another incoming packet.
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLocalForwarderClosedSessionDoesNotDropNextSession(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	bad, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	bad.Close()
	good, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	f := newLocalUDPForwarder(1500)
	f.Send(bad, netip.AddrPort{}, []byte("expired"))
	f.Send(good, netip.AddrPort{}, []byte("live"))
	f.Close()
	var buf [64]byte
	n, _, err := receiver.ReadFromUDP(buf[:])
	if err != nil || string(buf[:n]) != "live" {
		t.Fatalf("live session: %q %v", buf[:n], err)
	}
}

// Unlike the offered-send microbenchmark, each iteration waits for all 16
// datagrams to be received and checks their sequence numbers and contents.
// This isolates the local boundary, not the external tunnel or WireGuard.
func BenchmarkLocalForwarderDelivered(b *testing.B) {
	for _, size := range []int{64, 512, 1400} {
		for _, pipeline := range []bool{false, true} {
			b.Run(fmt.Sprintf("size=%d/pipeline=%t", size, pipeline), func(b *testing.B) {
				rx := localUDPListener(b, "udp4")
				tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
				if err != nil {
					b.Fatal(err)
				}
				defer tx.Close()
				var f *localUDPForwarder
				if pipeline {
					f = newLocalUDPForwarder(size)
					defer f.Close()
				}
				payload := bytes.Repeat([]byte{0xa5}, size)
				suffix := bytes.Clone(payload[8:])
				progress := make(chan error, 1)
				drained := make(chan struct{})
				iterations := b.N
				go func() {
					defer close(drained)
					buf := make([]byte, size+1)
					for i := 0; i < iterations; i++ {
						for j := 0; j < batchSize; j++ {
							n, err := rx.Read(buf)
							if err != nil {
								progress <- err
								return
							}
							if n != size || binary.BigEndian.Uint64(buf[:8]) != uint64(i*batchSize+j) || !bytes.Equal(buf[8:n], suffix) {
								progress <- fmt.Errorf("delivered payload or sequence changed at %d/%d", i, j)
								return
							}
						}
						progress <- nil
					}
				}()
				b.SetBytes(int64(batchSize * size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for j := 0; j < batchSize; j++ {
						binary.BigEndian.PutUint64(payload[:8], uint64(i*batchSize+j))
						if pipeline {
							f.Send(tx, netip.AddrPort{}, payload)
						} else if _, err := tx.Write(payload); err != nil {
							b.Fatal(err)
						}
					}
					if err := <-progress; err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				<-drained
			})
		}
	}
}
