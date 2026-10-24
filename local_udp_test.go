//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func localUDPListener(t testing.TB, network string) *net.UDPConn {
	t.Helper()
	addr := "127.0.0.1:0"
	if network == "udp6" {
		addr = "[::1]:0"
	}
	raddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP(network, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func assertLocalUDP(t *testing.T, c *net.UDPConn, want []byte) {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("UDP received %x, %v; want %x", buf[:n], err, want)
	}
}

func TestLocalUDPBatchDatagramBoundaries(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, connected := range []bool{false, true} {
			for _, gso := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/connected-%t/gso-%t", network, connected, gso), func(t *testing.T) {
					rx := localUDPListener(t, network)
					var tx *net.UDPConn
					if connected {
						var err error
						tx, err = net.DialUDP(network, nil, rx.LocalAddr().(*net.UDPAddr))
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { tx.Close() })
					} else {
						tx = localUDPListener(t, network)
					}
					writer := newLocalUDPWriter()
					writer.gsoDisabled = !gso
					addr := rx.LocalAddr().(*net.UDPAddr).AddrPort()
					if connected {
						addr = netip.AddrPort{}
					}
					var msgs []localUDPMessage
					// Empty packets, equal-sized runs, a shorter final GSO
					// segment, and changes in segment size must all survive.
					for i, n := range []int{0, 1200, 1200, 1200, 37, 1400, 1400, 0, 1, 1, 100, 200} {
						msgs = append(msgs, localUDPMessage{bytes.Repeat([]byte{byte(i)}, n), tx, addr})
					}
					if n, err := writer.WriteBatch(msgs); n != len(msgs) || err != nil {
						t.Fatalf("WriteBatch = %d %v", n, err)
					}
					for _, msg := range msgs {
						assertLocalUDP(t, rx, msg.payload)
					}
					for _, iov := range writer.vectors {
						if iov.Base != nil {
							t.Fatal("writer retained a payload after sending")
						}
					}
				})
			}
		}
	}
}

func TestLocalUDPBatchMixedSocketsAndDestinations(t *testing.T) {
	rx0, rx1 := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
	tx0, tx1 := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
	writer := newLocalUDPWriter()
	var msgs []localUDPMessage
	want := [2][][]byte{}
	for i := 0; i < 131; i++ {
		tx, dest := tx0, i%2
		if i%5 == 0 {
			tx = tx1
		}
		addr := []*net.UDPConn{rx0, rx1}[dest].LocalAddr().(*net.UDPAddr).AddrPort()
		payload := []byte{byte(i), 2, 3}
		msgs = append(msgs, localUDPMessage{payload, tx, addr})
		want[dest] = append(want[dest], payload)
	}
	if n, err := writer.WriteBatch(msgs); n != len(msgs) || err != nil {
		t.Fatalf("WriteBatch = %d %v", n, err)
	}
	for dest, rx := range []*net.UDPConn{rx0, rx1} {
		for _, payload := range want[dest] {
			assertLocalUDP(t, rx, payload)
		}
	}
}

func TestLocalUDPActualGSOSegments(t *testing.T) {
	for _, sizes := range [][]int{{1200, 1200, 1200, 37}, {32753, 32753}, {1, 1}} {
		t.Run(fmt.Sprint(sizes), func(t *testing.T) {
			rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
			writer := newLocalUDPWriter()
			socket, err := writer.socket(tx)
			if err != nil {
				t.Fatal(err)
			}
			if !socket.gso {
				t.Skip("kernel UDP_SEGMENT unavailable")
			}
			var msgs []localUDPMessage
			for i, size := range sizes {
				msgs = append(msgs, localUDPMessage{bytes.Repeat([]byte{byte(i + 1)}, size), tx, rx.LocalAddr().(*net.UDPAddr).AddrPort()})
			}
			if n, err := writer.WriteBatch(msgs); n != len(msgs) || err != nil {
				t.Fatalf("GSO write = %d %v", n, err)
			}
			for _, msg := range msgs {
				assertLocalUDP(t, rx, msg.payload)
			}
			if writer.gsoDisabled {
				t.Log("UDP_SEGMENT probe succeeded but send was rejected; verified sendmmsg fallback")
			} else {
				t.Logf("verified %d actual UDP_SEGMENT datagrams", len(msgs))
			}
		})
	}
}

func TestLocalUDPGSOFallback(t *testing.T) {
	for _, fallbackErr := range []error{unix.EINVAL, unix.EIO, unix.ENOPROTOOPT, unix.EOPNOTSUPP} {
		t.Run(fallbackErr.Error(), func(t *testing.T) {
			rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
			writer := newLocalUDPWriter()
			socket, err := writer.socket(tx)
			if err != nil {
				t.Fatal(err)
			}
			// Force capability availability independently of the test kernel,
			// then inject failure before publishing anything to that kernel.
			socket.gso = true
			realWrite, attempts := writer.write, 0
			writer.write = func(fd uintptr) bool {
				if writer.writeGSO {
					attempts++
					writer.writeErr = fallbackErr
					return true
				}
				return realWrite(fd)
			}
			msgs := []localUDPMessage{
				{[]byte{1, 2, 3}, tx, rx.LocalAddr().(*net.UDPAddr).AddrPort()},
				{[]byte{4, 5, 6}, tx, rx.LocalAddr().(*net.UDPAddr).AddrPort()},
			}
			for repeat := 0; repeat < 2; repeat++ {
				if n, err := writer.WriteBatch(msgs); n != 2 || err != nil {
					t.Fatalf("fallback = %d %v", n, err)
				}
				for _, msg := range msgs {
					assertLocalUDP(t, rx, msg.payload)
				}
			}
			if attempts != 1 || !writer.gsoDisabled {
				t.Fatalf("GSO fallback not remembered: attempts=%d disabled=%t", attempts, writer.gsoDisabled)
			}
		})
	}
}

func TestLocalUDPPartialAndClosedSocket(t *testing.T) {
	rx, tx := localUDPListener(t, "udp4"), localUDPListener(t, "udp4")
	writer := newLocalUDPWriter()
	writer.gsoDisabled = true
	addr := rx.LocalAddr().(*net.UDPAddr).AddrPort()
	msgs := []localUDPMessage{{[]byte{1}, tx, addr}, {make([]byte, 65508), tx, addr}, {[]byte{3}, tx, addr}}
	if n, err := writer.WriteBatch(msgs); n != 1 || !errors.Is(err, unix.EMSGSIZE) {
		t.Fatalf("partial batch = %d %v", n, err)
	}
	assertLocalUDP(t, rx, []byte{1})
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := writer.WriteBatch(msgs[:1]); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed cached socket = %d %v", n, err)
	}
	if n, err := writer.WriteBatch(nil); n != 0 || err != nil {
		t.Fatalf("empty batch = %d %v", n, err)
	}
}

func TestLocalUDPWriteDeadline(t *testing.T) {
	tx := localUDPListener(t, "udp4")
	if err := tx.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	writer := newLocalUDPWriter()
	// Model a temporarily full send queue. RawConn.Write must return through
	// Go's poller/deadline path instead of busy-spinning on EAGAIN.
	writer.write = func(uintptr) bool { return false }
	msg := localUDPMessage{[]byte{1}, tx, netip.MustParseAddrPort("127.0.0.1:9")}
	if n, err := writer.WriteBatch([]localUDPMessage{msg}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline = %d %v", n, err)
	}
}

func TestLocalUDPGSOGroupBounds(t *testing.T) {
	tx := localUDPListener(t, "udp4")
	addr := netip.MustParseAddrPort("127.0.0.1:9")
	for _, tc := range []struct {
		sizes []int
		want  int
	}{
		{[]int{0, 100}, 0}, {[]int{100, 100, 37, 100}, 3},
		{[]int{100, 200}, 1}, {[]int{100, 0}, 1},
		{[]int{32754, 32754}, 1}, {[]int{32753, 32753}, 2},
	} {
		msgs := make([]localUDPMessage, len(tc.sizes))
		for i, n := range tc.sizes {
			msgs[i] = localUDPMessage{make([]byte, n), tx, addr}
		}
		if n := localGSOGroup(msgs); n != tc.want {
			t.Fatalf("GSO sizes %v: got %d want %d", tc.sizes, n, tc.want)
		}
	}
	msgs := make([]localUDPMessage, 65)
	for i := range msgs {
		msgs[i] = localUDPMessage{[]byte{1}, tx, addr}
	}
	if n := localGSOGroup(msgs); n != 64 {
		t.Fatalf("GSO segment count = %d", n)
	}
}

func TestLocalUDPConfigureBuffers(t *testing.T) {
	tx := localUDPListener(t, "udp4")
	configureLocalUDP(tx, "test")
	writer := newLocalUDPWriter()
	if _, err := writer.socket(tx); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkLocalUDPWriter(b *testing.B) {
	for _, size := range []int{64, 512, 1400} {
		for _, mode := range []string{"write", "sendmmsg", "gso"} {
			b.Run(fmt.Sprintf("%d/%s", size, mode), func(b *testing.B) {
				rx := localUDPListener(b, "udp4")
				tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
				if err != nil {
					b.Fatal(err)
				}
				defer tx.Close()
				_ = rx.SetReadBuffer(socketBufSize)
				writer := newLocalUDPWriter()
				writer.gsoDisabled = mode != "gso"
				socket, err := writer.socket(tx)
				if err != nil {
					b.Fatal(err)
				}
				if mode == "gso" && !socket.gso {
					b.Skip("kernel UDP_SEGMENT unavailable")
				}
				msgs := make([]localUDPMessage, batchSize)
				for i := range msgs {
					msgs[i] = localUDPMessage{bytes.Repeat([]byte{byte(i)}, size), tx, netip.AddrPort{}}
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					var buf [1500]byte
					for {
						if _, err := rx.Read(buf[:]); err != nil {
							return
						}
					}
				}()
				b.ReportAllocs()
				b.SetBytes(int64(batchSize * size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if mode == "write" {
						for _, msg := range msgs {
							if _, err := tx.Write(msg.payload); err != nil {
								b.Fatal(err)
							}
						}
					} else if n, err := writer.WriteBatch(msgs); n != len(msgs) || err != nil {
						b.Fatalf("WriteBatch = %d %v", n, err)
					}
				}
				b.StopTimer()
				rx.Close()
				<-done
			})
		}
	}
}
