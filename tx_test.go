//go:build linux

package main

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func packetSenderPair(t *testing.T, flags int) (*packetSender, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	return &packetSender{fd: fds[0]}, fds[1]
}

func TestPacketSenderBatch(t *testing.T) {
	for _, count := range []int{0, 1, 8, 64, 65, 131} {
		t.Run(string(rune('A'+count)), func(t *testing.T) {
			sender, receiver := packetSenderPair(t, 0)
			packets := make([][]byte, count)
			for i := range packets {
				packets[i] = []byte{byte(i), 2, 3, 4}
			}
			if count > 0 {
				packets[count-1] = nil
			} // Zero-length datagrams are legal.
			n, err := sender.WriteBatch(packets)
			if err != nil || n != count {
				t.Fatalf("WriteBatch=%d,%v want %d", n, err, count)
			}
			buf := make([]byte, 64)
			for i := range packets {
				n, err := unix.Read(receiver, buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], packets[i]) {
					t.Fatalf("packet %d differs", i)
				}
			}
		})
	}
}

func TestPacketSenderBatchPartial(t *testing.T) {
	sender, receiver := packetSenderPair(t, unix.SOCK_NONBLOCK)
	if err := unix.SetsockoptInt(sender.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	packets := make([][]byte, 128)
	for i := range packets {
		packets[i] = bytes.Repeat([]byte{byte(i)}, 512)
	}
	n, err := sender.WriteBatch(packets)
	if !errors.Is(err, unix.EAGAIN) || n == 0 || n >= len(packets) {
		t.Fatalf("expected partial send/EAGAIN: %d,%v", n, err)
	}
	buf := make([]byte, 1024)
	for i := 0; i < n; i++ {
		got, err := unix.Read(receiver, buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:got], packets[i]) {
			t.Fatalf("packet %d differs", i)
		}
	}
	if _, err := unix.Read(receiver, buf); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("unexpected extra datagram: %v", err)
	}
}

func TestPacketSenderInvalidFD(t *testing.T) {
	s := packetSender{fd: -1}
	if n, err := s.WriteBatch([][]byte{{1}}); n != 0 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("%d %v", n, err)
	}
	if n, err := s.WriteBatch([][]byte{{1}, {2}}); n != 0 || !errors.Is(err, unix.EBADF) {
		t.Fatalf("pooled batch: %d %v", n, err)
	}
	if err := s.WritePacketData([]byte{1}); !errors.Is(err, unix.EBADF) {
		t.Fatal(err)
	}
}

func TestPacketMmsgLayout(t *testing.T) {
	var msg packetMmsg
	if unsafe.Offsetof(msg.length) != unsafe.Sizeof(msg.header) {
		t.Fatal("incorrect mmsghdr length offset")
	}
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(msg) != 64 {
		t.Fatalf("incorrect 64-bit mmsghdr size: %d", unsafe.Sizeof(msg))
	}
}

func BenchmarkPacketSender(b *testing.B) {
	for _, batched := range []bool{false, true} {
		name := "WritePacketData"
		if batched {
			name = "WriteBatch"
		}
		b.Run(name, func(b *testing.B) {
			const batchSize, payloadSize = 16, 1200
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				b.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			sender := packetSender{fd: fds[0]}
			packets := make([][]byte, batchSize)
			for i := range packets {
				packets[i] = bytes.Repeat([]byte{byte(i)}, payloadSize)
			}
			drained := make(chan error, 1)
			go func() {
				var buf [payloadSize]byte
				for i := 0; i < b.N*batchSize; {
					n, err := unix.Read(fds[1], buf[:])
					if err == unix.EINTR {
						continue
					}
					if err != nil {
						drained <- err
						return
					}
					if n != payloadSize {
						drained <- errors.New("unexpected datagram length")
						return
					}
					i++
				}
				drained <- nil
			}()
			b.SetBytes(batchSize * payloadSize)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if batched {
					if n, err := sender.WriteBatch(packets); err != nil || n != batchSize {
						b.Fatalf("WriteBatch: n=%d err=%v", n, err)
					}
				} else {
					for _, p := range packets {
						if err := sender.WritePacketData(p); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
			b.StopTimer()
			if err := <-drained; err != nil {
				b.Fatal(err)
			}
		})
	}
}
