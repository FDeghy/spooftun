//go:build linux

package main

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// packetSender writes complete Ethernet frames to one interface. Protocol 0
// makes this a send-only packet socket, so it does not capture traffic or
// allocate an RX ring just to call write(2).
type packetSender struct {
	fd int
}

func newPacketSender(ifaceName string) (*packetSender, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("find TX interface %q: %w", ifaceName, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open TX packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind TX packet socket to %q: %w", ifaceName, err)
	}
	return &packetSender{fd: fd}, nil
}

func (s *packetSender) WritePacketData(pkt []byte) error {
	var n int
	var err error
	for {
		n, err = unix.Write(s.fd, pkt)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return io.ErrShortWrite
	}
	return nil
}

// mmsg mirrors Linux struct mmsghdr. Go's native trailing alignment supplies
// the ABI padding after len on both amd64 and arm64.
type packetMmsg struct {
	header unix.Msghdr
	length uint32
}

const packetBatchSize = 64

type packetBatchDescriptors struct {
	vectors  [packetBatchSize]unix.Iovec
	messages [packetBatchSize]packetMmsg
}

var packetBatchPool = sync.Pool{New: func() any { return new(packetBatchDescriptors) }}

func (d *packetBatchDescriptors) release() {
	// Iovec.Base points into callers' packet buffers. Clear these before pooling
	// so an idle sender never retains an entire batch of otherwise dead buffers.
	clear(d.vectors[:])
	packetBatchPool.Put(d)
}

// WriteBatch sends complete frames with one syscall per batch, without waiting
// to collect more traffic. It returns the number sent before any failure.
// Per-call descriptors allow concurrent writers without a global TX lock.
func (s *packetSender) WriteBatch(packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(packets) == 1 {
		if err := s.WritePacketData(packets[0]); err != nil {
			return 0, err
		}
		return 1, nil
	}
	descriptors := packetBatchPool.Get().(*packetBatchDescriptors)
	defer descriptors.release()
	vectors := &descriptors.vectors
	messages := &descriptors.messages
	sent := 0
	for sent < len(packets) {
		count := min(packetBatchSize, len(packets)-sent)
		for i := 0; i < count; i++ {
			pkt := packets[sent+i]
			vectors[i] = unix.Iovec{}
			if len(pkt) > 0 {
				vectors[i].Base = &pkt[0]
			}
			vectors[i].SetLen(len(pkt))
			messages[i] = packetMmsg{}
			messages[i].header.Iov = &vectors[i]
			messages[i].header.SetIovlen(1)
		}
		done := 0
		for done < count {
			n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(s.fd), uintptr(unsafe.Pointer(&messages[done])), uintptr(count-done), unix.MSG_NOSIGNAL, 0, 0)
			// The syscall only sees uintptr addresses. Keep descriptors and packet
			// backing arrays live until the kernel has finished reading them.
			runtime.KeepAlive(packets)
			runtime.KeepAlive(descriptors)
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 {
				return sent + done, errno
			}
			if n == 0 {
				return sent + done, io.ErrNoProgress
			}
			for j := done; j < done+int(n); j++ {
				if int(messages[j].length) != len(packets[sent+j]) {
					return sent + j, io.ErrShortWrite
				}
			}
			done += int(n)
		}
		sent += count
	}
	return sent, nil
}

func (s *packetSender) Close() error {
	return unix.Close(s.fd)
}
