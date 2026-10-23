//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const txRingHeaderSize = (unix.SizeofTpacket2Hdr + unix.TPACKET_ALIGNMENT - 1) &^ (unix.TPACKET_ALIGNMENT - 1)

// txRingSender uses a dedicated, send-only TPACKET_V2 socket. This is mmap TX,
// not NIC zero-copy: the kernel may still copy frames to driver buffers.
type txRingSender struct {
	mu                                    sync.Mutex
	closing                               atomic.Bool
	fd                                    int
	ring                                  []byte
	frameSize, frameCount, next, maxFrame int
	broken                                error
}

func txRingLayout(mtu, pageSize int) (frameSize, blockSize, blockCount int, err error) {
	if mtu < 68 || mtu > 65535 || pageSize < 4096 || pageSize&(pageSize-1) != 0 {
		return 0, 0, 0, fmt.Errorf("invalid TX ring MTU %d or page size %d", mtu, pageSize)
	}
	frameSize = 2048
	for frameSize < txRingHeaderSize+mtu+14 {
		frameSize *= 2
	}
	blockSize = max(pageSize, frameSize)
	// Small contiguous allocations and a bounded ~1 MiB ring on normal MTUs.
	blockCount = max(1, (1<<20)/blockSize)
	return
}

func newTXRingSender(ifaceName string, mtu int) (*txRingSender, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	frameSize, blockSize, blockCount, err := txRingLayout(mtu, os.Getpagesize())
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open TX ring socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2); err != nil {
		return nil, err
	}
	// Skip malformed frames instead of permanently wedging the kernel TX head.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_LOSS, 1); err != nil {
		return nil, err
	}
	req := &unix.TpacketReq{Block_size: uint32(blockSize), Block_nr: uint32(blockCount), Frame_size: uint32(frameSize), Frame_nr: uint32(blockSize / frameSize * blockCount)}
	if err := unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_TX_RING, req); err != nil {
		return nil, fmt.Errorf("allocate TX ring: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index}); err != nil {
		return nil, err
	}
	ring, err := unix.Mmap(fd, 0, blockSize*blockCount, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map TX ring: %w", err)
	}
	ok = true
	return &txRingSender{fd: fd, ring: ring, frameSize: frameSize, frameCount: int(req.Frame_nr), maxFrame: mtu + 14}, nil
}

func (s *txRingSender) header(index int) *unix.Tpacket2Hdr {
	return (*unix.Tpacket2Hdr)(unsafe.Pointer(&s.ring[index*s.frameSize]))
}

func (s *txRingSender) kick() error {
	for {
		err := unix.Sendto(s.fd, nil, unix.MSG_DONTWAIT, nil)
		if err != unix.EINTR {
			return err
		}
	}
}

func (s *txRingSender) waitAvailable(h *unix.Tpacket2Hdr) error {
	for {
		if s.closing.Load() {
			return net.ErrClosed
		}
		status := atomic.LoadUint32(&h.Status)
		if status&unix.TP_STATUS_WRONG_FORMAT != 0 {
			atomic.StoreUint32(&h.Status, unix.TP_STATUS_AVAILABLE)
			return errors.New("kernel rejected TX ring frame format")
		}
		if status&(unix.TP_STATUS_SEND_REQUEST|unix.TP_STATUS_SENDING) == 0 {
			return nil
		}
		if status&unix.TP_STATUS_SEND_REQUEST != 0 {
			if err := s.kick(); err != nil && err != unix.EAGAIN && err != unix.ENOBUFS {
				return err
			}
		}
		fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(fds, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("TX ring socket failed while waiting")
		}
		// Some drivers report writable while the particular next slot still belongs
		// to the NIC. Bound that spurious readiness without burning a CPU core.
		if n > 0 && atomic.LoadUint32(&h.Status)&(unix.TP_STATUS_SEND_REQUEST|unix.TP_STATUS_SENDING) != 0 {
			time.Sleep(time.Millisecond)
		}
	}
}

// WriteBatch returns frames handed to the ring, including any still in flight.
// Like sendmmsg success, this is submission rather than delivery confirmation.
// All lengths are checked before publishing any frame from a batch.
func (s *txRingSender) WriteBatch(packets [][]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return 0, net.ErrClosed
	}
	if s.broken != nil {
		return 0, s.broken
	}
	for _, packet := range packets {
		if len(packet) < 14 || len(packet) > s.maxFrame {
			return 0, fmt.Errorf("TX ring Ethernet frame size %d outside 14..%d", len(packet), s.maxFrame)
		}
	}
	sent := 0
	for sent < len(packets) {
		h := s.header(s.next)
		if err := s.waitAvailable(h); err != nil {
			return sent, err
		}
		count := 0
		for sent < len(packets) && count < s.frameCount {
			h = s.header(s.next)
			if atomic.LoadUint32(&h.Status)&(unix.TP_STATUS_SEND_REQUEST|unix.TP_STATUS_SENDING|unix.TP_STATUS_WRONG_FORMAT) != 0 {
				break
			}
			packet := packets[sent]
			offset := s.next*s.frameSize + txRingHeaderSize
			copy(s.ring[offset:offset+len(packet)], packet)
			h.Len = uint32(len(packet))
			h.Snaplen = uint32(len(packet))
			atomic.StoreUint32(&h.Status, unix.TP_STATUS_SEND_REQUEST)
			s.next = (s.next + 1) % s.frameCount
			sent++
			count++
		}
		if err := s.kick(); err != nil {
			if err != unix.EAGAIN && err != unix.ENOBUFS {
				s.broken = err
				return sent, err
			}
		}
		// A successful send may still have consumed only part of the ring before
		// queue pressure. Never strand a final SEND_REQUEST awaiting a future call.
		last := (s.next + s.frameCount - 1) % s.frameCount
		if atomic.LoadUint32(&s.header(last).Status)&unix.TP_STATUS_SEND_REQUEST != 0 {
			if err := s.waitAvailable(s.header(last)); err != nil {
				return sent, err
			}
		}
	}
	return sent, nil
}

func (s *txRingSender) Close() error {
	s.closing.Store(true) // Interrupt a writer waiting under mu within 100 ms.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ring == nil {
		return nil
	}
	// Close before unmapping; no userspace writer can touch the mapping now.
	err := unix.Close(s.fd)
	s.fd = -1
	unmapErr := unix.Munmap(s.ring)
	s.ring = nil
	return errors.Join(err, unmapErr)
}
