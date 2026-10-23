//go:build linux

package main

// AF_XDP uses separate RX and TX frame pools. The kernel owns an RX frame
// from fill publication until RX consumption, and a TX frame until completion.
// Ring indices are shared with the kernel and require acquire/release atomics.
import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const xdpRingSize = 512
const xdpFrameSize = 4096

type xdpRing struct {
	mem                       []byte
	producer, consumer, flags *uint32
	desc                      unsafe.Pointer
}

func mapXDPRing(fd int, off unix.XDPRingOffset, pgoff int64, stride int) (xdpRing, error) {
	m, err := unix.Mmap(fd, pgoff, int(off.Desc)+xdpRingSize*stride, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return xdpRing{}, err
	}
	return xdpRing{m, (*uint32)(unsafe.Pointer(&m[off.Producer])), (*uint32)(unsafe.Pointer(&m[off.Consumer])), (*uint32)(unsafe.Pointer(&m[off.Flags])), unsafe.Pointer(&m[off.Desc])}, nil
}

func (r *xdpRing) address(i uint32) *uint64 {
	return (*uint64)(unsafe.Add(r.desc, uintptr(i&(xdpRingSize-1))*8))
}
func (r *xdpRing) packet(i uint32) *unix.XDPDesc {
	return (*unix.XDPDesc)(unsafe.Add(r.desc, uintptr(i&(xdpRingSize-1))*16))
}

type xdpQueue struct {
	fd, id                   int
	umem                     []byte
	rx, tx, fill, completion xdpRing
	freeTX                   []uint64
	zeroCopy                 bool
}

func xdpSockopt(fd, option int, value unsafe.Pointer, size uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), unix.SOL_XDP, uintptr(option), uintptr(value), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func xdpGetsockopt(fd, option int, value unsafe.Pointer, size uint32) error {
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_XDP, uintptr(option), uintptr(value), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func newXDPQueue(ifindex, id int, zero bool) (_ *xdpQueue, err error) {
	q := &xdpQueue{fd: -1, id: id}
	defer func() {
		if err != nil {
			q.close()
		}
	}()
	q.fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	q.umem, err = unix.Mmap(-1, 0, xdpFrameSize*xdpRingSize*2, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	reg := unix.XDPUmemReg{Addr: uint64(uintptr(unsafe.Pointer(&q.umem[0]))), Len: uint64(len(q.umem)), Size: xdpFrameSize}
	// Use the original 32-byte registration ABI, supported before TX metadata.
	if err = xdpSockopt(q.fd, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), 32); err != nil {
		return nil, fmt.Errorf("register UMEM: %w", err)
	}
	for _, opt := range []int{unix.XDP_UMEM_FILL_RING, unix.XDP_UMEM_COMPLETION_RING, unix.XDP_RX_RING, unix.XDP_TX_RING} {
		if err = unix.SetsockoptInt(q.fd, unix.SOL_XDP, opt, xdpRingSize); err != nil {
			return nil, err
		}
	}
	var offsets unix.XDPMmapOffsets
	if err = xdpGetsockopt(q.fd, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(&offsets), uint32(unsafe.Sizeof(offsets))); err != nil {
		return nil, err
	}
	if q.rx, err = mapXDPRing(q.fd, offsets.Rx, unix.XDP_PGOFF_RX_RING, 16); err != nil {
		return nil, err
	}
	if q.tx, err = mapXDPRing(q.fd, offsets.Tx, unix.XDP_PGOFF_TX_RING, 16); err != nil {
		return nil, err
	}
	if q.fill, err = mapXDPRing(q.fd, offsets.Fr, unix.XDP_UMEM_PGOFF_FILL_RING, 8); err != nil {
		return nil, err
	}
	if q.completion, err = mapXDPRing(q.fd, offsets.Cr, unix.XDP_UMEM_PGOFF_COMPLETION_RING, 8); err != nil {
		return nil, err
	}
	flags := uint16(unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP)
	if zero {
		flags = unix.XDP_ZEROCOPY | unix.XDP_USE_NEED_WAKEUP
	}
	// A recently closed socket's pool can remain bound briefly while kernel
	// RCU/workqueue cleanup finishes. Retry only EBUSY, on the same socket and
	// mode, with a bounded sleep; another live owner still produces an error.
	bindAddr := &unix.SockaddrXDP{Ifindex: uint32(ifindex), QueueID: uint32(id), Flags: flags}
	bindDeadline := time.Now().Add(time.Second)
	for {
		err = unix.Bind(q.fd, bindAddr)
		if err != unix.EBUSY || !time.Now().Before(bindDeadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return nil, &xdpModeError{fmt.Errorf("bind AF_XDP queue %d: %w", id, err)}
	}
	var options uint32
	if err = xdpGetsockopt(q.fd, unix.XDP_OPTIONS, unsafe.Pointer(&options), 4); err != nil {
		return nil, fmt.Errorf("read actual XDP mode: %w", err)
	}
	q.zeroCopy = options&unix.XDP_OPTIONS_ZEROCOPY != 0
	for i := uint32(0); i < xdpRingSize; i++ {
		*q.fill.address(i) = uint64(i) * xdpFrameSize
		q.freeTX = append(q.freeTX, uint64(i+xdpRingSize)*xdpFrameSize)
	}
	atomic.StoreUint32(q.fill.producer, xdpRingSize)
	return q, nil
}

func (q *xdpQueue) close() {
	if q.fd >= 0 {
		unix.Close(q.fd)
		q.fd = -1
	}
	for _, r := range []*xdpRing{&q.rx, &q.tx, &q.fill, &q.completion} {
		if r.mem != nil {
			unix.Munmap(r.mem)
			r.mem = nil
		}
	}
	if q.umem != nil {
		unix.Munmap(q.umem)
		q.umem = nil
	}
}

type xdpIO struct {
	queues     []*xdpQueue
	xsks       *ebpf.Map
	program    *ebpf.Program
	attachment link.Link
	wake       int
	closed     atomic.Bool
	closeOnce  sync.Once
	rxMu, txMu sync.Mutex
	next       int
	held       *xdpQueue
	heldAddr   uint64
	poll       []unix.PollFd
}

func xdpUnsupported(err error) bool {
	var modeErr *xdpModeError
	return errors.As(err, &modeErr) && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS))
}

// Only bind/attach unsupported errors permit mode fallback. Verifier, map,
// UMEM allocation, permission, and resource-limit failures remain actionable.
type xdpModeError struct{ error }

func (e *xdpModeError) Unwrap() error { return e.error }

func xdpQueueIDs(iface string) ([]int, error) {
	paths, err := filepath.Glob(filepath.Join("/sys/class/net", iface, "queues/rx-*"))
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, p := range paths {
		id, e := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), "rx-"))
		if e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("interface %s has no discoverable RX queues", iface)
	}
	sort.Ints(ids)
	return ids, nil
}

func newXDPIO(iface string, proto uint8, mac net.HardwareAddr, localIP net.IP, port uint16, isClient bool) (packetReceiver, packetTransmitter, error) {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, err
	}
	if len(mac) != 6 || localIP != nil && localIP.To4() == nil {
		return nil, nil, fmt.Errorf("XDP requires Ethernet and IPv4")
	}
	// One frame per packet; multi-buffer AF_XDP requires a different ownership ABI.
	if dev.MTU+14 > xdpFrameSize-256 {
		return nil, nil, fmt.Errorf("XDP single-buffer mode supports interface MTU up to %d", xdpFrameSize-256-14)
	}
	ids, err := xdpQueueIDs(iface)
	if err != nil {
		return nil, nil, err
	}
	// Each attempt owns its resources and is fully unwound before the next one.
	for _, mode := range []struct {
		zero  bool
		flags link.XDPAttachFlags
		name  string
	}{
		{true, link.XDPDriverMode, "native zero-copy"},
		{false, link.XDPDriverMode, "native copy"},
		{false, link.XDPGenericMode, "generic copy"},
	} {
		x, e := openXDPIO(dev, ids, proto, mac, localIP, port, isClient, mode.zero, mode.flags)
		if e == nil {
			attachName, copyName := "native", "copy"
			if mode.flags == link.XDPGenericMode {
				attachName = "generic"
			}
			if x.queues[0].zeroCopy {
				copyName = "zero-copy"
			}
			log.Printf("packet backend=xdp attach=%s mode=%s queues=%d", attachName, copyName, len(x.queues))
			for _, q := range x.queues {
				log.Printf("AF_XDP %s queue=%d attachment=%s zero-copy=%t UMEM=%d MiB", iface, q.id, mode.name, q.zeroCopy, len(q.umem)>>20)
			}
			return x, x, nil
		}
		if !xdpUnsupported(e) {
			return nil, nil, fmt.Errorf("XDP %s: %w", mode.name, e)
		}
		log.Printf("AF_XDP %s unavailable: %v", mode.name, e)
		err = e
	}
	return nil, nil, fmt.Errorf("no supported AF_XDP mode: %w", err)
}

func openXDPIO(dev *net.Interface, ids []int, proto uint8, mac net.HardwareAddr, ip net.IP, port uint16, client, zero bool, flags link.XDPAttachFlags) (_ *xdpIO, err error) {
	x := &xdpIO{wake: -1}
	defer func() {
		if err != nil {
			x.Close()
		}
	}()
	x.wake, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		q, e := newXDPQueue(dev.Index, id, zero)
		if e != nil {
			return nil, e
		}
		x.queues = append(x.queues, q)
	}
	x.xsks, err = ebpf.NewMap(&ebpf.MapSpec{Name: "spooftun_xsks", Type: ebpf.XSKMap, KeySize: 4, ValueSize: 4, MaxEntries: uint32(ids[len(ids)-1] + 1)})
	if err != nil {
		return nil, fmt.Errorf("create XSK map (check BPF privileges/memlock): %w", err)
	}
	for _, q := range x.queues {
		key, value := uint32(q.id), uint32(q.fd)
		if err = x.xsks.Update(key, value, ebpf.UpdateAny); err != nil {
			return nil, err
		}
	}
	x.program, err = ebpf.NewProgram(&ebpf.ProgramSpec{Name: "spooftun_rx", Type: ebpf.XDP, License: "GPL", Instructions: xdpInstructions(x.xsks.FD(), proto, mac, ip, port, client)})
	if err != nil {
		return nil, fmt.Errorf("load XDP filter: %w", err)
	}
	// BPF_LINK_CREATE fails with EBUSY when an XDP attachment already exists.
	// It never replaces an unrelated firewall, CNI, or monitoring program.
	x.attachment, err = link.AttachXDP(link.XDPOptions{Program: x.program, Interface: dev.Index, Flags: flags})
	if err != nil {
		return nil, &xdpModeError{fmt.Errorf("attach XDP without replacing existing program: %w", err)}
	}
	x.poll = make([]unix.PollFd, 1, len(ids)+1)
	x.poll[0] = unix.PollFd{Fd: int32(x.wake), Events: unix.POLLIN}
	for _, q := range x.queues {
		x.poll = append(x.poll, unix.PollFd{Fd: int32(q.fd), Events: unix.POLLIN})
	}
	return x, nil
}

// ReadPacket's slice is valid until the next ReadPacket or Close. A single
// consumer reads every RSS queue, preserving the forwarding loop's ownership.
func (x *xdpIO) ReadPacket() ([]byte, error) {
	x.rxMu.Lock()
	defer x.rxMu.Unlock()
	if x.closed.Load() {
		return nil, os.ErrClosed
	}
	for x.held != nil {
		if x.closed.Load() {
			return nil, os.ErrClosed
		}
		q := x.held
		p := atomic.LoadUint32(q.fill.producer)
		if p-atomic.LoadUint32(q.fill.consumer) >= xdpRingSize {
			// The kernel can publish RX before releasing its cached FILL
			// consumer (xsk_flush does this). Retain the frame until that
			// slot is released; never overwrite a kernel-owned ring entry.
			// RX may already be readable, so polling the socket here would
			// spin. A short eventfd-only wait bounds CPU use and lets Close
			// interrupt us even if FILL progress stops.
			_, err := unix.Poll([]unix.PollFd{{Fd: int32(x.wake), Events: unix.POLLIN}}, 1)
			if err != nil && err != unix.EINTR {
				return nil, err
			}
			continue
		}
		*q.fill.address(p) = x.heldAddr
		atomic.StoreUint32(q.fill.producer, p+1)
		x.held = nil
		if atomic.LoadUint32(q.fill.flags)&unix.XDP_RING_NEED_WAKEUP != 0 {
			_, err := unix.Poll([]unix.PollFd{{Fd: int32(q.fd), Events: unix.POLLIN}}, 0)
			if err != nil && err != unix.EINTR {
				return nil, err
			}
		}
	}
	for !x.closed.Load() {
		for i := 0; i < len(x.queues); i++ {
			idx := (x.next + i) % len(x.queues)
			q := x.queues[idx]
			c := atomic.LoadUint32(q.rx.consumer)
			if c == atomic.LoadUint32(q.rx.producer) {
				continue
			}
			d := *q.rx.packet(c)
			atomic.StoreUint32(q.rx.consumer, c+1)
			// Frame start is masked because drivers may return a headroom offset.
			base := d.Addr & ^uint64(xdpFrameSize-1)
			if base >= xdpRingSize*xdpFrameSize || d.Options != 0 || d.Len == 0 || d.Addr+uint64(d.Len) > base+xdpFrameSize {
				return nil, fmt.Errorf("invalid AF_XDP RX descriptor")
			}
			x.held = q
			x.heldAddr = base
			x.next = (idx + 1) % len(x.queues)
			return q.umem[d.Addr : d.Addr+uint64(d.Len)], nil
		}
		_, err := unix.Poll(x.poll, -1)
		if err != nil && err != unix.EINTR {
			return nil, err
		}
		for _, p := range x.poll[1:] {
			if p.Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return nil, fmt.Errorf("AF_XDP RX poll flags %#x", p.Revents)
			}
		}
	}
	return nil, os.ErrClosed
}

func (q *xdpQueue) reap() error {
	c := atomic.LoadUint32(q.completion.consumer)
	p := atomic.LoadUint32(q.completion.producer)
	for c != p {
		addr := *q.completion.address(c)
		if addr < xdpRingSize*xdpFrameSize || addr >= uint64(len(q.umem)) || addr%xdpFrameSize != 0 {
			return fmt.Errorf("invalid AF_XDP completion")
		}
		q.freeTX = append(q.freeTX, addr)
		c++
	}
	atomic.StoreUint32(q.completion.consumer, c)
	return nil
}

func (x *xdpIO) WriteBatch(packets [][]byte) (int, error) {
	x.txMu.Lock()
	defer x.txMu.Unlock()
	if x.closed.Load() {
		return 0, os.ErrClosed
	}
	if len(packets) == 0 {
		return 0, nil
	}
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > xdpFrameSize {
			return 0, unix.EMSGSIZE
		}
	}
	q := x.queues[0]
	sent := 0
	deadline := time.Now().Add(time.Second)
	for sent < len(packets) && !x.closed.Load() {
		if err := q.reap(); err != nil {
			return sent, err
		}
		p := atomic.LoadUint32(q.tx.producer)
		space := xdpRingSize - (p - atomic.LoadUint32(q.tx.consumer))
		n := min(int(space), len(q.freeTX), len(packets)-sent)
		for i := 0; i < n; i++ {
			packet := packets[sent+i]
			addr := q.freeTX[len(q.freeTX)-1]
			q.freeTX = q.freeTX[:len(q.freeTX)-1]
			copy(q.umem[addr:addr+uint64(len(packet))], packet)
			*q.tx.packet(p) = unix.XDPDesc{Addr: addr, Len: uint32(len(packet))}
			p++
		}
		atomic.StoreUint32(q.tx.producer, p)
		sent += n
		if err := x.kickTX(q, deadline); err != nil {
			return sent, err
		}
		if n == 0 {
			if time.Now().After(deadline) {
				return sent, fmt.Errorf("AF_XDP TX stalled: %w", io.ErrNoProgress)
			}
			_, err := unix.Poll([]unix.PollFd{{Fd: int32(q.fd), Events: unix.POLLOUT}, {Fd: int32(x.wake), Events: unix.POLLIN}}, 10)
			if err != nil && err != unix.EINTR {
				return sent, err
			}
			// POLLOUT reports descriptor space, not necessarily completed UMEM
			// frames. Avoid spinning when the driver still owns every TX frame.
			if len(q.freeTX) == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}
	runtime.KeepAlive(q.umem)
	if x.closed.Load() {
		return sent, os.ErrClosed
	}
	return sent, nil
}

func (x *xdpIO) kickTX(q *xdpQueue, deadline time.Time) error {
	for atomic.LoadUint32(q.tx.flags)&unix.XDP_RING_NEED_WAKEUP != 0 {
		if x.closed.Load() {
			return os.ErrClosed
		}
		err := unix.Sendto(q.fd, nil, unix.MSG_DONTWAIT, nil)
		if err == nil {
			return nil
		}
		if err != unix.EAGAIN && err != unix.ENOBUFS && err != unix.EBUSY && err != unix.EINTR {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("AF_XDP TX wakeup stalled: %w", err)
		}
		// A transient wakeup failure must be retried even on the last batch.
		// Poll can report writable before descriptors complete; bound CPU use.
		time.Sleep(time.Millisecond)
	}
	return nil
}

func (x *xdpIO) Close() error {
	x.closeOnce.Do(func() {
		x.closed.Store(true)
		if x.wake >= 0 {
			var b [8]byte
			binary.NativeEndian.PutUint64(b[:], 1)
			unix.Write(x.wake, b[:])
		}
		x.rxMu.Lock()
		defer x.rxMu.Unlock()
		x.txMu.Lock()
		defer x.txMu.Unlock()
		if x.attachment != nil {
			x.attachment.Close()
		}
		// Remove socket references explicitly before closing the map/program.
		// Map destruction itself may be deferred through RCU by the kernel.
		if x.xsks != nil {
			for _, q := range x.queues {
				key := uint32(q.id)
				x.xsks.Delete(key)
			}
		}
		if x.program != nil {
			x.program.Close()
		}
		if x.xsks != nil {
			x.xsks.Close()
		}
		for _, q := range x.queues {
			q.close()
		}
		if x.wake >= 0 {
			unix.Close(x.wake)
		}
	})
	return nil
}
