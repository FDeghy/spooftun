//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type localUDPDatagram struct {
	payload []byte
	addr    netip.AddrPort
}

// One goroutine owns a reader. Payloads are borrowed until its next ReadBatch;
// callers must finish encoding them before reading again. GRO records can span
// multiple batches, so storage is refilled only after every record is consumed.
type localUDPReader struct {
	raw        syscall.RawConn
	gro        bool
	maxPayload int
	buffers    [batchSize][]byte
	vectors    [batchSize]unix.Iovec
	messages   [batchSize]packetMmsg
	addresses  [batchSize]unix.RawSockaddrInet4
	controls   [batchSize][32]byte
	read       func(uintptr) bool
	readErr    error
	count      int
	next       int
	offset     int
	segment    int
	addr       netip.AddrPort
	loaded     bool
}

// Only capability errors permit fallback. Permission and descriptor failures
// must be reported rather than silently selecting a different receive path.
func configureLocalUDPGRO(raw syscall.RawConn, enabled bool, setOption func(int, int, int, int) error) (bool, error) {
	value := 0
	if enabled {
		value = 1
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = setOption(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, value)
	}); err != nil {
		return false, err
	}
	switch optionErr {
	case nil:
		return enabled, nil
	case unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EINVAL:
		return false, nil
	default:
		return false, os.NewSyscallError("setsockopt UDP_GRO", optionErr)
	}
}

func newLocalUDPReader(conn *net.UDPConn, maxPayload int, gro bool) (*localUDPReader, error) {
	if conn == nil {
		return nil, unix.EBADF
	}
	if maxPayload < 0 || maxPayload > 65507 {
		return nil, fmt.Errorf("invalid local UDP payload limit %d", maxPayload)
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP.To4() == nil {
		return nil, fmt.Errorf("local UDP reader requires an IPv4 socket")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	gro, err = configureLocalUDPGRO(raw, gro, unix.SetsockoptInt)
	if err != nil {
		return nil, err
	}
	r := &localUDPReader{raw: raw, gro: gro, maxPayload: maxPayload}
	r.read = r.readReady
	size := maxPayload + 1 // Detect oversize datagrams without forwarding a prefix.
	if gro {
		size = 65535
	}
	storage := make([]byte, batchSize*size)
	for i := range r.buffers {
		r.buffers[i] = storage[i*size : (i+1)*size : (i+1)*size]
		r.vectors[i].Base = &r.buffers[i][0]
		r.vectors[i].SetLen(size)
		hdr := &r.messages[i].header
		hdr.Iov = &r.vectors[i]
		hdr.SetIovlen(1)
		hdr.Name = (*byte)(unsafe.Pointer(&r.addresses[i]))
		if gro {
			hdr.Control = &r.controls[i][0]
		}
	}
	return r, nil
}

func (r *localUDPReader) readReady(fd uintptr) bool {
	for {
		for i := range r.messages {
			hdr := &r.messages[i].header
			hdr.Namelen = unix.SizeofSockaddrInet4
			hdr.Flags = 0
			if r.gro {
				hdr.SetControllen(len(r.controls[i]))
			} else {
				hdr.SetControllen(0)
			}
			r.messages[i].length = 0
		}
		n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&r.messages[0])), uintptr(len(r.messages)), unix.MSG_DONTWAIT, 0, 0)
		runtime.KeepAlive(r)
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false
		}
		if errno != 0 {
			r.readErr = errno
		} else {
			r.count = int(n)
		}
		return true
	}
}

// Linux reports UDP_GRO's segment size as a native-endian int. Walking one
// control message at a time avoids ParseSocketControlMessage's slice allocation.
func localUDPGROSize(control []byte) (int, bool) {
	segment := 0
	for len(control) != 0 {
		if len(control) < unix.CmsgLen(0) {
			return 0, false
		}
		hdr, data, rest, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, false
		}
		if hdr.Level == unix.IPPROTO_UDP && hdr.Type == unix.UDP_GRO {
			if len(data) != 4 || segment != 0 {
				return 0, false
			}
			size := binary.NativeEndian.Uint32(data)
			if size == 0 || size > 65507 {
				return 0, false
			}
			segment = int(size)
		}
		control = rest
	}
	return segment, true
}

func (r *localUDPReader) loadRecord() bool {
	m := &r.messages[r.next]
	hdr := &m.header
	if hdr.Flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || uint64(m.length) > uint64(len(r.buffers[r.next])) ||
		hdr.Namelen < unix.SizeofSockaddrInet4 || r.addresses[r.next].Family != unix.AF_INET ||
		uint64(hdr.Controllen) > uint64(len(r.controls[r.next])) {
		return false
	}
	segment, ok := localUDPGROSize(r.controls[r.next][:int(hdr.Controllen)])
	if !ok || segment > r.maxPayload || (segment != 0 && (!r.gro || int(m.length) < segment)) ||
		(segment == 0 && int(m.length) > r.maxPayload) {
		return false
	}
	address := &r.addresses[r.next]
	portBytes := (*[2]byte)(unsafe.Pointer(&address.Port))
	r.addr = netip.AddrPortFrom(netip.AddrFrom4(address.Addr), binary.BigEndian.Uint16(portBytes[:]))
	r.segment = segment
	r.loaded = true
	return true
}

// ReadBatch waits only when no previously received records remain. It never
// waits to fill dst. Invalid/truncated/oversize input is discarded whole.
// When every record is discarded, the next read still passes through Go's
// poller so continuous invalid traffic cannot bypass a read deadline.
func (r *localUDPReader) ReadBatch(dst []localUDPDatagram) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	for {
		if r.next == r.count {
			r.next, r.count, r.readErr = 0, 0, nil
			if err := r.raw.Read(r.read); err != nil {
				return 0, err
			}
			runtime.KeepAlive(r)
			if r.readErr != nil {
				return 0, os.NewSyscallError("recvmmsg", r.readErr)
			}
		}
		n := 0
		for n < len(dst) && r.next < r.count {
			if !r.loaded && !r.loadRecord() {
				r.next++
				continue
			}
			end := int(r.messages[r.next].length)
			if r.segment != 0 {
				end = min(end, r.offset+r.segment)
			}
			// Capacity must end at this datagram: fake-fragment padding must never
			// append into the next GRO segment's bytes.
			dst[n] = localUDPDatagram{r.buffers[r.next][r.offset:end:end], r.addr}
			n++
			r.offset = end
			if end == int(r.messages[r.next].length) {
				r.next++
				r.offset, r.segment, r.loaded = 0, 0, false
			}
		}
		if n != 0 {
			return n, nil
		}
	}
}
