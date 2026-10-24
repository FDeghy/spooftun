//go:build linux

package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// An invalid addr selects the connected socket's peer. Payloads must remain
// owned by the caller until WriteBatch returns. A writer has one goroutine owner.
type localUDPMessage struct {
	payload []byte
	conn    *net.UDPConn
	addr    netip.AddrPort
}

type localUDPSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	gso  bool
}

// Keep a bounded cache: retaining every expired server session here would keep
// its Go socket alive indefinitely. Repeated active flows need no new RawConn.
type localUDPWriter struct {
	sockets     [batchSize]localUDPSocket
	nextSocket  int
	gsoDisabled bool
	vectors     [packetBatchSize]unix.Iovec
	messages    [packetBatchSize]packetMmsg
	addresses   [packetBatchSize][unix.SizeofSockaddrInet6]byte
	control     [32]byte
	write       func(uintptr) bool
	writeGSO    bool
	writeHeader unix.Msghdr
	writeTotal  int
	writeDone   int
	writeMsgs   []localUDPMessage
	writeErr    error
}

func newLocalUDPWriter() *localUDPWriter {
	w := new(localUDPWriter)
	w.write = w.writeReady
	return w
}

func (w *localUDPWriter) socket(conn *net.UDPConn) (*localUDPSocket, error) {
	if conn == nil {
		return nil, unix.EBADF
	}
	for i := range w.sockets {
		if w.sockets[i].conn == conn {
			return &w.sockets[i], nil
		}
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	gso := false
	if err := raw.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		gso = err == nil
	}); err != nil {
		return nil, err
	}
	s := &w.sockets[w.nextSocket]
	w.nextSocket = (w.nextSocket + 1) % len(w.sockets)
	*s = localUDPSocket{conn: conn, raw: raw, gso: gso}
	return s, nil
}

// localGSOGroup preserves datagram boundaries. A final shorter datagram is
// allowed, but empty datagrams and a longer next datagram end the group.
func localGSOGroup(msgs []localUDPMessage) int {
	if len(msgs) == 0 || len(msgs[0].payload) == 0 {
		return 0
	}
	size, total := len(msgs[0].payload), 0
	for i := 0; i < min(len(msgs), udpSegmentMaxDatagrams); i++ {
		m := &msgs[i]
		n := len(m.payload)
		// 65507 is valid for both IPv4 and IPv6 UDP payloads.
		if m.conn != msgs[0].conn || m.addr != msgs[0].addr || n == 0 || n > size || total+n > 65507 {
			return i
		}
		total += n
		if n < size {
			return i + 1
		}
	}
	return min(len(msgs), udpSegmentMaxDatagrams)
}

func localGSOUnsupported(err error) bool {
	return err == unix.EINVAL || err == unix.EIO || err == unix.ENOPROTOOPT || err == unix.EOPNOTSUPP
}

func (w *localUDPWriter) address(i int, addr netip.AddrPort, hdr *unix.Msghdr) error {
	if !addr.IsValid() {
		return nil
	}
	b := &w.addresses[i]
	clear(b[:])
	binary.BigEndian.PutUint16(b[2:4], addr.Port())
	ip := addr.Addr()
	if ip.Is4() {
		binary.NativeEndian.PutUint16(b[:2], unix.AF_INET)
		a := ip.As4()
		copy(b[4:8], a[:])
		hdr.Namelen = unix.SizeofSockaddrInet4
	} else {
		binary.NativeEndian.PutUint16(b[:2], unix.AF_INET6)
		a := ip.As16()
		copy(b[8:24], a[:])
		if zone := ip.Zone(); zone != "" {
			index, err := strconv.ParseUint(zone, 10, 32)
			if err != nil {
				iface, err := net.InterfaceByName(zone)
				if err != nil {
					return err
				}
				index = uint64(iface.Index)
			}
			binary.NativeEndian.PutUint32(b[24:28], uint32(index))
		}
		hdr.Namelen = unix.SizeofSockaddrInet6
	}
	hdr.Name = &b[0]
	return nil
}

func (w *localUDPWriter) vector(i int, payload []byte) {
	w.vectors[i] = unix.Iovec{}
	if len(payload) != 0 {
		w.vectors[i].Base = &payload[0]
	}
	w.vectors[i].SetLen(len(payload))
}

func (w *localUDPWriter) sendGSO(s *localUDPSocket, msgs []localUDPMessage) error {
	w.writeHeader = unix.Msghdr{}
	hdr := &w.writeHeader
	if err := w.address(0, msgs[0].addr, hdr); err != nil {
		return err
	}
	total := 0
	for i := range msgs {
		w.vector(i, msgs[i].payload)
		total += len(msgs[i].payload)
	}
	hdr.Iov = &w.vectors[0]
	hdr.SetIovlen(len(msgs))
	clear(w.control[:])
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&w.control[0]))
	cmsg.Level, cmsg.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
	cmsg.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(w.control[unix.CmsgLen(0):], uint16(len(msgs[0].payload)))
	hdr.Control = &w.control[0]
	hdr.SetControllen(unix.CmsgSpace(2))
	w.writeGSO, w.writeTotal, w.writeErr = true, total, nil
	err := s.raw.Write(w.write)
	runtime.KeepAlive(msgs)
	runtime.KeepAlive(w)
	if err != nil {
		return err
	}
	return w.writeErr
}

// Store the poller callback once on construction. Creating closures around each
// syscall would make the captured headers and counters escape on every batch.
func (w *localUDPWriter) writeReady(fd uintptr) bool {
	if w.writeGSO {
		for {
			n, _, errno := unix.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(&w.writeHeader)), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
			if errno == unix.EINTR {
				continue
			}
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
				return false
			}
			if errno != 0 {
				w.writeErr = errno
			} else if int(n) != w.writeTotal {
				w.writeErr = io.ErrShortWrite
			}
			return true
		}
	}
	for w.writeDone < len(w.writeMsgs) {
		n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&w.messages[w.writeDone])), uintptr(len(w.writeMsgs)-w.writeDone), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL, 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false
		}
		if errno != 0 {
			w.writeErr = errno
			return true
		}
		if n == 0 {
			w.writeErr = io.ErrNoProgress
			return true
		}
		for j := w.writeDone; j < w.writeDone+int(n); j++ {
			if int(w.messages[j].length) != len(w.writeMsgs[j].payload) {
				w.writeErr = io.ErrShortWrite
				w.writeDone = j
				return true
			}
		}
		w.writeDone += int(n)
	}
	return true
}

func (w *localUDPWriter) sendBatch(s *localUDPSocket, msgs []localUDPMessage) (int, error) {
	for i := range msgs {
		w.vector(i, msgs[i].payload)
		w.messages[i] = packetMmsg{}
		hdr := &w.messages[i].header
		hdr.Iov = &w.vectors[i]
		hdr.SetIovlen(1)
		if err := w.address(i, msgs[i].addr, hdr); err != nil {
			return 0, err
		}
	}
	w.writeGSO, w.writeDone, w.writeMsgs, w.writeErr = false, 0, msgs, nil
	err := s.raw.Write(w.write)
	w.writeMsgs = nil
	runtime.KeepAlive(msgs)
	runtime.KeepAlive(w)
	if err != nil {
		return w.writeDone, err
	}
	return w.writeDone, w.writeErr
}

// WriteBatch sends only already available datagrams; it never waits to assemble
// a larger batch. GSO uses scatter/gather, so no concatenation copy is required.
func (w *localUDPWriter) WriteBatch(msgs []localUDPMessage) (int, error) {
	defer clear(w.vectors[:]) // Do not retain callers' packet buffers while idle.
	sent := 0
	for sent < len(msgs) {
		remaining := msgs[sent:]
		s, err := w.socket(remaining[0].conn)
		if err != nil {
			return sent, err
		}
		if s.gso && !w.gsoDisabled {
			if n := localGSOGroup(remaining); n > 1 {
				err := w.sendGSO(s, remaining[:n])
				if err == nil {
					sent += n
					continue
				}
				if !localGSOUnsupported(err) {
					return sent, os.NewSyscallError("sendmsg", err)
				}
				// Unsupported GSO has not sent any datagrams. Retry the same
				// messages, then use sendmmsg for this writer's future batches.
				w.gsoDisabled = true
			}
		}
		n := 1
		for n < min(len(remaining), packetBatchSize) && remaining[n].conn == remaining[0].conn {
			n++
		}
		done, err := w.sendBatch(s, remaining[:n])
		sent += done
		if err != nil {
			return sent, os.NewSyscallError("sendmmsg", err)
		}
	}
	return sent, nil
}

// Linux doubles SO_RCVBUF/SO_SNDBUF values for kernel accounting. Report those
// actual values and detect silent clamping, rather than assuming Set* succeeded.
func configureLocalUDP(conn *net.UDPConn, label string) {
	raw, err := conn.SyscallConn()
	if err != nil {
		log.Printf("UDP %s socket buffers: %v", label, err)
		return
	}
	inspect := func() (rx, tx int, err error) {
		var sysErr error
		err = raw.Control(func(fd uintptr) {
			rx, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			if sysErr == nil {
				tx, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
			}
		})
		if err == nil {
			err = sysErr
		}
		return
	}
	beforeRX, beforeTX, beforeErr := inspect()
	if err := conn.SetReadBuffer(socketBufSize); err != nil {
		log.Printf("UDP %s SetReadBuffer: %v", label, err)
	}
	if err := conn.SetWriteBuffer(socketBufSize); err != nil {
		log.Printf("UDP %s SetWriteBuffer: %v", label, err)
	}
	rx, tx, err := inspect()
	if err != nil || beforeErr != nil {
		log.Printf("UDP %s inspect socket buffers: before=%v after=%v", label, beforeErr, err)
		return
	}
	log.Printf("UDP %s socket buffers requested=%d kernel-rx=%d (was %d) kernel-tx=%d (was %d)", label, socketBufSize, rx, beforeRX, tx, beforeTX)
	if rx < 2*socketBufSize || tx < 2*socketBufSize {
		log.Printf("Warning: UDP %s socket buffers capped: requested=%d kernel-rx=%d kernel-tx=%d (Linux accounting target=%d); inspect net.core.rmem_max/net.core.wmem_max", label, socketBufSize, rx, tx, 2*socketBufSize)
	}
}
