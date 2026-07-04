//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// --- GSO/GRO Helpers ---

// gsoControlSize is the cmsg space needed for UDP_SEGMENT
var gsoControlSize = unix.CmsgSpace(sizeOfGSOData)

// supportsUDPOffload probes the socket for GSO (UDP_SEGMENT) and GRO (UDP_GRO) support
func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		txOffload = errSyscall == nil
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		rxOffload = errSyscall == nil && opt == 1
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}

// enableUDPGRO enables UDP_GRO on the socket
func enableUDPGRO(conn *net.UDPConn) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sysErr error
	err = rc.Control(func(fd uintptr) {
		sysErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	})
	if err != nil {
		return err
	}
	return sysErr
}

// getGSOSize parses control message for UDP_GRO and returns the GSO segment size
func getGSOSize(control []byte) (int, error) {
	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  = control
		err  error
	)
	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(rem)
		if err != nil {
			return 0, fmt.Errorf("error parsing socket control message: %w", err)
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= sizeOfGSOData {
			var gso uint16
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&gso)), sizeOfGSOData), data[:sizeOfGSOData])
			return int(gso), nil
		}
	}
	return 0, nil
}

// setGSOSize sets a UDP_SEGMENT in control based on gsoSize
func setGSOSize(control *[]byte, gsoSize uint16) {
	existingLen := len(*control)
	avail := cap(*control) - existingLen
	space := unix.CmsgSpace(sizeOfGSOData)
	if avail < space {
		return
	}
	*control = (*control)[:cap(*control)]
	gsoControl := (*control)[existingLen:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(gsoControl)[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	copy((gsoControl)[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:existingLen+space]
}

// errShouldDisableUDPGSO checks if GSO should be disabled due to EIO (missing tx checksum offload)
func errShouldDisableUDPGSO(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		return serr.Err == unix.EIO
	}
	return false
}

// splitCoalescedMessages splits GRO-coalesced messages into individual datagrams
func splitCoalescedMessages(msgs []ipv4.Message, firstMsgAt int) (int, error) {
	n := 0
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, nil
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		var err error
		gsoSize, err = getGSOSize(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			msg.N = 0
		}
	}
	return n, nil
}

// resetOOB resets OOB slices to full capacity before ReadBatch so the kernel
// can write GRO control messages into them. Without this, GRO silently fails
// after the first batch because msg.NN truncates the OOB length.
func resetOOB(msgs []ipv4.Message) {
	for i := range msgs {
		if msgs[i].OOB != nil {
			msgs[i].OOB = msgs[i].OOB[:cap(msgs[i].OOB)]
		}
	}
}

// prepareMsgsUDP creates message buffers for UDP batch reads
// When groEnabled is true, OOB buffers are allocated for control message parsing (UDP_GRO)
// and a larger data buffer is used to accommodate GRO-coalesced payloads
func prepareMsgsUDP(groEnabled bool) []ipv4.Message {
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		if groEnabled {
			// GRO can coalesce up to udpSegmentMaxDatagrams into one buffer
			msgs[i].Buffers[0] = make([]byte, udpPayloadSize*udpSegmentMaxDatagrams)
			msgs[i].OOB = make([]byte, gsoControlSize)
		} else {
			msgs[i].Buffers[0] = make([]byte, udpPayloadSize)
		}
	}
	return msgs
}
