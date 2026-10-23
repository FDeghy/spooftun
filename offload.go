//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// --- GSO/GRO Helpers ---

// gsoControlSize is the cmsg space needed for UDP_SEGMENT
var gsoControlSize = unix.CmsgSpace(sizeOfGSOData)

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

// splitCoalescedMessages splits GRO-coalesced messages into individual datagrams
func splitCoalescedMessages(msgs []ipv4.Message, firstMsgAt, received int) (int, error) {
	n := 0
	for i := firstMsgAt; i < firstMsgAt+received; i++ {
		msg := &msgs[i]
		// Snapshot source metadata before a destination slot may alias it.
		data, addr, flags := msg.Buffers[0][:msg.N], msg.Addr, msg.Flags
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
			end = min(gsoSize, len(data))
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], data[start:end])
			msgs[n].N = copied
			msgs[n].Addr = addr
			msgs[n].Flags = flags
			start = end
			end += gsoSize
			if end > len(data) {
				end = len(data)
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
			msgs[i].Buffers[0] = make([]byte, *tunnelMTU+1)
		}
	}
	return msgs
}
