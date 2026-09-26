//go:build linux

package main

import (
	"fmt"
	"io"
	"net"

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
	n, err := unix.Write(s.fd, pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *packetSender) Close() error {
	return unix.Close(s.fd)
}
