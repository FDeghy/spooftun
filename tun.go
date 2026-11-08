//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func validateTUNOptions() error {
	if *tunName == "" {
		if *tunAddress != "" {
			return fmt.Errorf("-tun-address requires -tun")
		}
		return nil
	}
	if _, err := unix.NewIfreq(*tunName); err != nil {
		return fmt.Errorf("invalid -tun: %w", err)
	}
	if _, err := netip.ParsePrefix(*tunAddress); err != nil {
		return fmt.Errorf("-tun requires a valid -tun-address CIDR: %w", err)
	}
	if net.ParseIP(*tunnelIP).To4() == nil {
		return fmt.Errorf("-tun requires -remote-ip on both peers")
	}
	if *noise || *udpGRO || *outboundPort != 0 {
		return fmt.Errorf("-tun cannot use -noise, -udp-gro, or -outbound-port")
	}
	return nil
}

// Never attach to an existing interface: changing its MTU/address could disrupt
// unrelated traffic. A nonpersistent TUN disappears when its last queue closes.
func openTUNQueues(name, address string, mtu, count int) (queues []*os.File, err error) {
	if _, e := net.InterfaceByName(name); e == nil {
		return nil, fmt.Errorf("TUN interface %q already exists", name)
	}
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return nil, err
	}
	if mtu < 68 || prefix.Addr().Is6() && mtu < 1280 {
		return nil, fmt.Errorf("outer MTU leaves insufficient space for TUN address family")
	}
	defer func() {
		if err != nil {
			for _, q := range queues {
				q.Close()
			}
		}
	}()
	for range count {
		fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return queues, e
		}
		req, e := unix.NewIfreq(name)
		if e == nil {
			flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
			if len(queues) == 0 {
				flags |= unix.IFF_TUN_EXCL
			}
			req.SetUint16(flags)
			e = unix.IoctlIfreq(fd, unix.TUNSETIFF, req)
		}
		if e != nil {
			unix.Close(fd)
			return queues, e
		}
		queues = append(queues, os.NewFile(uintptr(fd), name))
	}
	for _, args := range [][]string{
		{"address", "add", address, "dev", name},
		{"link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"},
	} {
		if out, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			return queues, fmt.Errorf("configure TUN: %w: %s", e, out)
		}
	}
	return queues, nil
}

// TUN never enables virtio/GSO offloads: every read is one complete IP packet.
// Check lengths before injection, including after removing fake-frag padding.
func validTUNPacket(p []byte, mtu int) bool {
	if len(p) == 0 || len(p) > mtu {
		return false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return false
		}
		h := int(p[0]&15) * 4
		return h >= 20 && h <= len(p) && int(binary.BigEndian.Uint16(p[2:4])) == len(p) && encoderFoldChecksum(encoderChecksumSum(p[:h], 0)) == 0
	case 6:
		return mtu >= 1280 && len(p) >= 40 && int(binary.BigEndian.Uint16(p[4:6]))+40 == len(p)
	}
	return false
}

// Fold the inner flow into the cosmetic source port so existing AF_PACKET
// fanout distributes flows, including custom outer protocol numbers. Fragmented
// IPv4 uses addresses/protocol only so all fragments keep the same worker.
func tunFlowPort(p []byte) uint16 {
	var key []byte
	var ports []byte
	proto := p[6]
	if p[0]>>4 == 4 {
		proto = p[9]
		key = p[12:20]
		h := int(p[0]&15) * 4
		if binary.BigEndian.Uint16(p[6:8])&0x3fff == 0 && (p[9] == 6 || p[9] == 17) && len(p) >= h+4 {
			ports = p[h : h+4]
		}
	} else {
		key = p[8:40]
		if (p[6] == 6 || p[6] == 17) && len(p) >= 44 {
			ports = p[40:44]
		}
	}
	h := uint32(2166136261)
	h = (h ^ uint32(proto)) * 16777619
	for _, b := range key {
		h = (h ^ uint32(b)) * 16777619
	}
	for _, b := range ports {
		h = (h ^ uint32(b)) * 16777619
	}
	return uint16(h%64512) + 1024
}

func tunTransmit(q *os.File, tx packetTransmitter, enc *tunnelEncoder, mtu, innerMTU int, client bool) error {
	// A single worker can amortize more sends per syscall. With multiple
	// workers keep bursts short so transmitters do not starve receive work.
	tunBatchSize := batchSize
	if *packetWorkers == 1 {
		tunBatchSize = 64
	}
	raw, err := q.SyscallConn()
	if err != nil {
		return err
	}
	// One blocking/pollable read, then drain only packets already available.
	// Reusable batch storage avoids per-packet allocations and queue handoffs.
	input := make([]byte, 65536)
	storage := make([][]byte, tunBatchSize*2)
	for i := range storage {
		storage[i] = make([]byte, max(60, mtu+14))
	}
	frames := make([][]byte, 0, len(storage))
	id := uint16(0)
	encodeOne := func(p []byte) error {
		if !validTUNPacket(p, innerMTU) {
			return nil
		}
		flow := tunFlowPort(p)
		src, dst := flow, uint16(*targetPort)
		if !client {
			src, dst = dst, src
		}
		flags := uint16(0x4000)
		if client && *fakeFrag {
			p = padData(p, 8, enc.transportLen)
			flags = 0x2000
		}
		idx := len(frames)
		frame, e := enc.Encode(storage[idx], p, src, dst, id, flags, 0, true)
		if e != nil {
			return e
		}
		if client && *fakeFrag {
			tail, e := enc.Encode(storage[idx+1], []byte{'0'}, 0, 0, id, 0, uint16((len(p)+enc.transportLen)/8), false)
			if e != nil {
				return e
			}
			frames = append(frames, frame, tail)
		} else {
			frames = append(frames, frame)
		}
		id++
		return nil
	}
	for {
		n, err := q.Read(input)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.EOF
		}
		frames = frames[:0]
		if err := encodeOne(input[:n]); err != nil {
			return err
		}
		var readErr error
		if tunBatchSize > 1 {
			if controlErr := raw.Control(func(fd uintptr) {
				for i := 1; i < tunBatchSize; i++ {
					n, readErr = unix.Read(int(fd), input)
					if readErr != nil {
						if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EINTR) {
							readErr = nil
						}
						return
					}
					if n == 0 {
						readErr = io.EOF
						return
					}
					if readErr = encodeOne(input[:n]); readErr != nil {
						return
					}
				}
			}); controlErr != nil && readErr == nil {
				readErr = controlErr
			}
		}
		if len(frames) != 0 {
			written, err := tx.WriteBatch(frames)
			if err != nil {
				return err
			}
			if written != len(frames) {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

func tunReceive(q *os.File, rx packetReceiver, filter tunnelPacketFilter, peer, local net.IP, mtu int, client bool) error {
	r := newPacketReader(rx)
	peer4 := [4]byte(peer.To4())
	local4 := [4]byte(local.To4())
	for {
		frame, err := r.ReadPacket()
		if err != nil {
			return err
		}
		p, ok := parseEthIPv4(frame)
		if !ok || [4]byte(p.srcIP) != peer4 || [4]byte(p.dstIP) != local4 {
			continue
		}
		src, dst, payload, ok := parseTunnelTransport(p, *fakeTCP)
		if !ok || !filter.matches(p, src, dst) {
			continue
		}
		if !client && *fakeFrag {
			payload = unpadData(payload)
		}
		if !validTUNPacket(payload, mtu) {
			continue
		}
		n, err := q.Write(payload)
		if err != nil {
			return err
		}
		if n != len(payload) {
			return io.ErrShortWrite
		}
	}
}

func startTUN(iface string, peer net.IP, up, down uint8) error {
	mtu, err := effectiveMTU(iface)
	if err != nil {
		return err
	}
	innerMTU := payloadLimit(mtu, *fakeTCP, *fakeFrag)
	mac, ifaceIP, err := getInterfaceInfo(iface)
	if err != nil {
		return err
	}
	txSrcIP := ifaceIP
	if *customSrc != "" {
		txSrcIP = net.ParseIP(*customSrc)
	}
	dstMAC, err := getNeighborMAC(iface, peer)
	if err != nil {
		return err
	}
	client := *mode == "client"
	txProto, rxProto := up, down
	if !client {
		txProto, rxProto = down, up
	}
	enc, err := newTunnelEncoder(mac, dstMAC, txSrcIP, peer, txProto, *fakeTCP, tcpFlagByte)
	if err != nil {
		return err
	}
	filterIP := resolveFilterDstIP(ifaceIP)
	workers, err := newTunnelWorkers(iface, rxProto, mac, filterIP, uint16(*targetPort), client)
	if err != nil {
		return err
	}
	queues, err := openTUNQueues(*tunName, *tunAddress, innerMTU, len(workers))
	if err != nil {
		closeTunnelWorkers(workers)
		return err
	}
	// Once loops start these resources live until process exit, just like the
	// UDP mode. Never unmap a packet ring while a reader still borrows it.
	failed := make(chan error, len(workers)*2)
	filter := newTunnelPacketFilter(rxProto, mac, filterIP, uint16(*targetPort), client)
	for i, w := range workers {
		q := queues[i]
		go func() { failed <- tunTransmit(q, w.sender, enc, mtu, innerMTU, client) }()
		go func() { failed <- tunReceive(q, w.receiver, filter, peer, filterIP, innerMTU, client) }()
	}
	log.Printf("TUN %s address=%s mtu=%d outer-mtu=%d queues=%d (no encryption/authentication)", *tunName, *tunAddress, innerMTU, mtu, len(queues))
	err = <-failed
	for _, q := range queues {
		q.Close()
	}
	return fmt.Errorf("TUN forwarding stopped: %w", err)
}
