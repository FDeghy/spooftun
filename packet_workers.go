//go:build linux

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type tunnelWorker struct {
	receiver packetReceiver
	sender   packetTransmitter
}

func validatePacketWorkers(backend string, count int, distribution string) error {
	if count < 1 || count > 64 {
		return fmt.Errorf("-packet-workers must be 1..64")
	}
	if distribution != "flow" && distribution != "spread" {
		return fmt.Errorf("-packet-distribution must be flow or spread")
	}
	if backend != "afpacket" && (count != 1 || distribution != "flow") {
		return fmt.Errorf("-packet-workers and -packet-distribution require -backend afpacket")
	}
	return nil
}

func closeTunnelWorkers(workers []tunnelWorker) {
	for _, w := range workers {
		w.receiver.Close()
		w.sender.Close()
	}
}

// A temporary member asks the kernel to allocate a unique fanout group. This
// avoids PID-derived IDs accidentally sharing packets with another process.
// It also supplies the public fd needed to install the group's cBPF selector;
// gopacket intentionally does not expose its socket fd. The temporary member
// leaves before any forwarding loop starts, so only real workers receive data.
func openPacketFanout(iface, distribution string) (fd int, id uint16, kind afpacket.FanoutType, err error) {
	dev, err := net.InterfaceByName(iface)
	if err != nil {
		return -1, 0, 0, err
	}
	fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, err
	}
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()
	// sockaddr_ll protocol is in network byte order on both supported CPUs.
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: dev.Index, Protocol: 0x0008}); err != nil {
		return
	}
	kind = afpacket.FanoutCBPF
	if distribution == "spread" {
		kind = afpacket.FanoutLoadBalance
	}
	arg := (int(kind) | unix.PACKET_FANOUT_FLAG_UNIQUEID) << 16
	if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, arg); err != nil {
		return
	}
	var actual int
	actual, err = unix.GetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT)
	if err != nil {
		return
	}
	id = uint16(actual)
	if distribution == "flow" {
		raw, e := bpf.Assemble(packetFlowSteering())
		if e != nil {
			err = e
			return
		}
		filter := make([]unix.SockFilter, len(raw))
		for i, ins := range raw {
			filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		err = unix.SetsockoptSockFprog(fd, unix.SOL_PACKET, unix.PACKET_FANOUT_DATA, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]})
	}
	return
}

// Fanout runs on the network-layer skb before tpacket_rcv restores Ethernet.
// IPv4 includes options. The first four IP payload bytes are the
// tunnel's port-shaped fields regardless of the enclosing IP protocol number.
// Fold high bits down before multiplication so source ports vary across queues
// even when the queue count is a power of two and the destination port is fixed.
// Short/malformed loads return zero in cBPF; the normal capture filter rejects
// malformed packets and noninitial fragments on every member socket.
func packetFlowSteering() []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadMemShift{Off: 0},
		bpf.LoadIndirect{Off: 0, Size: 4},
		bpf.StoreScratch{Src: bpf.RegA, N: 0},
		bpf.LoadAbsolute{Off: 12, Size: 4}, bpf.TAX{},
		bpf.LoadAbsolute{Off: 16, Size: 4}, bpf.ALUOpX{Op: bpf.ALUOpXor}, bpf.TAX{},
		bpf.LoadScratch{Dst: bpf.RegA, N: 0}, bpf.ALUOpX{Op: bpf.ALUOpXor},
		bpf.TAX{}, bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 16}, bpf.ALUOpX{Op: bpf.ALUOpXor},
		bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 0x85ebca6b},
		bpf.TAX{}, bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 13}, bpf.ALUOpX{Op: bpf.ALUOpXor},
		bpf.RetA{},
	}
}

func newTunnelWorkers(iface string, proto uint8, mac net.HardwareAddr, localIP net.IP, port uint16, client bool) (_ []tunnelWorker, err error) {
	if err = validatePacketWorkers(*backend, *packetWorkers, *packetDistribution); err != nil {
		return nil, err
	}
	var workers []tunnelWorker
	defer func() {
		if err != nil {
			closeTunnelWorkers(workers)
		}
	}()
	fd, id, kind := -1, uint16(0), afpacket.FanoutCBPF
	if *packetWorkers > 1 {
		fd, id, kind, err = openPacketFanout(iface, *packetDistribution)
		if err != nil {
			return nil, fmt.Errorf("create packet fanout: %w", err)
		}
		defer unix.Close(fd)
	}
	for i := 0; i < *packetWorkers; i++ {
		rx, tx, e := newTunnelIO(iface, proto, mac, localIP, port, client)
		if e != nil {
			return nil, e
		}
		workers = append(workers, tunnelWorker{rx, tx})
		if fd >= 0 {
			if err = rx.(*afpacketReceiver).socket.SetFanout(kind, id); err != nil {
				return nil, fmt.Errorf("join packet fanout worker %d: %w", i, err)
			}
		}
	}
	log.Printf("packet receive workers=%d distribution=%s ring-mb-per-worker=%d", len(workers), *packetDistribution, *ringMB)
	return workers, nil
}
