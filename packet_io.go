//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/gopacket/gopacket/afpacket"
)

// ReadPacket returns a view valid until the next ReadPacket call.
type packetReceiver interface {
	ReadPacket() ([]byte, error)
	Close() error
}

type packetTransmitter interface {
	WriteBatch([][]byte) (int, error)
	Close() error
}

type afpacketReceiver struct{ socket *afpacket.TPacket }

func (r *afpacketReceiver) ReadPacket() ([]byte, error) {
	for {
		frame, _, err := r.socket.ZeroCopyReadPacketData()
		if errors.Is(err, afpacket.ErrTimeout) {
			continue
		}
		return frame, err
	}
}
func (r *afpacketReceiver) Close() error { r.socket.Close(); return nil }

func newTunnelIO(iface string, proto uint8, mac net.HardwareAddr, localIP net.IP, port uint16, isClient bool) (packetReceiver, packetTransmitter, error) {
	if *backend == "xdp" {
		return newXDPIO(iface, proto, mac, localIP, port, isClient)
	}
	rx, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(afBlockSize),
		afpacket.OptNumBlocks(afNumBlocks),
		afpacket.OptFrameSize(afFrameSize),
		afpacket.OptBlockTimeout(afBlockTimeout),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open AF_PACKET RX: %w", err)
	}
	if err = rx.SetBPF(createBPFFilter(proto, mac, *fakeFrag, localIP, port, isClient)); err != nil {
		rx.Close()
		return nil, nil, fmt.Errorf("attach capture filter: %w", err)
	}
	var tx packetTransmitter
	if *afpacketTX == "ring" {
		var mtu int
		mtu, err = effectiveMTU(iface)
		if err == nil {
			tx, err = newTXRingSender(iface, mtu)
		}
	} else {
		tx, err = newPacketSender(iface)
	}
	if err != nil {
		rx.Close()
		return nil, nil, fmt.Errorf("open AF_PACKET TX: %w", err)
	}
	log.Printf("packet backend=afpacket tx=%s", *afpacketTX)
	return &afpacketReceiver{socket: rx}, tx, nil
}
