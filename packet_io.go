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

// Batch views remain valid until the next backend receive call or Close.
// Receivers return available traffic immediately, never waiting to fill dst.
type packetBatchReceiver interface {
	ReadPacketBatch(dst [][]byte) (int, error)
}

// packetReader drains a borrowed batch before asking the backend for more.
// The forwarding loops finish parsing/copying each view before advancing.
// AF_PACKET keeps its existing one-packet lifetime and receive behavior.
type packetReader struct {
	receiver packetReceiver
	batch    packetBatchReceiver
	packets  [batchSize][]byte
	n, next  int
}

func newPacketReader(receiver packetReceiver) *packetReader {
	batch, _ := receiver.(packetBatchReceiver)
	return &packetReader{receiver: receiver, batch: batch}
}

func (r *packetReader) ReadPacket() ([]byte, error) {
	if r.batch == nil {
		return r.receiver.ReadPacket()
	}
	if r.next == r.n {
		clear(r.packets[:])
		n, err := r.batch.ReadPacketBatch(r.packets[:])
		if err != nil {
			return nil, err
		}
		if n <= 0 || n > len(r.packets) {
			return nil, fmt.Errorf("invalid packet receive batch size: %d", n)
		}
		r.n, r.next = n, 0
	}
	packet := r.packets[r.next]
	r.packets[r.next] = nil
	r.next++
	return packet, nil
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
