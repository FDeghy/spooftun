//go:build linux

package main

import (
	"net"
	"net/netip"
)

// localUDPDelivery couples a borrowed receive batch to local writes. XDP views
// are written before the next backend read can recycle them, avoiding the copy
// and channel handoff needed for AF_PACKET's single-frame lifetime. Parsing
// may discard frames: flushing at the next read also handles a skipped tail.
type localUDPDelivery struct {
	reader     *packetReader
	queued     *localUDPForwarder
	writer     *localUDPWriter
	maxPayload int
	messages   [batchSize]localUDPMessage
	n          int
}

func newLocalUDPDelivery(receiver packetReceiver, maxPayload int) *localUDPDelivery {
	d := &localUDPDelivery{reader: newPacketReader(receiver), maxPayload: maxPayload}
	if d.reader.batch == nil {
		d.queued = newLocalUDPForwarder(maxPayload)
	} else {
		d.writer = newLocalUDPWriter()
	}
	return d
}

func (d *localUDPDelivery) ReadPacket() ([]byte, error) {
	if d.reader.next == d.reader.n {
		d.flush()
	}
	return d.reader.ReadPacket()
}

// One Send per received packet; additional sends flush when the bounded array
// fills. The caller must leave the borrowed payload unchanged until flushed.
func (d *localUDPDelivery) Send(conn *net.UDPConn, addr netip.AddrPort, payload []byte) bool {
	if d.queued != nil {
		return d.queued.Send(conn, addr, payload)
	}
	if len(payload) > d.maxPayload {
		return false
	}
	if d.n == len(d.messages) {
		d.flush()
	}
	d.messages[d.n] = localUDPMessage{conn: conn, addr: addr, payload: payload}
	d.n++
	return true
}

func (d *localUDPDelivery) flush() {
	if d.n != 0 {
		writeLocalUDPBatch(d.writer, d.messages[:d.n])
		clear(d.messages[:d.n])
		d.n = 0
	}
}

func (d *localUDPDelivery) Close() {
	d.flush()
	if d.queued != nil {
		d.queued.Close()
	}
}
