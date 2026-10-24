//go:build linux

package main

import (
	"log"
	"net"
	"net/netip"
)

// Two batches bound buffering and memory. Every queued payload is owned by
// this forwarder: raw packet ring views must not outlive the next receive.
const localForwardQueueSize = batchSize * 2

type localUDPSlot struct {
	message localUDPMessage
	storage []byte
}

type localUDPForwarder struct {
	maxPayload int
	free       chan *localUDPSlot
	ready      chan *localUDPSlot
	done       chan struct{}
}

func newLocalUDPForwarder(maxPayload int) *localUDPForwarder {
	f := &localUDPForwarder{
		maxPayload: maxPayload,
		free:       make(chan *localUDPSlot, localForwardQueueSize),
		ready:      make(chan *localUDPSlot, localForwardQueueSize),
		done:       make(chan struct{}),
	}
	storage := make([]byte, maxPayload*localForwardQueueSize)
	slots := make([]localUDPSlot, localForwardQueueSize)
	for i := range slots {
		slots[i].storage = storage[i*maxPayload : (i+1)*maxPayload : (i+1)*maxPayload]
		f.free <- &slots[i]
	}
	go f.run()
	return f
}

// Send and Close have one producer, the raw receive loop. Backpressure bounds
// memory rather than accumulating an unbounded queue of stale datagrams.
func (f *localUDPForwarder) Send(conn *net.UDPConn, addr netip.AddrPort, payload []byte) bool {
	if len(payload) > f.maxPayload {
		return false // Drop the whole datagram rather than forward a truncation.
	}
	slot := <-f.free
	n := copy(slot.storage, payload)
	slot.message = localUDPMessage{conn: conn, addr: addr, payload: slot.storage[:n]}
	f.ready <- slot
	return true
}

func (f *localUDPForwarder) Close() {
	close(f.ready)
	<-f.done
}

func (f *localUDPForwarder) run() {
	defer close(f.done)
	writer := newLocalUDPWriter()
	var messages [batchSize]localUDPMessage
	var slots [batchSize]*localUDPSlot
	for first := range f.ready {
		slots[0], messages[0] = first, first.message
		n := 1
	drain:
		for n < len(slots) {
			select {
			case slot, ok := <-f.ready:
				if !ok {
					break drain
				}
				slots[n], messages[n] = slot, slot.message
				n++
			default:
				break drain // Flush immediately; never wait to fill a batch.
			}
		}
		for sent := 0; sent < n; {
			written, err := writer.WriteBatch(messages[sent:n])
			sent += written
			if err != nil {
				log.Printf("Local UDP batch: %v", err)
				// One failed session must not discard another session's data.
				sent++
			} else {
				break
			}
		}
		for i := 0; i < n; i++ {
			slot := slots[i]
			slot.message = localUDPMessage{}
			messages[i], slots[i] = localUDPMessage{}, nil
			f.free <- slot
		}
	}
}
