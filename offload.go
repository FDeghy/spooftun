//go:build linux

package main

import "golang.org/x/net/ipv4"

// Keep separate datagram buffers for recvmmsg. UDP GRO remains disabled: every
// message is one datagram, and an extra byte detects oversized input intact.
func prepareMsgsUDP() []ipv4.Message {
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, *tunnelMTU+1)}
	}
	return msgs
}
