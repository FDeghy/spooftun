# Flows and sessions

This path applies to AF_PACKET and AF_XDP: [[Packet backends]].

## Round trip

1. The client binds `-listen` (default `127.0.0.1:1001`) and reads local UDP batches. Each application IPv4 address/port maps to a 16-bit virtual source port.
2. The encoder wraps each datagram in Ethernet + IPv4 + UDP-shaped or TCP-shaped transport framing. `-target-port` is the wire destination port; the directional protocol setting becomes the outer IP protocol.
3. The server filters and parses incoming frames, discards marked noise and noninitial fragments, removes fake-fragment padding when enabled, and looks up a session by incoming source IPv4 + virtual source port.
4. Each new server session gets a connected UDP socket targeting `127.0.0.1:<wire destination port>`, or `-outbound-port` when set, plus one reply goroutine.
5. Replies retain the original tunnel port as their wire source port. The client reverses the virtual destination port into the originating application address and sends the payload through its listener socket.

Sources: [client.go](../client.go), [server.go](../server.go), [encoder.go](../encoder.go), [framing.go](../framing.go).

## State invariants

- Client NAT has a locked forward map and 65,536 atomic reverse slots. All virtual port values are identifiers; allocation scans for a free slot and reports exhaustion. Retained address bytes are copied.
- Client mappings idle for more than 60 seconds are eligible for cleanup, scanned every 30 seconds. This is separate from the server's configurable `-session-timeout` (default one minute).
- Server activity in either direction refreshes the idle lifetime. Concurrent creation rechecks under a mutex so spread workers create one target socket/reply goroutine per key. Retirement uses atomic state and identity-aware deletion so stale cleanup cannot delete a replacement.
- With no server `-remote-ip`, replies use the incoming source IP; an explicit value fixes their destination. Spoofing therefore needs an intentional return route.
- Noise state belongs to the session. It is marked sent only after the transmitter accepts the noise frame, and resets with a new session. Receivers discard recognized noise before session activity or delivery.

Sources: [nat.go](../nat.go), [server.go](../server.go), [noise.go](../noise.go). Regression evidence: [nat_test.go](../nat_test.go), [server_test.go](../server_test.go), [packet_workers_test.go](../packet_workers_test.go), [noise_test.go](../noise_test.go).

Buffer lifetime and framing obligations: [[Design constraints]]. Verification: [[Development]].
