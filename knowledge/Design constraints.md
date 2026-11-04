# Design constraints

## Wire and deployment

- The tunnel is IPv4 over Ethernet and Linux-only. Source spoofing still depends on upstream policy and a valid return path; changing source bytes does not provide routing.
- Peers must agree on directional IP protocols and UDP/TCP framing. Fake fragmentation is client uplink only and requires matching server parsing. It pads the first fragment and emits a cosmetic tail; this is not general-purpose fragmentation/reassembly.
- Fake TCP has static sequence/ack fields and no handshake, retransmission or congestion-control layer. Stateful inspectors can reject it. The wrapper provides no authentication or encryption; use an authenticated inner protocol such as WireGuard when needed.
- `-mtu` budgets the outer IPv4 packet and is capped to interface MTU; it does not discover path MTU. UDP/TCP framing and fake-fragment padding reduce application payload capacity. On a verified 1500-byte path, the documented WireGuard starting point is MTU 1420 on both peers with spooftun MTU 1500.
- AF_PACKET does not consume frames before the host stack. Protocol 6/17 can trigger TCP resets or direct UDP delivery alongside the forwarder. Apply narrowly scoped ingress isolation from the deployment guide and keep the tunnel port separate from the local target using `-outbound-port`. Noise filtering in Go cannot stop host-stack delivery.

Sources: [framing.go](../framing.go), [encoder.go](../encoder.go), [client.go](../client.go), [server.go](../server.go), [README.md](../README.md#kernel-processing-of-tunnel-frames), [WIREGUARD.md](../WIREGUARD.md).

## Datagrams, buffers and concurrency

- RX frames are borrowed. A single frame is valid until the next read; batch views until the next backend receive or close. Copy retained addresses and asynchronous payloads before advancing.
- AF_PACKET delivery copies into a bounded queue; XDP delivery flushes borrowed payloads before recycling the receive batch. Flush available work without waiting for a full batch, including sparse tails and read-error paths.
- UDP GRO must split coalesced input back into complete datagrams. Truncated/oversize input is dropped as a whole. UDP GSO groups only compatible messages and falls back when unsupported; it must preserve datagram boundaries.
- Ring slots/UMEM cannot be reused while owned by the kernel. Partial sends and completion publication matter; noise-once state tracks accepted frames rather than attempted writes.
- Session refresh and retirement must compete atomically; concurrent first packets must not duplicate server sockets. Keep these guarantees when changing worker distribution or cleanup.

Sources: [packet_io.go](../packet_io.go), [local_delivery.go](../local_delivery.go), [local_forwarder.go](../local_forwarder.go), [udp_receive.go](../udp_receive.go), [local_udp.go](../local_udp.go), [xdp.go](../xdp.go), [tx_ring.go](../tx_ring.go), [noise.go](../noise.go), [nat.go](../nat.go), [server.go](../server.go).

## Performance evidence

Performance records describe particular hosts/configurations. More workers can regress throughput. Recorded tests do not establish loss-free gigabit WireGuard, hardware zero-copy or WAN capacity.

Sources: [PERFORMANCE.md](../PERFORMANCE.md), [test-results/ubuntu-2026-10-30-multiqueue/README.md](../test-results/ubuntu-2026-10-30-multiqueue/README.md). Related: [[Development]], [[Flows and sessions]].
