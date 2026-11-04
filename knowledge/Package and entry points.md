# Package and entry points

The module is `spooftun`; all Go sources belong to one Linux-only `package main`. File boundaries express responsibilities, not independently importable packages. There is no separate library or `cmd/` tree.

## Startup

`main()` parses flags, validates combinations, discovers the interface, sizes AF_PACKET rings and resolves directional protocols. Client/server mode selects `startClientAFPacket` or `startServerAFPacket`. Despite those names, both functions also support AF_XDP through the packet-I/O abstraction. See [[Flows and sessions]] and [[Packet backends]].

## Responsibility map

| Concern | Owning sources |
| --- | --- |
| CLI, defaults, tuning, coarse clock | [main.go](../main.go), [config.go](../config.go) |
| Client listener, uplink encoding, reply routing | [client.go](../client.go), [nat.go](../nat.go) |
| Server target sockets, concurrent session creation, reply workers | [server.go](../server.go) |
| IPv4 parsing, cosmetic transport headers, padding, MTU budget, wire encoding and checksums | [framing.go](../framing.go), [encoder.go](../encoder.go) |
| Per-flow marked noise and transmit acceptance tracking | [noise.go](../noise.go) |
| Backend selection, receive/transmit contracts, fanout workers | [packet_io.go](../packet_io.go), [packet_workers.go](../packet_workers.go) |
| Classic BPF capture and raw transmit implementations | [bpf.go](../bpf.go), [tx.go](../tx.go), [tx_ring.go](../tx_ring.go) |
| AF_XDP sockets, UMEM, rings and eBPF redirect filter | [xdp.go](../xdp.go), [xdp_filter.go](../xdp_filter.go) |
| UDP receive/GRO, local delivery, copy queue, sendmmsg/GSO | [udp_receive.go](../udp_receive.go), [local_delivery.go](../local_delivery.go), [local_forwarder.go](../local_forwarder.go), [local_udp.go](../local_udp.go) |
| Interface, route, neighbor discovery and ring sizing | [netutil.go](../netutil.go) |

Direct dependencies: cilium/ebpf for eBPF, gopacket for AF_PACKET and packet structures, x/net for BPF/IPv4 helpers, x/sys for Linux syscalls. Versions and toolchain requirement live in [go.mod](../go.mod). See [[Development]].
