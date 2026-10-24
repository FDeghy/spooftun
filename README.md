# spooftun

A Linux UDP tunnel that carries traffic under a configurable **custom IP
protocol number**. Choose AF_PACKET (TPACKET_V3 receive with sendmmsg or TX-ring
transmit) or AF_XDP (eBPF redirect with automatic zero-copy/copy selection).
It supports source-IP spoofing, per-flow NAT, fake TCP-shaped framing and
fake IP fragmentation.

## How it works

```
                    custom IP proto (default 200), raw Ethernet frames
  app ──UDP──▶ client ═══════════════════════════════════════════▶ server ──UDP──▶ 127.0.0.1:<target-port>
             (-listen)                                                            (local service)
  app ◀─UDP── client ◀═══════════════════════════════════════════ server ◀─UDP── (service reply)
```

- The **client** binds a local UDP socket (`-listen`) that applications send to.
  Each distinct client `IP:port` is mapped to a 16-bit virtual port by the NAT
  table. Each datagram is wrapped in a raw `Ethernet + IPv4 + fake UDP/TCP`
  frame under the custom IP protocol number and sent through the selected backend.
- The **server** receives those frames (filtered by classic BPF or XDP), unwraps
  them, and forwards the inner payload to `127.0.0.1:<target-port>`. Replies
  from the local service are wrapped back into tunnel frames and returned to the
  client, which delivers them to the originating application socket.

AF_PACKET receives frames before normal IP processing. Copies can still reach the host IP stack; the tunnel itself parses cosmetic transport framing directly.

## Requirements

- **Linux** (the whole program is behind a `//go:build linux` tag).
- **Root** is recommended for setup and the test scripts. AF_PACKET needs
  `CAP_NET_RAW`; AF_XDP also needs permission to load and attach eBPF/XDP
  programs. See [backend requirements](PACKET_BACKENDS.md#selection-and-lifecycle).
- **Go 1.27.3** to build. Classic BPF is assembled in Go; libpcap and cgo are not required.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -o spooftun .
```

## Usage

Run the service you want to expose on the server's loopback (e.g. on
`127.0.0.1:8080`), then:

**Server**

```sh
sudo ./spooftun -mode server -proto 200
```

**Client**

```sh
sudo ./spooftun -mode client -remote-ip <SERVER_IP> \
    -listen 127.0.0.1:1001 -target-port 8080 -proto 200
```

Applications now send UDP to `127.0.0.1:1001` on the client and reach
`127.0.0.1:8080` on the server.

> The tunnel-shaping flags must be **identical on both ends**: `-proto`
> (and `-uplink-proto` / `-downlink-proto`), `-fake-tcp`, and `-fake-frag`.
> A mismatch means one side won't recognize the other's frames.

## WireGuard over spooftun

For WireGuard sending to spooftun's local UDP listener, start with **WireGuard
MTU 1420 on both peers** when the physical path MTU is 1500. Keep spooftun
`-mtu 1500`; its setting controls the outer IPv4 packet, not the WireGuard
interface. This budget also fits `-fake-tcp -fake-frag` on a 1500-byte path.

See [WIREGUARD.md](WIREGUARD.md) for setup, padding arithmetic, smaller-path
MTUs, and diagnosing high CPU or low iperf3 throughput. Reducing MTU alone is
not a solution to a packet-processing bottleneck.

## Flags

| Flag | Default | Applies to | Description |
|------|---------|-----------|-------------|
| `-mode` | `client` | both | `client` or `server`. |
| `-backend` | `afpacket` | both | `afpacket` or `xdp`; independent of the peer's backend. |
| `-afpacket-tx` | `sendmmsg` | AF_PACKET | `sendmmsg` or `ring` (PACKET_TX_RING). Ignored by XDP. |
| `-ring-mb` | `16` | AF_PACKET | Receive-ring budget in MiB; does not set TX-ring or XDP UMEM size. |
| `-block-timeout` | `1ms` | AF_PACKET | TPACKET_V3 receive-block retirement delay. |
| `-mtu` | `1500` | both | Maximum outer IPv4 size, capped to interface MTU; does not discover path MTU. |
| `-session-timeout` | `1m` | server | Idle session lifetime, refreshed by either direction. |
| `-remote-ip` | *(empty)* | client (required), server (optional) | Remote tunnel endpoint IP. On the server it fixes the downlink destination; if empty the server auto-detects it per session from incoming packets. |
| `-listen` | `127.0.0.1:1001` | client | Local UDP address applications send to. |
| `-target-port` | `8080` | client (forward port), server (BPF narrowing) | Port the payload is delivered to on the server's loopback. On the client it is encoded into every uplink frame; on the server it is only used to narrow the BPF filter when `-proto` is 6/17. |
| `-proto` | `200` | both | Custom IP protocol number (0–255) for both directions. |
| `-uplink-proto` | `-1` | both | IP protocol for client→server packets. Overrides `-proto` for that direction; `-1` inherits `-proto`. |
| `-downlink-proto` | `-1` | both | IP protocol for server→client packets. Overrides `-proto` for that direction; `-1` inherits `-proto`. |
| `-iface` | *(auto)* | both | Physical Ethernet interface for the selected backend. Auto-detected from the route to `-remote-ip` if empty. |
| `-src-ip` | *(auto)* | both | Force a specific source IP (spoofing). Defaults to the interface IP. |
| `-filter-dst-ip` | *(empty)* | both | Destination IP for the BPF capture filter (TCP/UDP protos only). Use when `-src-ip` is spoofed and the on-wire destination differs from it; defaults to `-src-ip`. |
| `-fake-tcp` | `false` | both | Use a TCP-shaped header instead of UDP for tunnel framing. Must match on both ends. |
| `-tcp-flags` | `0x18` | both | TCP flag byte (hex or decimal) used with `-fake-tcp`, e.g. `0x18`=PSH+ACK, `0x10`=ACK, `0x02`=SYN. |
| `-fake-frag` | `false` | both | Shape client uplink packets as IP fragments (with a decoy trailing fragment). Must be enabled on both ends: the client emits them, the server strips the padding. |

### Direction terminology

- **Uplink** = client → server.
- **Downlink** = server → client.

`-proto` sets both directions; `-uplink-proto` / `-downlink-proto` let you use a
different protocol number per direction (useful when a middlebox treats the two
directions asymmetrically).

## File layout

All files are `package main` under the `//go:build linux` constraint.

| File | Responsibility |
|------|----------------|
| `main.go` | Entrypoint `main()`: flag parsing, interface/ring setup, mode dispatch. |
| `config.go` | Flag definitions, tuning constants, runtime AF_PACKET receive-ring config, coarse clock. |
| `nat.go` | Client-side NAT table mapping `client IP:port` ↔ virtual port. |
| `netutil.go` | Interface / ARP / default-route discovery and ring-buffer sizing. |
| `framing.go` | Fixed-offset Ethernet/IPv4 parsing plus fake UDP/TCP and fragmentation framing. |
| `bpf.go` | In-kernel BPF capture filter and filter-IP resolution. |
| `client.go` | Client data path (app → tunnel and tunnel → app). |
| `server.go` | Server data path (tunnel → target and target → tunnel). |
| `packet_io.go` | Shared RX/TX interfaces and backend selection. |
| `tx.go` | Send-only AF_PACKET sendmmsg transmitter for either endpoint. |
| `tx_ring.go` | Dedicated TPACKET_V2 mmap transmit ring. |
| `xdp.go` | AF_XDP sockets, UMEM ownership, fallback and resource lifecycle. |
| `xdp_filter.go` | eBPF tunnel redirect filter; unrelated traffic passes. |
| `offload.go` | Reusable local UDP receive-batch buffers. |
| `local_udp.go` | Local UDP sendmmsg/GSO writes, fallback, and socket-buffer verification. |
| `local_forwarder.go` | Bounded local-delivery queue with owned packet storage. |
| `encoder.go` | Fixed Ethernet/IPv4/UDP/TCP encoding with precomputed checksum sums. |

## Notes & limitations

- **Tunnel MTU**: oversized application datagrams are dropped whole, never forwarded after truncation. At MTU 1500, client payload limits are 1472 bytes (UDP), 1471 (UDP + fake frag), 1460 (fake TCP), and 1459 (fake TCP + fake frag). The limit is capped by the selected interface MTU. Fake fragmentation applies only to uplink.
- **Custom protocol delivery**: because frames are also seen by the host stack
  as an unknown IP protocol, you may want a firewall rule to drop them on the
  local stack so the OS doesn't emit ICMP protocol-unreachable replies.
- **`-fake-tcp` and stateful firewalls**: the fake TCP segments carry static
  sequence/ack values and no handshake, so a stateful TCP inspector may mark
  them invalid. It only helps against stateless DPI.

## Performance and validation

The AF_PACKET backend uses a TPACKET_V3 mmap receive ring. TX batches packets already returned by
UDP recvmmsg; it never waits to fill a batch. Both endpoints reuse separate
packet buffers per queued frame and encode fixed headers directly, preserving
wire compatibility and checksums. Per-session UDP reads use 16 slots
instead of 64 (about 24 KB vs 94 KB payload storage at MTU 1500), plus reusable
TX buffers.

Local UDP delivery on both endpoints uses a bounded 32-slot queue (about 48 KB
of payload storage at MTU 1500). It copies borrowed RX payloads before the next
packet-ring read, then sends up to 16 already-queued datagrams without waiting
to fill a batch. Compatible same-destination packets use UDP GSO; mixed lengths,
empty datagrams, and unsupported GSO use sendmmsg. Payload contents and datagram
boundaries are preserved. Local UDP receive GRO remains disabled.

Socket setup logs the requested and actual receive/send buffer sizes, including
Linux's doubled accounting values, and warns if the kernel caps the request.
The program does not change system-wide socket limits.

- `-ring-mb 16`: RX ring budget, separate from UDP socket buffers.
- `-block-timeout 1ms`: block retirement latency. Try 5ms for bulk traffic,
  measuring latency, CPU and packet loss; increasing it may add latency.
- `-mtu 1500`: maximum outer IP size, capped to interface MTU.
- `-session-timeout 1m`: server idle expiry, refreshed by either direction.

Application datagrams must fit the smaller MTU of the actual end-to-end path;
interface MTU alone cannot discover bottlenecks elsewhere. Route discovery uses
the selected interface's main IPv4 routing table; policy routing requires a
kernel netlink route lookup before it can be supported fully.

Run native Linux checks (race needs a C compiler, release builds do not):

```sh
go test ./...
go test -race ./...
go vet ./...
sudo bash scripts/netns-test.sh --benchmark
go test -run '^$' -bench 'BenchmarkPacketSender|BenchmarkNAT' -benchmem .
```

The namespace suite changes only temporary veth interfaces and namespaces, and
removes its own processes/network on exit. Measurements are local one-flow echo
results, not Internet bandwidth or maximum tunnel capacity. Both endpoints
and the Python applications share one 2-vCPU machine; the 128-request window
and three-second runs can constrain results. **1-Gbps tunneling has not been
demonstrated.** See [PERFORMANCE.md](PERFORMANCE.md) for measurement limits and
a two-host capacity-test plan.

### Kernel processing of tunnel frames

AF_PACKET capture does not consume packets. With protocol 17, normal UDP delivery
can duplicate tunnel replies into an application socket; protocol 6 can trigger
TCP resets. Use narrow ingress rules on BOTH endpoints to suppress normal kernel
processing of the tunnel traffic. For example, on a dedicated tunnel interface:

```sh
# Example only: substitute the actual interface and tunnel protocol.
# Do not broadly drop TCP on an interface carrying SSH.
sudo iptables -t raw -I PREROUTING -i tun0 -p 200 -j DROP
```

For protocol 17/6, restrict rules to peer/destination addresses and the tunnel
port and account for non-initial fake fragments. Apply firewall changes with
out-of-band access; the program never changes host firewall rules itself.
The test suite configures these rules only in disposable network namespaces.

## Packet backends

AF_PACKET remains the default. Both choices use the same tunnel wire format,
NAT, local UDP forwarding, MTU checks, and shaping flags.

```sh
# Existing receive path; choose the raw transmitter explicitly for comparison.
sudo ./spooftun -mode server -backend afpacket -afpacket-tx sendmmsg
sudo ./spooftun -mode server -backend afpacket -afpacket-tx ring

# AF_XDP on both endpoints; other tunnel flags must still match.
sudo ./spooftun -mode server -backend xdp -iface eth0
sudo ./spooftun -mode client -backend xdp -iface eth0 -remote-ip SERVER_IP
```

The XDP backend loads a small eBPF program and an XSK map in Go; no clang,
libbpf, or cgo is required. It tries native AF_XDP zero-copy first, native
copy second, and generic XDP copy last. The log reports the kernel's actual
mode, attachment type and queue count. Permission, verifier, memory-lock and
allocation errors remain explicit failures; they are not silently relabeled
as lack of NIC support.

An existing XDP program is never replaced. If another firewall, CNI or
monitoring program owns the interface, startup fails. Only matching tunnel
traffic is redirected; unrelated traffic passes to the network stack.
Use a dedicated tunnel protocol/port and review existing interface consumers
before enabling XDP. Successful XDP redirection consumes matching frames,
whereas AF_PACKET is a tap and still needs normal-stack isolation for
protocols 6/17.

Requirements and limits:

- Linux 5.9+ with AF_XDP, eBPF and bpf_link XDP support, and suitable privileges.
- Zero-copy additionally requires native NIC/driver support. Copy fallback
  cannot provide NIC zero-copy and may perform differently.
- One socket/UMEM per discovered RX queue, covering RSS queue distribution.
  Each queue allocates 4 MiB UMEM; ensure sufficient locked-memory allowance.
  TX uses queue zero; concurrent server writers are synchronized.
- Interface MTU must be at most 3826 for this single-buffer implementation.
  Jumbo/multi-buffer XDP is not supported.
- Changing interface queue configuration while running is not supported.
- Closing the backend detaches its own program and closes maps, sockets and
  mappings; it never pins programs or changes interface routes/firewall rules.

PACKET_TX_RING uses a separate send-only TPACKET_V2 mmap ring (~1 MiB).
A TX ring is not a guarantee of NIC zero-copy. The explicit sendmmsg option is
retained for comparison and rollback. sendmmsg remains the default because the
TX-ring benchmark was mixed across payload sizes. See [PACKET_BACKENDS.md](PACKET_BACKENDS.md)
for measured results and the backend decision.

Compare backends on isolated namespace interfaces:

```sh
sudo bash scripts/netns-test.sh --backend afpacket --afpacket-tx sendmmsg --bench-only --benchmark --iterations 3
sudo bash scripts/netns-test.sh --backend afpacket --afpacket-tx ring --bench-only --benchmark --iterations 3
sudo bash scripts/netns-test.sh --backend xdp --bench-only --benchmark --iterations 3
sudo env SPOOFTUN_NETNS_TEST=1 go test -run TestNetworkNamespaceIntegration -v .
```
