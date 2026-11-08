# spooftun

A Linux UDP or routed TUN tunnel that carries traffic under a configurable **custom IP
protocol number**. Choose AF_PACKET (TPACKET_V3 receive with sendmmsg or TX-ring
transmit) or AF_XDP (eBPF redirect with automatic zero-copy/copy selection).
It supports source-IP spoofing, per-flow NAT, fake TCP-shaped framing and
fake IP fragmentation.

## How it works

```
                    custom IP proto (default 200), raw Ethernet frames
  app ──UDP──▶ client ═══════════════════════════════════════════▶ server ──UDP──▶ 127.0.0.1:<application-port>
             (-listen)                                                            (local service)
  app ◀─UDP── client ◀═══════════════════════════════════════════ server ◀─UDP── (service reply)
```

- The **client** binds a local UDP socket (`-listen`) that applications send to.
  Each distinct client `IP:port` is mapped to a 16-bit virtual port by the NAT
  table. Each datagram is wrapped in a raw `Ethernet + IPv4 + fake UDP/TCP`
  frame under the custom IP protocol number and sent through the selected backend.
- The **server** receives those frames (filtered by classic BPF or XDP), unwraps
  them, and forwards the inner payload to `127.0.0.1:<outbound-port>` when set,
  otherwise to the incoming tunnel destination port. Replies
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

## Routed TUN mode

Use `-tun <name> -tun-address <CIDR>` on both endpoints to carry complete
IPv4/IPv6 packets instead of local UDP datagrams. This creates a new,
nonpersistent Linux TUN interface and configures its address and MTU using `ip`.
It requires `CAP_NET_ADMIN` in addition to the packet backend's permissions.
Both endpoints require a fixed `-remote-ip`; the received outer source must
match that peer. TUN mode uses the existing unencrypted tunnel framing and
does not authenticate peers. Route only trusted traffic through it.

```sh
# Server (substitute the client's outer IPv4 address)
sudo ./spooftun -mode server -remote-ip <CLIENT_IP> \
  -tun sttun0 -tun-address 10.77.0.2/30 -packet-workers 2

# Client
sudo ./spooftun -mode client -remote-ip <SERVER_IP> \
  -tun sttun0 -tun-address 10.77.0.1/30 -packet-workers 2

ping 10.77.0.2
```

`-packet-workers` creates the same number of TUN queues and AF_PACKET workers,
each with its own packet buffers and transmitter. Sends drain up to 64 available
packets with one worker, or 16 per worker with multiple workers, without waiting
for a full batch. The default `flow`
distribution uses ports derived from inner flows; `spread` can reorder packets.
Checksums use portable 64-bit accumulation with end-around carry; the wire
format and packet validation remain the same. See the measured comparisons in
[the bandwidth tuning report](test-results/tun-bandwidth-2026-11-05/README.md).
XDP currently supports one worker, as in UDP mode. Existing interfaces are
rejected, and the new interface disappears when the process exits. Additional
routes and addresses are managed with normal `ip route` / `ip address` commands;
keep the outer peer reachable through the physical interface.

The TUN MTU is derived from `min(-mtu, physical interface MTU)`, subtracting
the outer IPv4 and cosmetic transport headers and reserving fake-fragment
padding when enabled. Both peers must use the same path MTU and framing flags.
For outer MTU 1500:

| Framing | TUN MTU |
| --- | ---: |
| UDP-shaped | 1472 |
| TCP-shaped | 1460 |
| UDP-shaped + fake fragments | 1471 |
| TCP-shaped + fake fragments | 1459 |

`-mtu` is an outer path budget; it does not discover path MTU. Set it lower
when the path requires it. IPv6 requires a derived MTU of at least 1280.
Fake fragmentation retains its existing client-uplink-only behavior.
`-noise`, `-udp-gro`, and `-outbound-port` are rejected in TUN mode.

Run the isolated correctness checks and repeated TCP benchmarks with:

```sh
sudo python3 scripts/bench-tun.py --binary ./spooftun --workers 1 --output /tmp/tun-one
sudo python3 scripts/bench-tun.py --binary ./spooftun --workers 2 --output /tmp/tun-two
sudo python3 scripts/bench-tun.py --binary ./spooftun --direct --output /tmp/tun-direct
```

The harness verifies IPv4/IPv6 MTU boundaries in both directions, records three
forward/reverse iperf3 runs with four streams and process CPU time, and removes
its namespaces afterward. Both peers share the test host; these are processing
benchmarks rather than WAN measurements. Use `--fake-tcp`, `--fake-frag`,
`--mtu`, or `--verify-only` for framing and smaller-MTU checks.

## WireGuard over spooftun

For WireGuard sending to spooftun's local UDP listener, start with **WireGuard
MTU 1420 on both peers** when the physical path MTU is 1500. Keep spooftun
`-mtu 1500`; its setting controls the outer IPv4 packet, not the WireGuard
interface. This budget also fits `-fake-tcp -fake-frag` on a 1500-byte path.

See [WIREGUARD.md](WIREGUARD.md) for setup, padding arithmetic, smaller-path
MTUs, and diagnosing high CPU or low iperf3 throughput. Reducing MTU alone is
not a solution to a packet-processing bottleneck.

## Flags

| Flag                   | Default          | Applies to                           | Description                                                                                                                                                        |
| ---------------------- | ---------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-mode`                | `client`         | both                                 | `client` or `server`.                                                                                                                                              |
| `-backend`             | `afpacket`       | both                                 | `afpacket` or `xdp`. |
| `-tun`                 | *(empty)*        | both                                 | Create a new multiqueue TUN interface instead of forwarding local UDP. |
| `-tun-address`         | *(empty)*        | TUN                                  | Interface address/prefix; requires `-remote-ip` on both peers. |
| `-udp-gro`             | `false`          | both                                 | Coalesce local UDP receives when supported, then preserve individual datagrams. Uses about 1 MiB of receive storage per local socket; see performance notes.       |
| `-afpacket-tx`         | `sendmmsg`       | AF_PACKET                            | `sendmmsg` or `ring` (PACKET_TX_RING). Ignored by XDP.                                                                                                             |
| `-packet-workers`      | `1`              | AF_PACKET                            | Receive workers, each owning an RX ring and transmitter (1–64).                                                                                                    |
| `-packet-distribution` | `flow`           | AF_PACKET                            | `flow` hashes visible tuples; `spread` distributes packets and may reorder them.                                                                                   |
| `-ring-mb`             | `16`             | AF_PACKET                            | Receive-ring budget in MiB; does not set TX-ring or XDP UMEM size.                                                                                                 |
| `-block-timeout`       | `1ms`            | AF_PACKET                            | TPACKET_V3 receive-block retirement delay.                                                                                                                         |
| `-mtu`                 | `1500`           | both                                 | Maximum outer IPv4 size, capped to interface MTU; does not discover path MTU.                                                                                      |
| `-session-timeout`     | `1m`             | server                               | Idle session lifetime, refreshed by either direction.                                                                                                              |
| `-remote-ip`           | *(empty)*        | client (required), server (optional) | Remote tunnel endpoint IP. On the server it fixes the downlink destination; if empty the server auto-detects it per session from incoming packets.                 |
| `-listen`              | `127.0.0.1:1001` | client                               | Local UDP address applications send to.                                                                                                                            |
| `-target-port`         | `8080`           | both                                 | Tunnel destination port encoded by the client; server capture port for protocols 6/17. Also the local application port unless the server sets `-outbound-port`.    |
| `-outbound-port`       | `0`              | server                               | Local UDP destination port on `127.0.0.1`. Zero preserves the incoming tunnel destination port. Replies retain the original tunnel port on the wire.               |
| `-noise`               | `false`          | both                                 | Send one marked noise packet before the first outgoing datagram of each flow. Requires UDP framing and outgoing protocol 17.                                       |
| `-noise-payload`       | *(empty)*        | noise sender                         | Standard Base64 content, padded or unpadded. Decoded bytes follow the internal 8-byte marker. Empty uses the default random content. Requires `-noise`.            |
| `-proto`               | `200`            | both                                 | Custom IP protocol number (0–255) for both directions.                                                                                                             |
| `-uplink-proto`        | `-1`             | both                                 | IP protocol for client→server packets. Overrides `-proto` for that direction; `-1` inherits `-proto`.                                                              |
| `-downlink-proto`      | `-1`             | both                                 | IP protocol for server→client packets. Overrides `-proto` for that direction; `-1` inherits `-proto`.                                                              |
| `-iface`               | *(auto)*         | both                                 | Physical Ethernet interface for the selected backend. Auto-detected from the route to `-remote-ip` if empty.                                                       |
| `-src-ip`              | *(auto)*         | both                                 | Force a specific source IP (spoofing). Defaults to the interface IP.                                                                                               |
| `-filter-dst-ip`       | *(empty)*        | both                                 | Destination IP for the BPF capture filter (TCP/UDP protos only). Use when `-src-ip` is spoofed and the on-wire destination differs from it; defaults to `-src-ip`. |
| `-fake-tcp`            | `false`          | both                                 | Use a TCP-shaped header instead of UDP for tunnel framing. Must match on both ends.                                                                                |
| `-tcp-flags`           | `0x18`           | both                                 | TCP flag byte (hex or decimal) used with `-fake-tcp`, e.g. `0x18`=PSH+ACK, `0x10`=ACK, `0x02`=SYN.                                                                 |
| `-fake-frag`           | `false`          | both                                 | Shape client uplink packets as IP fragments (with a decoy trailing fragment). Must be enabled on both ends: the client emits them, the server strips the padding.  |

### Direction terminology

- **Uplink** = client → server.
- **Downlink** = server → client.

`-proto` sets both directions; `-uplink-proto` / `-downlink-proto` let you use a
different protocol number per direction (useful when a middlebox treats the two
directions asymmetrically).

## File layout

Go files are `package main` under the `//go:build linux` constraint.

| File | Responsibility |
|------|----------------|
| `main.go` | Entrypoint `main()`: flag parsing, interface/ring setup, mode dispatch. |
| `config.go` | Flag definitions, tuning constants, runtime AF_PACKET receive-ring config, coarse clock. |
| `nat.go` | Client-side NAT table mapping `client IP:port` ↔ virtual port. |
| `netutil.go` | Interface / ARP / default-route discovery and ring-buffer sizing. |
| `framing.go` | Fixed-offset Ethernet/IPv4 parsing plus fake UDP/TCP and fragmentation framing. |
| `bpf.go` | In-kernel BPF capture filter and filter-IP resolution. |
| `client.go` | Client data path (app → tunnel and tunnel → app). |
| `tun.go` | Multiqueue routed IP forwarding, inner-packet validation and automatic TUN MTU. |
| `server.go` | Server data path (tunnel → target and target → tunnel). |
| `packet_io.go` | Shared RX/TX interfaces and backend selection. |
| `tx.go` | Send-only AF_PACKET sendmmsg transmitter for either endpoint. |
| `tx_ring.go` | Dedicated TPACKET_V2 mmap transmit ring. |
| `xdp.go` | AF_XDP sockets, UMEM ownership, fallback and resource lifecycle. |
| `xdp_filter.go` | eBPF tunnel redirect filter; unrelated traffic passes. |
| `udp_receive.go` | Allocation-free local UDP recvmmsg, address decoding and optional GRO splitting. |
| `local_udp.go` | Local UDP sendmmsg/GSO writes, fallback, and socket-buffer verification. |
| `local_forwarder.go` | Bounded local-delivery queue with owned packet storage. |
| `encoder.go` | Fixed Ethernet/IPv4/UDP/TCP encoding with precomputed checksum sums. |
| `noise.go` | Optional first-datagram noise, receiver classification, and accepted-send tracking. |

## Notes & limitations

- **Tunnel MTU**: oversized application datagrams are dropped whole, never forwarded after truncation. At MTU 1500, client payload limits are 1472 bytes (UDP), 1471 (UDP + fake frag), 1460 (fake TCP), and 1459 (fake TCP + fake frag). The limit is capped by the selected interface MTU. Fake fragmentation applies only to uplink.
- **Custom protocol delivery**: because frames are also seen by the host stack
  as an unknown IP protocol, you may want a firewall rule to drop them on the
  local stack so the OS doesn't emit ICMP protocol-unreachable replies.
- **`-fake-tcp` and stateful firewalls**: the fake TCP segments carry static
  sequence/ack values and no handshake, so a stateful TCP inspector may mark
  them invalid. It only helps against stateless DPI.

## Noise before UDP data

Add `-noise` to whichever endpoint should send noise, using protocol 17 and UDP
framing (`-fake-tcp` must be off):

```sh
sudo ./spooftun -mode server -proto 17 -target-port 40000 -outbound-port 51820 -noise
sudo ./spooftun -mode client -proto 17 -target-port 40000 -remote-ip SERVER_IP -noise
```

The first datagram of each flow is preceded by one standalone UDP noise
datagram with the same source/destination addresses and ports. Later datagrams
in that session send no more noise. By default its 32-byte UDP payload contains
an 8-byte version marker and 24 pseudorandom bytes. The sender queues noise
before real data in the same transmit batch; network delivery can still lose
or reorder packets.
With `-fake-frag`, noise precedes the first datagram's real first fragment, not its final fake tail.
No traffic is generated while idle. Mixed directional protocol configurations
are supported when the enabled endpoint's outgoing protocol is 17.
Client noise state follows its NAT session; server noise precedes the first
reply of each server session. A new session after expiry can send noise again.

To supply noise content as Base64:

```sh
# aGVsbG8= decodes to the five bytes "hello".
sudo ./spooftun -mode client -proto 17 -target-port 40000 -remote-ip SERVER_IP \
    -noise -noise-payload 'aGVsbG8='
```

The resulting UDP payload is the 8-byte internal marker followed by `hello`.
The marker is retained so the peer can discard noise without knowing your
chosen content. Content may contain arbitrary binary bytes. Standard padded
and unpadded Base64 are supported; malformed input is rejected. The decoded
content plus marker must fit `min(-mtu, interface MTU) - 28` bytes, so at MTU
1500 the custom content limit is **1464 bytes**. It is checked before opening
packet sockets. This limit also applies with fake fragmentation, because the
noise packet itself is unfragmented.

Upgrade **both peers** before enabling noise or custom-length noise content.
Updated receivers discard the marked packets before NAT/session activity,
padding removal or local delivery, even if they do not enable `-noise`
themselves. Real-data framing and MTU limits
are unchanged. Noise uses the legal IPv4 UDP zero-checksum form plus its marker;
real tunnel data always carries a nonzero UDP checksum, so an application's
identical payload is preserved. See [RFC 768](https://www.rfc-editor.org/rfc/rfc768).

For AF_PACKET, retain the [ingress isolation rules](#kernel-processing-of-tunnel-frames)
on both endpoints: userspace discarding cannot prevent Linux from directly
delivering a matching noise UDP packet to an application. Separate server
`-outbound-port` and tunnel ports as shown above. Default noise adds one packet
and a 74-byte Ethernet frame (before FCS/preamble/link overhead) per enabled flow;
custom content changes the frame length. Noise increases packet-processing
and bandwidth costs and is disabled by default.

Wire-order and application-delivery checks are recorded in the
[noise validation results](test-results/ubuntu-2026-10-24-noise/) and
[Base64 content validation results](test-results/ubuntu-2026-10-25-noise-base64/).

## Performance and validation

The AF_PACKET backend uses a TPACKET_V3 mmap receive ring. TX batches packets already returned by
UDP recvmmsg; it never waits to fill a batch. Both endpoints reuse separate
packet buffers per queued frame and encode fixed headers directly, preserving
wire compatibility and checksums. Per-session UDP reads use 16 slots
instead of 64 (about 24 KB vs 94 KB payload storage at MTU 1500), plus reusable
TX buffers.

With AF_PACKET, local UDP delivery uses a bounded 32-slot queue (about 48 KB
of payload storage at MTU 1500). It copies borrowed RX payloads before the next
packet-ring read, then sends up to 16 already-queued datagrams. With XDP,
receive batches contain up to 16 available frames; local delivery writes their
borrowed payloads before the next batch read recycles those frames. This avoids
the intermediate payload copy and channel handoff on the XDP receive path.
Neither path waits to fill a batch. Compatible same-destination packets use UDP
GSO; other datagrams and unsupported GSO use sendmmsg. Payload contents and
datagram boundaries are preserved. Local UDP receives decode addresses directly
into reusable storage, avoiding per-packet address allocations.

Add `-udp-gro` to opt into Linux UDP receive coalescing. This can reduce receive
syscalls when the application emits GSO batches. It does not merge application
datagrams on the tunnel wire. Unsupported kernels fall back to ordinary
recvmmsg; startup logs report the actual choice. GRO uses about **1 MiB per
client listener and per active server reply session**, versus about 24 KB
without it at MTU 1500. It is therefore disabled by default. Either endpoint
can enable it independently. Fake-fragment padding uses separate reusable
storage so it cannot overwrite a neighboring GRO segment.

Socket setup logs the requested and actual receive/send buffer sizes, including
Linux's doubled accounting values, and warns if the kernel caps the request.
The program does not change system-wide socket limits.

AF_PACKET optionally supports worker-owned software receive queues. Add
`-packet-workers 2 -packet-distribution flow` to distribute visible flows using
custom BPF hashing, including protocol 200. `-packet-distribution spread` can
distribute one carrier flow but may reorder packets. The default is one worker;
ring memory scales with the worker count. See [multiqueue details](PACKET_BACKENDS.md#af_packet-software-multiqueue)
for ownership, backend limits and performance tradeoffs.

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
and three-second runs can constrain results. New native one-way and real
WireGuard tests are documented in [PERFORMANCE.md](PERFORMANCE.md#udp-receive-and-capacity-tests--2026-10-29).
Short spooftun-only runs exceeded 1 Gbps with packet loss; **loss-free 1 Gbps
and 1-Gbps WireGuard over spooftun have not been demonstrated**. See
[WIREGUARD.md](WIREGUARD.md#performance-profile-for-a-two-vcpu-vm) for the tested
configuration and the remaining CPU bottleneck.

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

For protocol 17 with UDP framing, use a separate server application port to
prevent the original tunnel UDP packet from reaching that application directly:

```sh
# Real application (for example WireGuard) listens on UDP 51820.
# Reserve UDP 40000 for tunnel traffic; no application should listen there.
sudo ./spooftun -mode server -proto 17 -target-port 40000 -outbound-port 51820
sudo ./spooftun -mode client -proto 17 -target-port 40000 \
    -remote-ip SERVER_IP -listen 127.0.0.1:1001
```

Only the server needs `-outbound-port`. The client still uses the tunnel port
40000; server replies also use source port 40000 so capture filters match.
Port separation prevents this server application from receiving the original
tunnel datagram, but AF_PACKET still allows Linux to process it. An unused
tunnel UDP port can generate ICMP port-unreachable responses. It also does not
suppress direct UDP delivery on the client or TCP resets with protocol 6;
retain appropriate ingress isolation. AF_XDP redirects matching packets away
from normal kernel delivery when redirection succeeds.

## Packet backends

AF_PACKET remains the default. AF_PACKET and AF_XDP use the same tunnel wire format,
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
