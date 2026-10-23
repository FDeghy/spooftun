# spooftun

A high-throughput Linux UDP tunnel that carries traffic under a configurable
**custom IP protocol number** using a TPACKET_V3 `AF_PACKET` receive ring and
batched `sendmmsg` on send-only `AF_PACKET` sockets for transmit, bypassing the kernel IP stack. It supports
source-IP spoofing, a per-flow NAT layer, and optional obfuscation via fake
TCP-shaped framing and fake IP fragmentation.

## How it works

```
                    custom IP proto (default 200), raw AF_PACKET frames
  app ──UDP──▶ client ═══════════════════════════════════════════▶ server ──UDP──▶ 127.0.0.1:<target-port>
             (-listen)                                                            (local service)
  app ◀─UDP── client ◀═══════════════════════════════════════════ server ◀─UDP── (service reply)
```

- The **client** binds a local UDP socket (`-listen`) that applications send to.
  Each distinct client `IP:port` is mapped to a 16-bit virtual port by the NAT
  table. Each datagram is wrapped in a raw `Ethernet + IPv4 + fake UDP/TCP`
  frame under the custom IP protocol number and sent via `AF_PACKET`.
- The **server** captures those frames (filtered in-kernel by BPF), unwraps
  them, and forwards the inner payload to `127.0.0.1:<target-port>`. Replies
  from the local service are wrapped back into tunnel frames and returned to the
  client, which delivers them to the originating application socket.

AF_PACKET receives frames before normal IP processing. Copies can still reach the host IP stack; the tunnel itself parses cosmetic transport framing directly.

## Requirements

- **Linux** (the whole program is behind a `//go:build linux` tag).
- **Root** / `CAP_NET_RAW` + `CAP_NET_ADMIN` — required to open `AF_PACKET`
  sockets and attach BPF filters.
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

## Flags

| Flag | Default | Applies to | Description |
|------|---------|-----------|-------------|
| `-mode` | `client` | both | `client` or `server`. |
| `-remote-ip` | *(empty)* | client (required), server (optional) | Remote tunnel endpoint IP. On the server it fixes the downlink destination; if empty the server auto-detects it per session from incoming packets. |
| `-listen` | `127.0.0.1:1001` | client | Local UDP address applications send to. |
| `-target-port` | `8080` | client (forward port), server (BPF narrowing) | Port the payload is delivered to on the server's loopback. On the client it is encoded into every uplink frame; on the server it is only used to narrow the BPF filter when `-proto` is 6/17. |
| `-proto` | `200` | both | Custom IP protocol number (0–255) for both directions. |
| `-uplink-proto` | `-1` | both | IP protocol for client→server packets. Overrides `-proto` for that direction; `-1` inherits `-proto`. |
| `-downlink-proto` | `-1` | both | IP protocol for server→client packets. Overrides `-proto` for that direction; `-1` inherits `-proto`. |
| `-iface` | *(auto)* | both | Network interface for `AF_PACKET`. Auto-detected from the route to `-remote-ip` if empty. |
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
| `tx.go` | Send-only AF_PACKET socket for server replies. |
| `offload.go` | UDP GSO/GRO helpers (scaffolding, currently disabled). |

## Notes & limitations

- **Tunnel MTU**: oversized application datagrams are dropped whole, never forwarded after truncation. At MTU 1500, client payload limits are 1472 bytes (UDP), 1471 (UDP + fake frag), 1460 (fake TCP), and 1459 (fake TCP + fake frag). The limit is capped by the selected interface MTU. Fake fragmentation applies only to uplink.
- **Custom protocol delivery**: because frames are also seen by the host stack
  as an unknown IP protocol, you may want a firewall rule to drop them on the
  local stack so the OS doesn't emit ICMP protocol-unreachable replies.
- **`-fake-tcp` and stateful firewalls**: the fake TCP segments carry static
  sequence/ack values and no handshake, so a stateful TCP inspector may mark
  them invalid. It only helps against stateless DPI.

## Performance and validation

RX retains a zero-copy TPACKET_V3 ring. TX batches packets already returned by
UDP recvmmsg; it never waits to fill a batch. Both endpoints reuse separate
serialization buffers per queued frame. Per-session UDP reads use 16 slots
instead of 64 (about 24 KB vs 94 KB payload storage at MTU 1500), plus reusable
TX buffers. GRO/GSO remain disabled pending segmentation/checksum validation.

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
go test -run '^$' -bench 'BenchmarkPacketSender|BenchmarkNat' -benchmem .
```

The namespace suite changes only temporary veth interfaces and namespaces, and
removes its own processes/network on exit. Measurements are local one-flow echo
results, not Internet bandwidth. See [PERFORMANCE.md](PERFORMANCE.md) for measured
results and raw packet I/O alternatives.

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
