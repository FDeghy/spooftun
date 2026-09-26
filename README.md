# spooftun

A high-throughput Linux UDP tunnel that carries traffic under a configurable
**custom IP protocol number** using a TPACKET_V3 `AF_PACKET` receive ring and
raw `AF_PACKET` writes for transmit, bypassing the kernel IP stack. It supports
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

Because both ends use `AF_PACKET`, the packets never traverse the host IP stack,
and the transport header is purely cosmetic framing (the kernel never parses it).

## Requirements

- **Linux** (the whole program is behind a `//go:build linux` tag).
- **Root** / `CAP_NET_RAW` + `CAP_NET_ADMIN` — required to open `AF_PACKET`
  sockets and attach BPF filters.
- **libpcap** (with headers, e.g. `libpcap-dev`) — the BPF capture filter is
  compiled at runtime via cgo, so libpcap is needed to both build and run.

## Build

```sh
go build -o spooftun .
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

- **Tunnel MTU**: the read buffers are sized for a single ~1500-byte Ethernet
  frame after encapsulation. Applications should keep datagrams within the
  tunnel MTU; oversized datagrams are truncated.
- **Custom protocol delivery**: because frames are also seen by the host stack
  as an unknown IP protocol, you may want a firewall rule to drop them on the
  local stack so the OS doesn't emit ICMP protocol-unreachable replies.
- **`-fake-tcp` and stateful firewalls**: the fake TCP segments carry static
  sequence/ack values and no handshake, so a stateful TCP inspector may mark
  them invalid. It only helps against stateless DPI.
