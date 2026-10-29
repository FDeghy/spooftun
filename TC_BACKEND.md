# TC kernel rewrite backend

`-backend tc` moves packet transformation into kernel eBPF. Go loads the
programs, configures a dedicated veth pair, waits for shutdown and reports
kernel counters. There is no per-packet UDP receive/send loop in the spooftun
process. Kernel networking and eBPF still consume CPU; low Go process CPU does
not mean the whole forwarding path is free.

This is a separate backend from `-backend xdp`. AF_XDP redirects packets into
userspace. TC rewrites and redirects packets within the kernel:

```text
WireGuard UDP -> owned veth -> TC eBPF -> physical interface
physical interface -> TC eBPF -> owned veth -> WireGuard UDP
```

The first version supports one fixed IPv4 peer and one fixed local application
port per endpoint. Use both peers in TC mode for the documented setup.
AF_PACKET and AF_XDP remain available for dynamic local flows and other framing.

## Requirements and supported framing

- Linux 6.6 or later with TCX, eBPF and veth support; root for setup.
- Runtime tools: `ip`, `tc` and `ethtool`.
- An IPv4 Ethernet interface and a reachable fixed remote IPv4 address.
- Protocol 6 with `-fake-tcp`. Custom flags, including `0x06` (SYN + RST),
  and a configured spoofed source IP are supported.
- Outer MTU 80–1500, capped to the physical interface MTU. For WireGuard on a
  verified 1500-byte path, use outer MTU 1500 and WireGuard MTU 1420.

TC does not support noise, fake fragmentation, other IP protocols, IPv6,
IPv4 options, fragmented tunnel packets, automatic peer discovery or NAT
rebinding. It rejects `-noise`, `-fake-frag` and `-udp-gro` at startup.
The normal fake-TCP payload/header format is retained, but fixed port mapping
and the virtual endpoint differ from the userspace NAT/forwarder configuration.

## WireGuard setup with a spoofed source

Replace all uppercase placeholders and choose the actual Ethernet interface.
Both WireGuard interfaces need `ListenPort = 51820` and `MTU = 1420`, with
their usual keys, tunnel addresses and allowed IPs configured.

Start the server:

```sh
sudo ./spooftun -mode server -backend tc -iface eth0 \
    -remote-ip CLIENT_REAL_IP -tc-peer-src-ip SPOOFED_CLIENT_IP \
    -tc-local-port 51820 -tc-peer-port 51820 -target-port 40000 \
    -proto 6 -fake-tcp -tcp-flags 0x06 -mtu 1500
```

Start the client:

```sh
sudo ./spooftun -mode client -backend tc -iface eth0 \
    -remote-ip SERVER_IP -src-ip SPOOFED_CLIENT_IP \
    -filter-dst-ip CLIENT_REAL_IP -tc-local-port 51820 -target-port 40000 \
    -proto 6 -fake-tcp -tcp-flags 0x06 -mtu 1500
```

After both log `packet backend=tc ready`, set the client's WireGuard peer:

```ini
[Peer]
Endpoint = 198.18.0.2:40000
```

The server learns the client as `198.18.0.2:51820`. Its actual wire replies
still go to `CLIENT_REAL_IP`, while its incoming filter expects
`SPOOFED_CLIENT_IP`. Without source spoofing, omit client `-src-ip` and
`-filter-dst-ip`, and omit server `-tc-peer-src-ip`.

**Do not use `127.0.0.1:1001` as the WireGuard endpoint in TC mode.** There is
no spooftun UDP listener. `-listen` is unused. A generic local UDP application
must bind the configured fixed port on `0.0.0.0` or `198.18.0.1`, rather than
loopback, and send to the virtual peer endpoint. An optional server
`-outbound-port` must equal `-tc-local-port`; it does not create a forwarder.

The default `-tc-address 198.18.0.1/30` gives the numbered veth endpoint `.1`.
The synthetic peer is `.2`, with a permanent neighbor entry, but `.2` is
deliberately not assigned to an interface. Both machines can use this same
private subnet because it is local to each network namespace. If the subnet
is already routed or in use, choose an unused IPv4 network+1 `/30` on that
machine and update its application's endpoint to network+2. Startup refuses
overlap with existing non-default routes. Keep the real remote endpoint
reachable through the physical interface when configuring full-tunnel routes.

## Offloads and packet handling

The backend disables transmit checksum/segmentation and receive coalescing
offloads only on its own veth pair. Linux completes checksum/segmentation work
before the TC ingress rewrite. This prevents stale UDP checksum offsets or
segmentation metadata from being used after conversion to fake TCP.
Physical NIC offload settings are unchanged.

The virtual link MTU is outer MTU minus 12 bytes, reserving the UDP-to-TCP
header expansion. Oversize or malformed matching packets are rejected;
unrelated traffic is passed. Incremental checksum conversion preserves payload
corruption as an invalid UDP checksum, which the destination UDP stack rejects.

Kernel WireGuard is exercised through this path. A generic application using
`UDP_SEGMENT` directly may receive `EIO` on the dedicated link and must fall
back to ordinary UDP sends/sendmmsg. Do not assume every userspace GSO sender
is compatible just because WireGuard works.

The remote or gateway MAC is resolved at startup and stored in the BPF
configuration. Restart the backend if that MAC or routing changes. The fixed
peer address and port checks do not automatically adapt to NAT port changes
or additional peers. Fake TCP still has no real TCP handshake or retransmission
layer; arbitrary static flags may not traverse stateful TCP inspection.

## Ownership and shutdown

Startup refuses a physical interface with an existing XDP attachment, legacy
TC ingress filter or TCX ingress program. It does not replace those programs,
change host firewall rules, alter sysctls or modify physical NIC offloads.
Only its dedicated veth interfaces, address and neighbor entry are created.

SIGINT/SIGTERM prints `TC kernel packets tx=... rx=... dropped=...`, detaches
the owned links and removes the owned veth pair and its connected route.
After SIGKILL, kernel links disappear when the process descriptors close,
but the veth pair may remain. Once that process is gone, remove the exact
owned `stc...a` interface named in its startup log before restarting:

```sh
sudo ip link del dev EXACT_OWNED_VETH_NAME
```

Do not remove an interface merely because its name starts with `stc`.

## Build and test

The embedded little-endian BPF object is generated from `bpf/tc.c` and shipped
with the source. Normal Go builds and runtime need no C compiler, libbpf or
cgo. To regenerate the object on Linux with Clang 18's BPF target and Linux
UAPI headers:

```sh
CLANG=clang-18 sh scripts/build-tc-bpf.sh
CGO_ENABLED=0 go build -o spooftun .
```

Kernel verifier/rewrite tests and isolated namespace checks:

```sh
sudo env SPOOFTUN_TC_TEST=1 go test -run 'TestTC' -v .
sudo python3 scripts/test-tc.py --binary ./spooftun --output tc-correctness
```

Real WireGuard capacity tests require `wg`, `iperf3`, Python 3 and the tools
above. The output directory must not already exist:

```sh
sudo python3 scripts/bench-wireguard.py --binary ./spooftun \
    --path tc --output tc-forward --seconds 30 \
    --proto 6 --tcp-flags 0x06 --spoof
# Repeat with a fresh output directory and --reverse.
```

These scripts create disposable network namespaces and veth devices. They do
not attach programs to production interfaces. Both endpoints share the test
machine, so results are not a physical-link or WAN bandwidth guarantee. Read
host CPU/softirq alongside throughput and loss; spooftun process CPU alone
excludes the new kernel forwarding work.

## Measurements on the two-vCPU test server

Real kernel WireGuard and TCP iperf3, 30 seconds per run, MTU 1420,
spoofed client source and flags `0x06`, both endpoints on one Xeon E5-2670 v2 VM:

| Backend | Direction | Received Mbps |
|---|---|---:|
| AF_XDP with local UDP GRO | Forward | 375.67 |
| TC kernel rewrite | Forward | 777.29 |
| TC kernel rewrite | Reverse | 752.80 |

At a requested TCP pacing rate of 300 Mbps, two comparisons reversed the order
of the backends. AF_XDP delivered 299.94/298.00 Mbps and consumed 56.02/55.71
host CPU-seconds; TC delivered 299.99/299.99 Mbps and consumed 49.74/49.36
host CPU-seconds. That is about **11% less total host CPU time** at approximately
equal throughput in these runs. Host CPU includes WireGuard, iperf3, kernel
networking and other activity, and excludes idle, iowait and steal. It cannot
isolate eBPF's cost. These are two comparisons, not a broad statistical study.

The two Go processes together used 0.09–0.11 CPU-seconds with TC versus
19.77–20.06 with AF_XDP in the paced runs. Most packet work now runs in the
kernel; the much smaller host-wide reduction is the relevant CPU comparison.
The capacity runs were CPU-saturated and were not paced. They show a substantial
improvement on this host, **not a demonstrated 1-Gbps WireGuard tunnel**.

Validation includes native race tests, kernel verifier/packet-rewrite tests,
real UDP socket rejection of corrupted TCP checksums, empty/odd/MTU datagrams,
explicit GSO capability fallback, wire capture of spoofing/flags/checksums,
unrelated traffic, existing-owner protection and cleanup of owned interfaces.
No hardware zero-copy or production-interface tests were performed.

Full receiver reports, kernel counters, environment and tested source/binary
hashes: [TC test evidence](test-results/ubuntu-2026-10-29-tc/).
