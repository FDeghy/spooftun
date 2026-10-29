# WireGuard over spooftun

## Topology and starting MTU

This guide assumes the WireGuard client's UDP endpoint is spooftun's local
IPv4 listener. spooftun carries the WireGuard UDP payload in its own IPv4
packet and the server forwards it to a loopback WireGuard UDP port.

```text
inner IP -> WireGuard UDP payload -> 127.0.0.1:1001
         -> spooftun raw framing -> remote spooftun
         -> 127.0.0.1:51820 -> WireGuard -> inner IP
```

For a verified 1500-byte physical path, use **WireGuard MTU 1420 on both peers**
with spooftun `-fake-tcp -mtu 1500`. Configure both WireGuard interfaces:

```ini
[Interface]
MTU = 1420
```

For an immediate Linux interface change (persist it in the configuration too):

```sh
sudo ip link set dev wg0 mtu 1420
```

The two MTU settings have different meanings:
- WireGuard MTU: largest inner IP packet admitted to the WireGuard interface.
- spooftun `-mtu`: maximum outer IPv4 packet, capped to its interface MTU.
  It does not set WireGuard's MTU or discover a smaller path bottleneck.

If the path MTU is smaller or unknown, 1400 is a conservative starting
WireGuard MTU, not a guarantee for every path. Determine the actual path MTU
and verify delivery at the intended size before increasing it. Other nested
tunnels or PPPoE may reduce the available budget.

## Why 1420 fits fake TCP

At outer IPv4 MTU 1500, spooftun accepts at most 1460 bytes of application UDP
payload with fake TCP, or 1459 with fake TCP plus fake fragmentation. Oversize
datagrams are dropped whole.

WireGuard data adds a 16-byte header and a 16-byte authentication tag, plus
alignment padding. Conservatively allowing the 1420-byte inner packet to pad
to 1424 bytes gives:

```text
1420  inner IP packet
   4  possible WireGuard alignment padding
  32  WireGuard data header and authentication tag
  20  spooftun outer IPv4 header
  20  fake TCP-shaped header
----
1496  outer IPv4 packet
```

WireGuard implementations can cap padding at the configured MTU; the above
calculation reserves padding anyway. With fake fragmentation, spooftun adds
up to the next 8-byte boundary: this example reaches 1500 bytes. That mode
also sends a separate decoy fragment per uplink datagram.

The original local UDP/IP headers are stripped by spooftun's UDP socket.
Do not subtract both a complete ordinary WireGuard outer UDP/IP envelope and
spooftun's outer headers: those local headers are not encapsulated here.

This calculation assumes direct UDP forwarding into spooftun. If you place
spooftun inside WireGuard, or add another carrier around it, recalculate the
budget for that topology.

References:
- [WireGuard data-packet format and padding](https://www.wireguard.com/protocol/)
- [WireGuard Linux padding implementation](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/send.c)
- spooftun limits: `payloadLimit` in `framing.go`.

## Example endpoints

Replace SERVER_IP and eth0 with the actual public server IP and physical
Ethernet interface. WireGuard must already have its keys and tunnel addresses
configured, with the server listening on UDP port 51820.

Server:

```sh
sudo ./spooftun -mode server -iface eth0 -target-port 51820 \
    -proto 200 -fake-tcp -mtu 1500
```

Client:

```sh
sudo ./spooftun -mode client -iface eth0 -remote-ip SERVER_IP \
    -listen 127.0.0.1:1001 -target-port 51820 \
    -proto 200 -fake-tcp -mtu 1500
```

Set the WireGuard client's peer `Endpoint = 127.0.0.1:1001`. Keep framing
flags consistent across spooftun endpoints. Add `-backend xdp` to opt into
AF_XDP, or `-afpacket-tx ring` to compare the AF_PACKET transmitter.

For a full-tunnel WireGuard configuration, keep spooftun's public endpoint
reachable outside the WireGuard routes and select the physical interface
explicitly. Automatic interface discovery can otherwise select WireGuard's
own interface. See README.md for AF_PACKET kernel-isolation rules, especially
when using outer IP protocols 6 or 17.

For outer protocol 17 with UDP framing, separate the wire port from WireGuard's
real server port: use `-proto 17 -target-port 40000 -outbound-port 51820` on the
server and `-proto 17 -target-port 40000` on the client. Omit `-fake-tcp` on both
ends for this UDP example. Keep the client's WireGuard endpoint pointing to
spooftun's local listener. This prevents direct delivery of the original tunnel
packet to server WireGuard on 51820; AF_PACKET client-side kernel isolation
and suppression of unwanted ICMP responses still apply. See the port-separation
example in [README.md](README.md#kernel-processing-of-tunnel-frames).

## Throughput and CPU troubleshooting

A result such as 170 Mbps at 75% CPU does not identify the cause by itself.
Record whether the CPU figure is a process, one core, or the whole machine.
Linux top normally reports process CPU relative to one logical CPU by default;
its display mode can change that interpretation. Attribute work to spooftun,
WireGuard, kernel networking/softirq and virtual-machine CPU steal time.

Use these comparisons in order:

1. Measure direct network throughput between the two machines.
2. Measure direct WireGuard using the same inner addresses, traffic sizes and
   test settings, with spooftun bypassed.
3. Measure WireGuard over spooftun. Record the selected backend and the
   startup-reported XDP copy/zero-copy mode.
4. Repeat each direction and compare single and multiple TCP streams.
5. If permitted by the path, compare fake fragmentation disabled/enabled;
   its additional uplink frames increase packet-processing work.
6. Profile before changing worker count, batching, offloads or hardware.
   MTU adjustment prevents oversize loss; it does not remove a CPU bottleneck.

Run iperf3 between WireGuard tunnel IPs. For example, start on the remote peer:

```sh
iperf3 -s -B WG_SERVER_IP
```

On the other peer:

```sh
iperf3 -c WG_SERVER_IP -t 30 -P 1
iperf3 -c WG_SERVER_IP -t 30 -P 1 -R
iperf3 -c WG_SERVER_IP -t 30 -P 4
```

Multiple inner TCP streams still share one WireGuard peer's outer UDP flow.
They can expose TCP stream/window limitations but do not automatically spread
that outer flow across NIC receive queues.

For a controlled UDP test at WireGuard MTU 1420, a 1360-byte UDP payload fits
both inner IPv4 and IPv6 headers:

```sh
iperf3 -c WG_SERVER_IP -u -b 200M -l 1360 -t 30
```

Increase the offered rate gradually and inspect receiver throughput, loss
and jitter. An offered 1-Gbps rate is not proof that 1 Gbps was delivered.

iperf3 uses a TCP control connection even for UDP tests. It works through
the full WireGuard IP tunnel, but pointing it directly at spooftun's
UDP-only listener does not forward that control connection.

At 1400 application bytes per datagram, 1 Gbps requires about 89,300 delivered
datagrams/second. A physical 1-Gbps link cannot carry a full 1 Gbps of useful
payload after headers and link overhead; roughly 940-960 Mbps is a typical
standard-MTU payload ceiling, depending on framing. Higher encapsulation
overhead lowers it further.

The repository's Python echo measurements do not demonstrate a 1-Gbps limit
or capability. See [PERFORMANCE.md](PERFORMANCE.md) for their scope and
[PACKET_BACKENDS.md](PACKET_BACKENDS.md) for backend comparisons.

- [iperf3 test/control connection documentation](https://software.es.net/iperf/invoking.html)

## Performance profile for a two-vCPU VM

For protocol 6, a spoofed client source address and custom flags `0x06`
(SYN + RST), the following preserves those settings. Replace every uppercase
placeholder and choose the actual Ethernet interface on each machine:

```sh
# Server: WireGuard listens on UDP 51820; 40000 is the tunnel port.
sudo ./spooftun -mode server -iface eth0 -backend xdp -udp-gro \
    -proto 6 -fake-tcp -tcp-flags 0x06 -mtu 1500 \
    -target-port 40000 -outbound-port 51820 -remote-ip CLIENT_REAL_IP

# Client: WireGuard peer Endpoint = 127.0.0.1:1001.
sudo ./spooftun -mode client -iface eth0 -backend xdp -udp-gro \
    -proto 6 -fake-tcp -tcp-flags 0x06 -mtu 1500 \
    -src-ip SPOOFED_IP -filter-dst-ip CLIENT_REAL_IP \
    -remote-ip SERVER_IP -target-port 40000 -listen 127.0.0.1:1001
```

Keep WireGuard MTU 1420 on a verified 1500-byte path. The fixed server
`-remote-ip` above supports one client return address; it is needed because
the spoofed source cannot identify the real return address. Fake fragmentation
is omitted in this example; when required, enable it on both peers and account
for the extra uplink frame per datagram.

Check the XDP startup log for the actual copy/zero-copy mode. A VM's virtual
NIC may only support copy mode. `-udp-gro` is optional, uses about 1 MiB per
local receive socket, and only reduces message counts when traffic can be
coalesced. The native batched UDP workload benefited, but the measured
WireGuard workload did not show a comparable gain. If XDP is unavailable,
use `-backend afpacket -afpacket-tx sendmmsg` and the documented narrow
ingress isolation rules; compare TX ring on the deployment machine.

On the test server, both tunnel endpoints, WireGuard peers and traffic tools
shared two older Xeon vCPUs. Short native UDP runs exceeded 1 Gbps with loss,
while WireGuard over spooftun remained much slower. These results do not
predict the speed of two separate VMs. Full logs, receiver counts and longer
runs are in [PERFORMANCE.md](PERFORMANCE.md#udp-receive-and-capacity-tests--2026-10-29).

For a sustained 1-Gbps useful-payload target, first verify that the direct
network and direct WireGuard paths have headroom above that rate, in both
directions. Use a link faster than 1 Gbps, low CPU steal and enough per-core
processing capacity. More vCPUs alone do not remove a serialized single-flow
packet path. Measure receiver loss and CPU/softirq, not just the requested
iperf3 send rate. Ordinary TCP TSO cannot be assumed to preserve arbitrary
fake-TCP flags, static sequence fields and packet boundaries.

The optional **kernel TC rewrite backend** now avoids that userspace forwarding
round trip for a fixed IPv4 peer. It preserves spoofed addresses and `0x06`
flags, using an owned virtual interface to complete offload work before header
rewriting. Applications must use its virtual endpoint and fixed local port;
noise and fake fragments remain unsupported. Follow [TC_BACKEND.md](TC_BACKEND.md)
for the complete WireGuard configuration and measured results. This is different
from AF_XDP, which redirects packets into userspace. [Mimic](https://github.com/hack3ric/mimic)
also uses kernel rewriting, but its published results on a newer CPU do not
establish a speed guarantee for this VM.
