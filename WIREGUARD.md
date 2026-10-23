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
