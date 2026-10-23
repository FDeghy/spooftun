# Packet-path changes and validation

Validated on the supplied Ubuntu 24.04 server, Linux 6.8, two vCPUs
(Intel Xeon E5-2670 v2), using Go 1.27.3. Tests use disposable network namespaces
and veth devices. Existing server interfaces, routes, services and host firewall
are not changed. Sources/toolchain/build outputs live in
/root/spooftun-test-20261023; Go was not installed system-wide.

## Changes

- Bounded full-range NAT allocation and atomic session retirement.
- Server idle lifetime includes either direction; deadlines renew on timeout,
  rather than resetting the runtime timer on every read batch.
- MTU-aware payload limits, whole-datagram oversize rejection, validated padding
  and IPv4 lengths. Empty datagrams remain valid.
- Interface-specific main-table IPv4 route and neighbor resolution, with actual
  ARP probes. Policy routing is not fully supported by /proc/net/route.
- Pure Go classic BPF with option-aware transport offsets and fragment checks;
  static release binaries no longer require libpcap/cgo.
- Send-only raw packet sockets and sendmmsg batching in both outbound paths.
  Already-read UDP batches are sent immediately without a batching timer.
  Descriptor pooling removes steady-state batch descriptor allocations.
- Smaller per-session UDP batch storage (16 slots), reusable TX serialization
  buffers, coarse activity timestamps; mmap-backed RX payloads are not queued
  past their buffer lifetime.
- Configurable ring budget, block retirement and MTU. Ring layout now respects
  TPACKET alignment and both 4 KiB and 64 KiB pages.
- Go 1.27.3, gopacket 1.7.4, x/net 0.61.0, x/sys 0.49.0;
  Staticcheck 0.8.2 handles the current Go export format.

## Measurement method

The compatibility baseline is original HEAD packet/NAT/UDP code, built with
the same Go/dependency versions and the new pure-Go BPF implementation solely
to remove the libpcap build dependency. Both runs use identical static veth
neighbors, namespace firewall isolation, Python echo service, and measurement
harness. It is not a completely untouched historical release comparison.

The final harness allows at most 128 outstanding datagrams, expires a missing
request after 200 ms without retransmitting, embeds sequence IDs, and counts
unique replies. It reports late responses separately after a bounded drain.
CPU includes both tunnel processes, excluding Python and system-wide softirq.
Results therefore are not total host CPU or an Internet link speed. Three
3-second runs per payload are summarized by median. The two tunnel endpoints
and both application endpoints share this two-vCPU host, introducing contention.
Preliminary flooding measurements were noisy and are not evidence of improvement.

## What the benchmarks establish

The recorded numbers are real local echo measurements. They are not a
maximum-capacity test, a WireGuard-over-spooftun benchmark, or proof of
1-Gbps tunneling. The Python generator/echo service, shared two-vCPU host,
128-datagram window and short measurement duration can constrain the result.
Each delivered echo traverses the tunnel in both directions; the reported
Mbps counts the echoed application payload once, not aggregate wire traffic.

Reaching a rate in this harness does not establish a speed ceiling for two
separate hosts. Likewise, passing correctness tests does not guarantee a
specific throughput or verify hardware zero-copy.

For a capacity test, use two separate Linux endpoints and a native compiled
generator/receiver. First establish the direct path's capacity. Measure
one-way received throughput for 30-60 seconds, then reverse direction and test
both single-flow and aggregate traffic. Keep packet sizes and offered load
identical between the baseline and tunnel runs. Record receiver loss/jitter,
per-core/process CPU, softirq, CPU steal time and NIC drops.

At 1400 application bytes, a 1-Gbps payload target requires about 89,300
delivered datagrams/second. Physical link capacity must also cover the
encapsulation and Ethernet overhead. Do not infer this target from a sender's
offered rate or total host CPU percentage.

For WireGuard layering, MTU and iperf3 instructions, see
[WIREGUARD.md](WIREGUARD.md). In particular, compare direct WireGuard against
WireGuard over spooftun before attributing a 170-Mbps/75%-CPU result to one
component.

## AF_PACKET settings and next steps

The default RX ring is 16 MiB, TPACKET_V3, 1 ms block retirement. Keep the
1 ms default for latency-sensitive traffic. Evaluate 5 ms on bulk traffic using
the benchmark's --block-timeout option, then check latency and missing replies;
a larger retirement timeout trades latency for fewer wakeups. Larger rings
absorb bursts but do not remove a sustained CPU bottleneck.

Transmit uses a protocol-zero AF_PACKET socket, so no unused receive ring is
allocated for TX. Qdisc bypass is not enabled: bypassing host traffic control
can defeat configured QoS and is not a universal throughput improvement.

PACKET_TX_RING and AF_XDP are implemented as selectable backends. See
[PACKET_BACKENDS.md](PACKET_BACKENDS.md) for the current measurements, fallback
behavior and retained sendmmsg default. The remaining larger optimizations
are flow-sharded receive fanout and profiling the encoder/local UDP boundary.

Primary references:
- [Linux PACKET_MMAP](https://docs.kernel.org/networking/packet_mmap.html)
- [Linux AF_XDP](https://docs.kernel.org/networking/af_xdp.html)
- [Go release metadata](https://go.dev/dl/?mode=json)

## Operational limits

AF_PACKET taps packets; it does not consume them before the IP stack.
Protocols 6 and 17 require narrow ingress firewall isolation to avoid kernel
TCP resets or duplicate UDP delivery. The test suite installs such rules only
in disposable namespaces. Production rules are an explicit administrator step;
see README.md. Fake TCP does not implement a TCP connection.

## Final benchmark: default 16-slot batching

Median of three 3-second runs, protocol 200 / UDP framing / MTU 1500 / 1ms
retirement, with a 128-request window. CPU is microseconds per unique reply
delivered during the measurement interval, summed across client and server.

| UDP payload | Baseline Mbps | Optimized Mbps | Throughput change | Baseline CPU us/reply | Optimized CPU us/reply | CPU/reply change |
|---|---:|---:|---:|---:|---:|---:|
| 64 bytes | 7.707 | 8.603 | +11.6% | 71.081 | 61.450 | -13.5% |
| 512 bytes | 61.278 | 66.308 | +8.2% | 71.519 | 64.191 | -10.2% |
| 1400 bytes | 131.667 | 176.871 | +34.3% | 93.765 | 67.329 | -28.2% |

All nine baseline and nine optimized runs had zero unanswered requests after
the drain. In-flight replies at the measurement cutoff are excluded from
throughput and reported separately. These short shared-host tests support an
improvement for this workload; they are not a universal bandwidth guarantee.
A saturated process can consume a similar number of CPU cores while doing more
work, so CPU/reply, rather than raw CPU utilization, is the efficiency metric.

## Validation gates

- Native Ubuntu: go test -race ./... passed.
- go vet and formatting passed.
- Staticcheck 0.8.2 passed with the Linux target.
- Static CGO-disabled amd64 and arm64 release builds passed (arm64 cross-built,
  not executed on this amd64 host).
- Eight native network-namespace protocol/framing modes passed, including empty
  payloads, exact MTU boundaries, oversized datagram drops, and continuous
  one-way traffic across a shortened server idle timeout.
- Classic BPF VM and real kernel attachment, sendmmsg ABI/partial-send cases,
  NAT exhaustion/concurrency/retirement, route/ARP parsing, malformed framing,
  and 4K/64K page ring sizing are covered by regression tests.
- Batch descriptor and NAT lookup benchmarks report 0 allocations per operation
  in steady state. Socketpair write-vs-batch timings varied with scheduling;
  they are not used as proof of a universal speedup.

A separate 64-slot variant measured 7.466 / 65.217 / 159.821 Mbps for the same
64 / 512 / 1400-byte cases, versus the 16-slot default's
8.603 / 66.308 / 176.871 Mbps. It did not justify increasing the default on this
host. These runs were sequential rather than randomized; treat close differences
as scheduler noise rather than a universal batch-size rule.

Raw test evidence: [Ubuntu results](test-results/ubuntu-2026-10-23/).
