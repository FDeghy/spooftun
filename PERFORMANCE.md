# Packet-path changes and validation

For the latest native UDP and actual WireGuard capacity tests, see
[the 2026-10-29 results](#udp-receive-and-capacity-tests--2026-10-29).
The earlier sections retain their original echo-test methodology and results.

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
include flow-sharded receive fanout. Receive-address allocations were removed
in the 2026-10-29 change. The encoder/local UDP boundary was optimized separately;
see the 2026-10-24 results below.

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

## Local UDP and encoding changes — 2026-10-24

The client and server now use a specialized fixed-header encoder. Static
Ethernet/IPv4/transport fields and checksum sums are prepared once per direction;
each packet copies its payload and updates lengths, ports, flags and checksums.
Differential tests compare exact bytes against gopacket for UDP, fake TCP,
custom protocol numbers, fragmentation, empty/odd-length payloads and padding.
Encoder microbenchmarks compare equally reused buffers, not repeated setup.

Both raw receive loops hand owned payload copies to a bounded local UDP writer:
32 slots per endpoint, at most 16 messages per write batch, no batching timer.
Only already-available messages are grouped. Consecutive compatible datagrams
use scatter/gather UDP_SEGMENT, without a concatenation buffer. Other datagrams
use sendmmsg; unsupported GSO retries the unchanged batch and disables GSO for
that writer. Empty datagrams, a shorter final GSO segment, mixed destinations,
partial sends, cached socket closure and Go poller deadlines are tested.

This pipeline adds one payload copy and a goroutine/channel boundary to local
delivery. Its benefit must be measured against those costs. UDP GRO remains
disabled, and there is no additional congestion controller or wire protocol.
Socket-buffer setup now reports actual kernel sizes and silent caps; it does
not modify host sysctls or force privileged buffer increases.

Reproduce the component measurements on Linux:

```sh
go test -race ./...
go test -run '^$' -bench 'Benchmark(TunnelEncoding|LocalUDPWriter|LocalForwarderDelivered)$' -benchmem -count 3
go test -run '^$' -bench 'BenchmarkTunnelEncoding/size=1400/tcp=true/direct=false$' -benchtime 2s -cpuprofile encoder-before.cpu
go test -run '^$' -bench 'BenchmarkTunnelEncoding/size=1400/tcp=true/direct=true$' -benchtime 2s -cpuprofile encoder-after.cpu
go tool pprof -top encoder-before.cpu
go tool pprof -top encoder-after.cpu
sudo bash scripts/netns-test.sh --backend xdp --bench-only --bench-fake-tcp --benchmark --iterations 3
```

The UDP writer microbenchmark measures offered-send wall time while a Go
receiver drains concurrently. Its reported MB/s is not independently verified
delivered throughput. Use the integration checks and received echo counts for
correctness and delivery evidence. Full-tunnel numbers remain bounded Python
echo measurements on the shared two-vCPU host, excluding WireGuard encryption
and host-wide softirq CPU; they do not establish 1-Gbps capacity.

`BenchmarkLocalForwarderDelivered` separately compares individual connected UDP
writes against the complete copy/queue/GSO pipeline. A native Go receiver
checks every sequence number and payload and acknowledges each 16-datagram
window before the sender continues. It verifies delivered bytes on loopback;
the acknowledgement channel and shared CPUs constrain its absolute rate.

For the complete tunnel, median of three 3-second XDP native-copy runs per
payload, protocol 200, MTU 1500, before versus after:

| Framing | Payload bytes | Before Mbps | After Mbps | Before CPU us/reply | After CPU us/reply |
|---|---:|---:|---:|---:|---:|
| UDP | 64 | 10.554 | 10.828 | 50.603 | 45.232 |
| UDP | 512 | 76.514 | 81.061 | 56.910 | 49.516 |
| UDP | 1400 | 179.511 | 205.422 | 65.718 | 53.610 |
| Fake TCP | 64 | 9.910 | 10.651 | 54.234 | 47.423 |
| Fake TCP | 512 | 82.506 | 83.694 | 53.945 | 49.226 |
| Fake TCP | 1400 | 212.131 | 220.151 | 56.136 | 49.008 |

Every run had zero unanswered requests after the bounded drain. UDP ran
before/after; fake TCP reversed that order. Runs are sequential, not randomized,
so small throughput differences can reflect scheduling noise. CPU per reply
decreased in every measured case. The baseline is commit `6205bed`, built with
the same toolchain/dependencies as the candidate. These results compare the
combined changes; they do not isolate each change's contribution.

Raw component benchmarks, CPU-profile summaries, received-count JSON and
validation logs: [2026-10-24 local UDP results](test-results/ubuntu-2026-10-24-local-udp/).

## XDP receive batching and borrowed local delivery — 2026-10-24

The XDP forwarding loops now consume up to 16 already-available descriptors
per receive call. RX-consumer and FILL-producer updates, wakeups and locking
are amortized over that batch. Recycling still waits for actual FILL space,
including partial publication and uint32 counter wraparound. No batching timer
is added, and ready queues rotate after each batch.

Local UDP delivery uses the batch's borrowed payloads directly with the existing
sendmmsg/GSO writer, flushing before the next backend read can recycle them.
This removes the intermediate payload copy, queue and worker handoff on the
XDP receive path. AF_PACKET retains the bounded copy/queue pipeline because
its borrowed frame expires at the next individual read. Local write pressure
can still block the receive loop. NIC copy/zero-copy selection, wire framing,
MTU limits and the serialized TX path are unchanged.

On the same two-vCPU Ubuntu host, five paired 10-second native Go echo runs
(1400-byte payloads, fake TCP, protocol 200, XDP native-copy, MTU 1500) measured:

| Metric | Baseline `7c49ae9` | Combined optimization |
|---|---:|---:|
| Median received echo payload Mbps | 228.215 | 251.998 |
| Median tunnel CPU us/delivered reply | 47.307 | 41.822 |
| Throughput range, Mbps | 212.558–258.033 | 247.262–261.574 |

That is about 10.4% higher median throughput and 11.6% less tunnel CPU per
reply in this workload. All ten runs had zero duplicates or unanswered
requests after the bounded drain. Run order alternated within pairs. The
baseline varied substantially and one pair favored it, so this is evidence
for this workload, not a universal speedup or a prediction for live WireGuard.

The native generator sends sequential 128-packet bursts and validates every
received payload and sequence number. It measures echo payload once per
round trip, not total wire bandwidth; both tunnel endpoints and generator/echo
share the host. CPU counts both tunnel processes, excluding generator/echo
and host-wide softirq. WireGuard encryption and a physical inter-server path
are absent. Native burst results are not directly comparable to the older
Python rolling-window results.

Synthetic ring-only measurements reduced the median bookkeeping time for
16 frames from 1498 ns through the single-packet API to 387.7 ns through the
batched reader (zero allocations for both). They exclude kernel wakeups and
all UDP/encoding work. Receive batching alone showed only a small gain with
the native generator and mixed Python results; the final change also removes
the local copy/channel handoff. Raw preliminary results are retained.

Race tests, all 24 namespace integration cases, kernel native/generic-copy
receive tests, vet, Staticcheck and Linux amd64/arm64 static builds pass.
arm64 is cross-built only; hardware zero-copy is still unverified.
Regression tests cover borrowed-buffer reuse, empty datagrams, discarded
batch tails, read errors, close flushing, partial FILL publication, shutdown,
counter wraparound and queue fairness.

Raw results, exact tested source hashes, native generator source and method:
[XDP batching evidence](test-results/ubuntu-2026-10-24-xdp-batch/).

## UDP receive and capacity tests — 2026-10-29

The local UDP receive path on both endpoints now uses reusable native
`recvmmsg` descriptors and `netip.AddrPort`, removing per-datagram address
allocations. Optional `-udp-gro` receives coalesced records and splits them
into borrowed datagram views. It preserves empty and short datagrams, rejects
truncated/oversize records, and retains pending segments across batches.
Fake-fragment padding uses separate reusable scratch storage. No wire format
or TCP flag changes are required. GRO is disabled by default because its
receive storage costs about 1 MiB per client socket/server reply session.

AF_PACKET now subscribes to `ETH_P_IP` instead of `ETH_P_ALL`, avoiding
irrelevant packet taps before the filter. AF_XDP reclaims completions after
its TX-space poll before deciding to sleep. The latter fixes a stale-state
backoff; the diagnostic workload recorded **zero** FILL/TX/wakeup waits, so
its measured throughput cannot be attributed to that fix.

### Actual one-way UDP delivery

These tests use `scripts/udp-load.c`, a native GSO/sendmmsg generator and a
GRO/recvmmsg receiver. Every unique sequence and payload is checked. Payloads
are 1360 bytes, protocol 6, fake TCP with **`-tcp-flags 0x06`**, a spoofed source
IP and an explicit return IP. Both endpoints share the same two-vCPU Xeon
E5-2670 v2 host and isolated veth network. AF_XDP ran in **native-copy** mode.
There is no physical NIC, Internet path or WireGuard encryption in this table.
The baseline is `e5579d5`, built with the same Go 1.27.3 toolchain.

| 30-second run | Requested Mbps | Actual send Mbps | Received Mbps | Missing datagrams | Tunnel CPU us/delivered datagram |
|---|---:|---:|---:|---:|---:|
| Baseline XDP | 1080 | 1032.55 | 966.88 | 3.199% | 14.42 |
| Updated XDP + GRO | 1080 | 1035.01 | 988.92 | 1.227% | 13.67 |
| Updated AF_PACKET/sendmmsg + GRO | 1080 | 1009.73 | 971.25 | 0.548% | 13.69 |
| Updated XDP + GRO, lower load | 900 | 873.02 | 838.83 | 0.652% | 15.74 |

Received Mbps conservatively divides unique received bytes by the full parent
measurement interval, including a one-second drain and shutdown overhead.
`received_mbps_send_interval` uses the sender's interval and includes late
drained packets; it is reported separately, not substituted for that measure.
Loss compares accepted sends against unique received datagrams after the drain.
CPU sums the two spooftun processes; it excludes the generator, receiver,
WireGuard and host-wide softirq. Host CPU tick deltas are retained separately.

For the 1080-Mbps requested XDP comparison, throughput increased about 2.3%
and tunnel CPU per delivered datagram fell about 5.2%. These are individual,
sequential runs on a shared VM, not replicated statistical estimates. The
candidate ran before the baseline. Scheduling and steal time varied, and the
lower-rate run still lost packets. Do not interpret this as a loss-free rate
guarantee or as an isolated measurement of GRO's contribution.

Earlier 10- and 20-second candidate runs received **1031.23 and 1013.21 Mbps**,
with **0.475% and 0.239% loss** respectively. The short 10-second baseline
received 836.91 Mbps with 10.105% loss. The smaller gain in the longer comparison
is why the headline is not a universal percentage speedup. A direct-veth
calibration received 1787.44 Mbps including the drain, with zero loss and an
actual send rate of 1968.88 Mbps. This checks the native generator's capacity
under that workload, not the physical link's speed.

**Loss-free 1-Gbps spooftun and 1-Gbps WireGuard over spooftun are not proven.**
The native receiver found zero corruption or duplicates in these runs. A
separate GSO/GRO + fake-fragment test at 100 Mbps verified all 45,984 datagrams
with zero loss or corruption; it is a correctness check, not a capacity claim.

### Real WireGuard and iperf3

`scripts/bench-wireguard.py` also creates two real kernel WireGuard interfaces,
uses private keys only through stdin, and runs iperf3 through their tunnel IPs.
WireGuard MTU is 1420; outer veth MTU is 1500. The final 30-second TCP tests use
the same spoofing and `0x06` settings as above:

| Path | Received TCP payload Mbps |
|---|---:|
| WireGuard + baseline XDP, forward | 396.29 |
| WireGuard + updated XDP/GRO, forward | 415.10 |
| WireGuard + updated XDP/GRO, reverse | 393.14 |

One short direct-WireGuard calibration measured 1015.35 Mbps, and direct-veth
TCP measured 10333.60 Mbps. Veth offloads and shared CPUs make these local
calibrations unsuitable as physical-network estimates. The direct-WireGuard
run has little margin above 1 Gbps even before adding spooftun.

The forward candidate was about 4.7% faster in the final comparison, but
earlier short runs had mixed results. This does not establish a large WireGuard
speedup. A native UDP test requesting 1 Gbps through WireGuard + spooftun sent
only 768.52 Mbps and received 411.68 Mbps after the drain, with 41.0% loss.
Increasing offered load is not a solution to the CPU limit.

### Profile and design conclusions

An instrumented baseline XDP run put roughly 68–74% of sampled CPU in the
low-level syscall function. The client cumulative profile attributed about
39% to TX wakeup and 18% to UDP receive calls; packet encoding was a much
smaller share. This supports reducing crossings into the kernel. A Go CPU
profile does not resolve the internal kernel functions, so it cannot attribute
all that time to a particular driver or softirq operation.

Increasing the global batch size from 16 to 64 did not reliably help: the
short WireGuard/XDP result fell from 379 to 300 Mbps, while AF_PACKET rose
from 393 to 453 Mbps. `GOMAXPROCS=1` measured 372 Mbps for WireGuard/XDP.
Neither experiment was promoted. Larger socket/ring buffers can absorb bursts
but do not eliminate the sustained processing cost. TX ring remains selectable;
the earlier cross-size comparison still does not justify making it the default.

The external projects suggest two distinct directions:

- [quic-go](https://quic-go.net/docs/quic/optimizations/) batches compatible
  sends with UDP GSO and falls back when unsupported. spooftun already uses
  this for local sends; optional receive GRO and reused address storage now
  complement it. QUIC congestion control and flow-control windows do not
  directly remove raw-packet forwarding costs.
- [Hysteria's performance guidance](https://v2.hysteria.network/docs/advanced/Performance/)
  emphasizes CPU capacity, socket buffers and QUIC windows. Its stream-window
  settings are not spooftun settings. spooftun reports actual socket limits;
  it does not silently change host sysctls or scheduling priority.
- [Mimic](https://github.com/hack3ric/mimic) rewrites UDP into TCP-shaped packets
  in kernel TC and restores them in XDP, avoiding a userspace forwarding loop.
  It moves a small header-adjacent region rather than copying the whole payload.
  Its published benchmark uses a newer CPU and is marked for retesting.
  A separate kernel rewrite backend is the most promising architectural
  experiment for WireGuard; it is **not implemented here**. Current AF_XDP
  still sends packets through userspace. Spoofed return mapping, arbitrary
  flags, checksums/offloads, noise and fragmentation need explicit compatibility
  design before such a backend can replace the present path.

### Reproduction and validation

On Linux with root, `ip`, `iptables`, `wg`, `iperf3`, Python 3 and GCC:

```sh
CGO_ENABLED=0 go build -o spooftun .
gcc -O2 -Wall -Wextra -Werror -o udp-load scripts/udp-load.c

# Native one-way spooftun UDP. Output directory must not already exist.
sudo python3 scripts/bench-wireguard.py --binary ./spooftun \
    --path xdp --output native-xdp --seconds 30 --proto 6 --tcp-flags 0x06 \
    --spoof --extra=-udp-gro --raw-udp --udp-load ./udp-load --udp-rate 1080M

# Real WireGuard + TCP iperf3; repeat with --reverse.
sudo python3 scripts/bench-wireguard.py --binary ./spooftun \
    --path xdp --output wg-xdp --seconds 30 --proto 6 --tcp-flags 0x06 \
    --spoof --extra=-udp-gro

# Direct WireGuard calibration. --path direct instead measures plain veth.
sudo python3 scripts/bench-wireguard.py --binary ./spooftun \
    --path wireguard --output wg-direct --seconds 30
```

Use `--path afpacket` or `--path ring` to compare packet backends. The harness
sets up and cleans only its own namespaces, veths, processes and scoped
firewall rules. It never attaches XDP or applies firewall rules to a production
interface. Native receive validation has a 16,777,216-datagram sequence cap and
fails explicitly on overflow; choose duration and rate accordingly. Native
mode currently supports one forward flow. iperf3 supports reverse and multiple
streams. Raw-UDP iperf mode uses a separate TCP control proxy, while its UDP
data still traverses spooftun.

Validation passed: fresh native race tests, 48 backend/framing/GRO namespace
cases, 14 noise cases, three outbound-port cases, real GRO boundary and
truncation tests, zero steady-state UDP reader allocations, fake-fragment GSO
delivery, vet, Staticcheck, and static Linux amd64/arm64 builds. arm64 was
cross-built only; physical NIC zero-copy remains untested.

Source and binary hashes, full received-count JSON, process logs, iperf3 JSON,
CPU-profile summaries, diagnostic instrumentation and validation output are
in [the raw performance evidence](test-results/ubuntu-2026-10-29-performance/).
