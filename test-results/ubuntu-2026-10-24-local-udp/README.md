# Local UDP and encoder validation — 2026-10-24

Ubuntu 24.04.5, Linux 6.8.0-146-generic, Go 1.27.3, amd64, two vCPUs.
The baseline binary was built from commit `6205bed` with the same dependencies.
The candidate adds direct encoding, bounded local delivery, sendmmsg/GSO and
socket-buffer inspection. Production interfaces/services/sysctls were unchanged;
full-tunnel tests used disposable namespaces/veths, removed after testing.

## Correctness

- `local-unit.log`: full `go test -race -timeout 90s ./...` passes.
- `local-focused.log`: new encoder/UDP/forwarder tests pass 20 repetitions under
  the race detector. Includes actual kernel UDP_SEGMENT delivery, injected GSO
  rejection with lossless fallback, empty/mixed datagrams, IPv4/IPv6, partial
  sends, closed sockets, deadlines and copied packet ownership.
- `local-integration.log`: all 24 combinations of AF_PACKET/sendmmsg,
  AF_PACKET/TX-ring and XDP with eight framing/protocol configurations pass.
- `local-bench-race.log`: delivered-pipeline benchmark also passes under the
  race detector (`-benchtime 20x`).
- Linux-targeted vet, Staticcheck, formatting and static amd64/arm64 builds pass.
  arm64 was cross-built, not executed here.

## Component measurements

`local-bench.log`: three repetitions, 300 ms per sub-benchmark. These are
component measurements, not Internet or WireGuard throughput.

| Encoder, 1400-byte payload | gopacket ns/packet | Direct ns/packet |
|---|---:|---:|
| UDP | 1284.0 | 1305.0 |
| Fake TCP | 1875.0 | 875.4 |

The direct encoder eliminates the serializer's 24 B / 1 allocation per packet.
UDP's 1400-byte timing shows no improvement in this short run; do not interpret
the encoder as universally faster. Other payload timings remain in the raw log.

| Local UDP offered send, 16 × 1400 bytes | Median us/batch |
|---|---:|
| Individual connected writes | 121.380 |
| sendmmsg | 89.919 |
| GSO | 46.652 |

The writer reports zero steady-state allocations. Its MB/s counts offered sends,
with a concurrent native receiver, and does not independently prove delivery.

`local-delivered.log` adds a native Go receiver that checks every payload and
sequence number. Each 16-datagram window is acknowledged before sending more.
Median of three repetitions:

| Payload bytes | Individual writes us/window | Copy/queue/GSO pipeline us/window |
|---|---:|---:|
| 64 | 345.358 | 184.888 |
| 512 | 365.243 | 184.678 |
| 1400 | 418.877 | 199.902 |

This verifies the local pipeline benefit including its extra copy and channel
cost. Loopback, acknowledgement synchronization and shared CPUs constrain the
absolute rate; it does not establish external tunnel capacity. Tiny B/op values
in this benchmark include asynchronous one-time worker setup, not a per-packet
allocation claim.

`encoder-before-profile.log` / `encoder-after-profile.log` and their `*-top.log`
files profile the 1400-byte fake-TCP encoder alone. The old profile spends most
time in gopacket checksum/serialization; the direct profile concentrates on its
payload checksum loop. Percentages within separate CPU profiles do not measure
absolute speedup. Binary CPU profiles are retained in the private test workspace
and local ignored cache; text summaries are committed here.

## Complete tunnel

`local-before.json`, `local-after.json`, `local-tcp-before.json` and
`local-tcp-after.json` contain received counts, duplicates, drain results,
process CPU and actual XDP native-copy startup logs. Commands:

```sh
SPOOFTUN_BINARY=../spooftun-local-before bash scripts/netns-test.sh --backend xdp --bench-only --benchmark --iterations 3
SPOOFTUN_BINARY=../spooftun-local-after bash scripts/netns-test.sh --backend xdp --bench-only --benchmark --iterations 3
SPOOFTUN_BINARY=../spooftun-local-after bash scripts/netns-test.sh --backend xdp --bench-only --bench-fake-tcp --benchmark --iterations 3
SPOOFTUN_BINARY=../spooftun-local-before bash scripts/netns-test.sh --backend xdp --bench-only --bench-fake-tcp --benchmark --iterations 3
```

All 36 measurements have zero duplicate replies and zero unanswered requests
after the drain. Median 1400-byte UDP echo: 179.511 → 205.422 Mbps, CPU/reply
65.718 → 53.610 us. Fake TCP: 212.131 → 220.151 Mbps, CPU/reply 56.136 →
49.008 us. Full tables and limitations are in [PERFORMANCE.md](../../PERFORMANCE.md).
These short sequential Python echo tests share the two-vCPU host and exclude
WireGuard encryption and host-wide softirq CPU. They are not randomized capacity
benchmarks, a NIC zero-copy test, or proof of 1-Gbps tunneling.

`local-sources.sha256` identifies the final candidate source snapshot. The
delivered benchmark was added after the earlier component runs; production
source remained unchanged during measurements.
