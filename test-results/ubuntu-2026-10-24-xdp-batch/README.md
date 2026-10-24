# XDP batching and borrowed local delivery — 2026-10-24

Tests used the supplied Ubuntu host, Linux 6.8.0-146-generic, two Xeon E5-2670
v2 vCPUs and Go 1.27.3. Traffic ran only through disposable namespaces/veths.
The final namespace listing was empty. Production services were not deployed
or restarted. Baseline: commit `7c49ae9`; both binaries used identical
dependencies/toolchain. `sources.sha256` matches every final workspace Go
source and module file, including tests.

## Final throughput

Native Go burst echo, 1400-byte payloads, fake TCP, protocol 200, XDP
native-copy, MTU 1500. Five paired 10-second measurements; the second and
fourth pairs reverse baseline/candidate order:

| Median metric | Baseline | Final |
|---|---:|---:|
| Received echo payload Mbps | 228.215 | 251.998 |
| Tunnel CPU us/delivered reply | 47.307 | 41.822 |

Median throughput increased 10.4%; CPU per reply decreased 11.6%. Baseline
throughput ranged 212.558–258.033 Mbps; final ranged 247.262–261.574 Mbps.
One pair favored the baseline. See `final-native-{baseline,final}-{1..5}.json`.

The existing Python rolling-window harness also ran three paired 3-second
measurements per payload, reversing order in the middle pair:

| Payload bytes | Baseline Mbps | Final Mbps | Baseline CPU us/reply | Final CPU us/reply |
|---|---:|---:|---:|---:|
| 64 | 11.326 | 11.794 | 44.436 | 42.706 |
| 512 | 83.229 | 95.185 | 49.867 | 42.597 |
| 1400 | 201.414 | 231.319 | 53.744 | 46.478 |

All 28 final measurements had zero duplicates and zero unanswered requests
after their bounded drain. Received counts, startup copy-mode logs, range and
median values are retained in the JSON files and `summary.json`.

Both methods count echo payload once per round trip, not total wire traffic.
Both tunnel endpoints and traffic processes share this two-vCPU host. CPU
includes both tunnel processes but excludes generator/echo and host-wide
softirq. There is no WireGuard encryption or physical inter-server path.
These results support this workload; they do not predict a specific live
WireGuard speedup or establish maximum tunnel capacity.

## Native method and reproduction

`native-echo.go.txt` is the exact compiled Go generator/echo source. It sends
128-packet bursts, reads their replies before the next burst, and validates
payload contents and unique sequence numbers. A burst has a bounded receive
deadline; a final 250-ms drain counts late replies separately. CPU ticks are
read from the two tunnel processes using the host's `CLK_TCK` value. This
differs from the Python harness's continuously replenished 128-request window,
so compare before/after within each method, not between methods.

`prepare-native.py.txt` copies the existing namespace harness and substitutes
the native target/measurement processes, preserving correctness probes and
namespace isolation. The `final-*-bench.sh.txt` and `final-native-extra.sh.txt`
files record the actual commands and order; their absolute private workspace
path must be adjusted when reproducing elsewhere. Build baseline and final
as `baseline-bin` and `final-bin`. The Python comparison can be reproduced
directly from either checkout:

```sh
SPOOFTUN_BINARY=/path/to/binary bash scripts/netns-test.sh \
  --backend xdp --bench-only --bench-fake-tcp --benchmark \
  --iterations 1 --duration 3
```

## Correctness and component evidence

- `final-focused.log`: borrowed-buffer delivery, skipped tails, read errors,
  close flushing, RX ownership, partial FILL publication, counter wraparound,
  queue fairness and shutdown tests, repeated 20 times under the race detector.
- `final-unit.log`: full race suite passes.
- `final-integration.log`: all 24 backend/framing combinations pass, including
  empty/oversize datagrams and unmatched XDP passthrough.
- `kernel.log`: real native-copy and generic-copy receive tests, ten repetitions
  with 8192 ordered frames per mode each time (163,840 frames). Tests use the
  batched reader and exercise kernel ring reuse across many wraps.
- Vet, Staticcheck, formatting and static Linux amd64/arm64 builds pass.
  arm64 was cross-built, not executed; NIC hardware zero-copy remains untested.
- `bookkeeping.log`: synthetic ring-only median 1498 ns per 16 frames through
  the single-packet API, 387.7 ns through the batched reader, both zero allocs.
  This excludes actual kernel wakeups, local UDP and encoding work.

## Preliminary measurements retained

`baseline-*.json`, `candidate-*.json`, and `native-{baseline,candidate}-*.json`
measure the intermediate receive-batching-only change, before borrowed local
delivery. Python results were mixed (1400-byte median 233.991 → 214.043 Mbps);
the native 1400-byte median was 240.512 → 244.659 Mbps. They are not final
performance results. The final implementation combines receive batching with
removal of the XDP local-delivery copy/channel handoff; the final throughput
comparisons do not isolate each change's individual contribution.
