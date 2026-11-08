# TUN bandwidth tuning — 2026-11-05

The final change uses 64-bit checksum accumulation with end-around carry and
drains up to 64 available packets per send batch with one TUN worker. Multiple
workers retain the previous 16-packet burst size to leave CPU time for receive
work. There are no new flags, dependencies, wire-format changes or MTU changes.

## End-to-end results

Measured on the supplied test server: two virtual CPUs, Intel Xeon E5-2670 v2,
Linux 6.8.0-146-generic, Go 1.27.3. Both endpoints and iperf3 shared this host,
using isolated namespaces and a veth pair. AF_PACKET/sendmmsg, default flow
distribution, outer MTU 1500 and inner MTU 1472; TCP used BBR.

Each row is the median of six five-second iperf3 runs with four streams per
direction. Tests ran serially. Forward and reverse were measured separately.

| Workers per peer | Before forward Mbps | After forward Mbps | Before reverse Mbps | After reverse Mbps |
| --- | ---: | ---: | ---: | ---: |
| 1 | 382.11 | 454.28 (+18.9%) | 384.57 | 453.53 (+17.9%) |
| 2 | 499.42 | 537.96 (+7.7%) | 536.98 | 576.42 (+7.3%) |

| Path | Forward range Mbps | Reverse range Mbps | Median combined tunnel CPU seconds/run, forward / reverse |
| --- | ---: | ---: | ---: |
| Before, 1 worker | 336.2–419.7 | 349.1–441.2 | 7.23 / 7.25 |
| After, 1 worker | 417.5–514.6 | 433.6–529.6 | 7.32 / 7.33 |
| Before, 2 workers | 411.7–633.7 | 399.2–607.5 | 7.95 / 7.72 |
| After, 2 workers | 428.4–656.4 | 464.0–640.8 | 7.93 / 7.88 |

The VM is noisy and sample ranges overlap, especially with two workers. These
are observed median improvements, not a guarantee of scaling or a claim of
statistical significance. Both peers contend for the same CPUs; measurements
describe local packet processing rather than WAN capacity. CPU time covers the
two tunnel processes, excluding iperf3 and other host work.

Final raw results are in `bandwidth-one/` and `bandwidth-two/`. Controls are in
`baseline-final-one/` and `final-baseline-two/`. JSON includes receiver throughput,
TCP retransmissions, tunnel CPU time and `/proc/<pid>/io` read/write counters.
`bandwidth-final-sha256.txt` identifies the unchanged baseline and final build.

## Focused performance proof

Six framing microbenchmark repetitions, baseline versus final build:

| Operation | Before median | After median | Allocations |
| --- | ---: | ---: | ---: |
| Encode, parse, verify transport checksum and validate a 1472-byte inner IPv4 packet | 1719 ns | 822.2 ns | 0 B/op, 0 allocs/op |

That is 52.2% less processing time for this operation. It excludes packet
sockets, TUN syscalls, kernel networking and queueing. Raw measurements are in
`final-micro-baseline.log` and `bandwidth-micro.log`.

The baseline CPU profile (`profile-baseline.txt`) showed syscall, scheduling,
TCP wake-up and checksum costs. Native NAPI, smaller packet blocks, immediate
TPACKET_V2 receive and TCP segmentation offload were explored. Their bandwidth
results were mixed, so their production code was removed. Larger batches with
multiple workers were also inconsistent; the final implementation preserves the
existing burst size there. The exploratory directories record those trials and
are not results for the shipped implementation.

## Correctness and cleanup

- The complete compiled Go test suite passed (`bandwidth-tests.log`).
- The checksum implementation matches an independent 16-bit reference across
  16,896 combinations of input size, alignment, initial sum and carry-heavy data,
  in addition to existing byte-for-byte serializer and framing tests.
- Tests preserve and validate 70 packets across both the 64-packet single-worker
  boundary and the 16-packet multiple-worker boundary.
- IPv4 and IPv6 maximum-size packets pass in both directions. IPv4 DF packets
  one byte beyond the derived MTU are rejected by the sending stack.
- IPv4/IPv6 UDP echo validates empty, small and maximum-size datagrams.
- IPv6 TCP forwarding passes (`bandwidth-ipv6/`). TCP-shaped framing plus fake
  fragmentation passes at outer MTU 1400 / inner MTU 1355
  (`bandwidth-framing/`). These short TCP runs are compatibility checks.
- `go vet ./...`, Linux compilation, Python syntax checks and `git diff --check`
  passed. The race detector was not run; Linux tests were cross-compiled from
  Windows with cgo disabled.
- No host routes, firewall rules or production interfaces were changed.
  `bandwidth-final-namespaces.txt` is empty: the harness removed its namespaces.

## Reproduce

Use the same toolchain and hardware for before/after comparisons. The preserved
baseline executable is available locally as `dist/spooftun-tun-baseline`; the
updated executable is `dist/spooftun-tun`. On a Linux test host:

```sh
CGO_ENABLED=0 go build -o spooftun-tun-bandwidth .
CGO_ENABLED=0 go test -c -o spooftun-tun-bandwidth.test .
sudo ./spooftun-tun-bandwidth.test -test.timeout 90s
sudo python3 scripts/bench-tun.py --binary ./spooftun-tun-bandwidth --workers 1 --repeat 6 --output /tmp/tun-after-one
sudo python3 scripts/bench-tun.py --binary ./spooftun-tun-bandwidth --workers 2 --repeat 6 --output /tmp/tun-after-two
sudo python3 scripts/bench-tun.py --binary ./spooftun-tun-baseline --workers 1 --repeat 6 --output /tmp/tun-before-one
sudo python3 scripts/bench-tun.py --binary ./spooftun-tun-baseline --workers 2 --repeat 6 --output /tmp/tun-before-two
sudo python3 scripts/bench-tun.py --binary ./spooftun-tun-bandwidth --workers 2 --ipv6 --repeat 1 --seconds 2 --output /tmp/tun-ipv6
sudo python3 scripts/bench-tun.py --binary ./spooftun-tun-bandwidth --workers 2 --fake-tcp --fake-frag --mtu 1400 --repeat 1 --seconds 2 --output /tmp/tun-framing
./spooftun-tun-bandwidth.test -test.run '^$' -test.bench BenchmarkTUNFraming -test.benchmem -test.count 6
```
