# Multiqueue TUN validation — 2026-11-05

Tested on the supplied server, using isolated network namespaces and a veth pair.
No host routes, firewall rules or production interfaces were changed. Both peers
and the traffic generator shared two virtual CPUs: Intel Xeon E5-2670 v2,
Linux 6.8.0-146-generic. Binaries were cross-compiled with Go 1.27.3,
`GOOS=linux GOARCH=amd64 CGO_ENABLED=0`; binary hashes are in `sha256.txt`.

## Throughput

TCP iperf3, four streams, five seconds per run, three repetitions per direction.
AF_PACKET/sendmmsg, flow distribution, outer MTU 1500 and derived TUN MTU 1472.
Measurements ran serially. Values below are medians of receiver throughput.

| Path | Forward Mbps (range) | Reverse Mbps (range) | Combined tunnel CPU seconds/run, forward / reverse |
| --- | ---: | ---: | ---: |
| TUN, 1 worker per peer | 419.60 (407–515) | 409.10 (357–457) | 7.37 / 7.40 |
| TUN, 2 workers per peer | 518.86 (511–588) | 544.11 (407–552) | 7.99 / 7.87 |
| Direct veth baseline | 15713.16 (13025–16873) | 16896.37 (14773–17702) | N/A |

Two workers had 23.7% higher forward and 33.0% higher reverse median throughput
in this sample. Three samples on a shared VM do not establish statistical
significance or predict scaling on a larger host. Both endpoints contend for
the same CPUs. Raw JSON includes TCP retransmissions, which were substantial;
the direct veth path also retransmitted. Direct veth benefits from kernel
offloads, whereas this TUN path intentionally receives complete packets without
virtio/GSO offloads. These are local processing results, not WAN capacity.

`final-one/`, `final-two/`, and `bench-direct/` contain all iperf3 JSON, process
logs and summary data. CPU seconds include both tunnel processes; they exclude
iperf3 and are not total host CPU utilization.

## Correctness

- The complete compiled Go test suite passed (`tests-final.log`). This includes
  malformed inner IP packets, checksum failures, unexpected outer peers,
  invalid CLI options, MTU arithmetic over 1280–1520 bytes, fake-fragment
  round trips and stable fragment flow selection.
- One and two attached TUN queues were verified from `/proc/<pid>/fdinfo`.
- Maximum-size IPv4 DF packets passed in both directions; one byte beyond the
  derived MTU was rejected by the sending stack.
- Maximum-size IPv6 packets passed in both directions.
- Two-worker integration checks passed with TCP-shaped framing (MTU 1460),
  fake fragments (1471), and TCP-shaped framing plus fake fragments with an
  outer MTU of 1400 (derived MTU 1355). See the `verify-*` directories.
- `go vet ./...`, Linux binary/test compilation and Python syntax checks passed.
- The namespace inventory after testing was empty (`namespaces-after.txt`).

The race detector was not run: this Windows environment cross-compiled the
Linux test executable without cgo. Live multiqueue forwarding was exercised
on Linux. TUN integration with XDP and AF_PACKET TX ring was not benchmarked;
the selected AF_PACKET/sendmmsg path was the acceptance target.

## Microbenchmarks

Six repetitions, recorded in `microbench-final.log`:

- Inner flow-port selection: 18.81–25.48 ns/op, zero allocations.
- Encode, parse, verify transport checksum and validate a 1472-byte inner IPv4
  packet: 1.645–2.120 µs/op, zero allocations (694–895 MB/s).

These exclude TUN syscalls, packet sockets, queueing and kernel networking;
they are not end-to-end throughput measurements.

## Reproduce

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o spooftun-tun .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o spooftun-tun.test .
# Run on the Linux test host as root:
./spooftun-tun.test -test.timeout 90s
python3 scripts/bench-tun.py --binary ./spooftun-tun --workers 1 --output /tmp/tun-one
python3 scripts/bench-tun.py --binary ./spooftun-tun --workers 2 --output /tmp/tun-two
python3 scripts/bench-tun.py --binary ./spooftun-tun --direct --output /tmp/tun-direct
python3 scripts/bench-tun.py --binary ./spooftun-tun --workers 2 --fake-tcp --fake-frag --mtu 1400 --verify-only --output /tmp/tun-framing
./spooftun-tun.test -test.run '^$' -test.bench BenchmarkTUN -test.benchmem -test.count 6
```
