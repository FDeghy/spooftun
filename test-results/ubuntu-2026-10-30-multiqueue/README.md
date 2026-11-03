# AF_PACKET worker queues — 2026-10-30

Ubuntu Linux 6.8.0-146-generic, two vCPUs, Go 1.27.3. Both tunnel endpoints,
Python generator and echo target share this host. All network changes were
confined to disposable namespaces/veths; the final namespace listing was empty.
Production interfaces, services and firewall rules were not changed.

The same candidate was compared with one worker, two `flow` workers, and two
`spread` workers. These are configuration comparisons, not before/after commit
comparisons. Settings: AF_PACKET/sendmmsg, protocol 200, fake TCP, MTU 1500,
GRO disabled, default 1-ms retirement and 16-MiB RX ring **per worker**.

## Throughput

Three 3-second repetitions for each configuration, flow count and payload.
The middle repetition reverses configuration order. All modes use the same
bounded 128-request window, shared across all application flows. Every reply's
payload and sequence number is checked. Late replies are counted separately
after a bounded drain. All 54 measurements had zero duplicates and zero
unanswered requests after the drain.

Median received echo payload Mbps:

| Flows | Payload | One worker | Two flow workers | Two spread workers |
|---|---:|---:|---:|---:|
| 1 | 64 | 9.095 | 9.468 | 8.424 |
| 1 | 512 | 72.904 | 74.584 | 67.772 |
| 1 | 1400 | 182.242 | 195.194 | 161.966 |
| 8 | 64 | 7.357 | 7.572 | 7.546 |
| 8 | 512 | 62.764 | 63.064 | 64.017 |
| 8 | 1400 | 164.907 | 180.108 | 172.622 |

At eight flows / 1400 bytes, flow mode improved median throughput about 9.2%
and reduced tunnel process CPU per delivered reply from 67.435 to 63.005 us
(about 6.6%). Single-flow spread regressed about 11.1% at 1400 bytes. The small
and contended host, Python traffic processes and short sequential runs constrain
these results. Single-flow `flow` mode still assigns its packets to one receive
worker; its measured difference is not evidence of parallelizing that flow.

Rates count echo payload once per round trip, not aggregate wire traffic.
Process CPU sums the two tunnel processes, excluding Python and host-wide
softirq. There is no WireGuard encryption or physical inter-server link.
These measurements do not establish maximum capacity or a live WireGuard
speedup. One worker remains the default; spread is explicitly opt-in.

## Correctness

- `unit.log`: full `go test -race -timeout 120s ./...` passes on final sources.
- `focused.log`: worker validation, tuple hashing and concurrent session creation
  tests repeated 20 times under the race detector. Covers IP options, custom
  protocols, source-port distribution, truncated input, metadata/payload changes,
  one session under 64 simultaneous callers, retirement and failed creation.
- The initial expanded integration run passed all six existing configurations
  (48 framing/protocol cases) and both new spread configurations (16 cases),
  but caught an offset bug in both new flow configurations. This negative
  evidence is retained as `integration-before-offset-fix.log`.
- `flow-integration.log` reruns the two flow configurations after correction,
  passing their 16 framing/protocol cases, plus two default configurations.
  Together the runs validate all 80 distinct configured cases. Flow mode checks
  per-flow order; both modes check eight concurrent flows, duplicate delivery,
  empty/oversize datagrams, and a burst creating exactly one target session.
- The selector must see the network-layer skb: Linux runs fanout before
  `tpacket_rcv` restores the Ethernet header used by ordinary capture filters.
  The corrected VM fixtures use the same IP-header origin as the kernel hook.
- Linux-targeted vet, Staticcheck, formatting, and static amd64/arm64 builds
  pass. arm64 was cross-built, not executed.

`sources.sha256` matches the final Go/module sources and Python harness in the
workspace. `binaries-sha256.json` identifies the built release artifacts.

## Reproduction

```sh
go test -race ./...
sudo env SPOOFTUN_NETNS_TEST=1 go test -timeout 360s \
  -run TestNetworkNamespaceIntegration -v .
sudo bash scripts/netns-test.sh --backend afpacket --packet-workers 2 \
  --packet-distribution flow --bench-only --bench-fake-tcp \
  --benchmark --flows 8 --duration 3 --iterations 3
```

Change worker count/distribution to compare configurations at identical flow
counts. `bench.sh` records the exact measurement order; adjust its private
workspace/toolchain paths and binary location when reproducing elsewhere.
