# TC kernel rewrite validation — 2026-10-29

The tests ran on the authorized Ubuntu server in disposable network namespaces.
Both WireGuard peers and traffic generators shared two Xeon E5-2670 v2 vCPUs.
No production interface, firewall, sysctl or physical NIC offload setting was
changed. Clang was extracted into the test workspace, not installed system-wide.

See [TC_BACKEND.md](../../TC_BACKEND.md#measurements-on-the-two-vcpu-test-server)
for the results, setup instructions and limitations.

- `verified-integration/` records real UDP boundaries, maximum/oversize payloads,
  GSO rejection and explicit fallback, wire checksum/flag/spoof capture, invalid
  TCP checksum rejection by the restored UDP socket, existing TCX ownership,
  unrelated ICMP and exact pre/post interface inventories. Kernel-created GRE
  placeholder interfaces are retained; cleanup compares against the actual
  starting inventory. `gso_supported: false` is intentional and documented.
- `final-race.log` is a fresh native `SPOOFTUN_TC_TEST=1 go test -count=1 -race
  -timeout 120s -v ./...`. It includes real verifier and BPF_PROG_TEST_RUN
  checks, corruption-preserving checksum conversion, fragments, tuple filtering,
  MTU boundaries and the source/object consistency test. Other opt-in suites
  remain marked skipped; this log does not claim they ran again.
- Capacity tests use real kernel WireGuard and receiver iperf3 TCP reports,
  protocol 6, spoofing and `0x06`. Forward/reverse TC tests use the final binary.
  `compare-xdp` uses the prior committed AF_XDP implementation (`379ec24`).
- Paced tests request 300 Mbps TCP. Order is XDP/TC, then TC/XDP. Raw host
  CPU ticks are kept in each summary; the index converts busy ticks using
  100 ticks/second. Host CPU includes unrelated host activity and kernel work,
  not just eBPF. Idle, iowait and steal are excluded from busy CPU-seconds.
- `sources.sha256` verifies all tested Go/module/BPF/script inputs byte for byte.
  `binaries.sha256` records the measured TC binary, an identical rebuild, and
  the prior userspace binary. A fresh rebuild reproduced the measured TC binary
  exactly. The BPF object and its source/object manifest are under `bpf/` in
  the repository. Git newline conversion may change raw Go/script file hashes.

Final local checks also passed: vet, Staticcheck and CGO-disabled Linux amd64
and arm64 builds. arm64 is cross-built only. CI now includes TC kernel checks,
but these logs describe the local/server checks, not a completed GitHub run.

These measurements demonstrate reduced userspace packet processing and a
host CPU reduction at matched throughput. They do not prove 1-Gbps WireGuard,
hardware zero-copy, performance between separate hosts, or WAN capacity.
