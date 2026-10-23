# AF_XDP and AF_PACKET transmit selection

## Usage

```sh
# Existing receive backend with batched syscalls (default).
sudo ./spooftun -mode server -backend afpacket -afpacket-tx sendmmsg

# Same receive backend with a dedicated mmap TX ring.
sudo ./spooftun -mode server -backend afpacket -afpacket-tx ring

# AF_XDP with automatic zero-copy/copy selection.
sudo ./spooftun -mode server -backend xdp -iface eth0
sudo ./spooftun -mode client -backend xdp -iface eth0 -remote-ip SERVER_IP
```

Keep protocol/framing options consistent between peers. Backends are wire
compatible, so endpoints need not select the same packet-I/O method.

## Selection and lifecycle

The AF_XDP path creates an XSK map and a small eBPF XDP program using
github.com/cilium/ebpf. No clang, generated ELF, libbpf, or cgo is required.

It tries native XDP plus XDP_ZEROCOPY, then native XDP plus XDP_COPY, then
generic XDP plus XDP_COPY. Unsupported bind/attach errors permit fallback.
Verifier/permission/UMEM allocation/memlock errors fail startup explicitly.
XDP_OPTIONS reports the actual mode; startup logs include the attachment,
copy mode, queue count, and per-queue UMEM allocation.

Every discovered RX queue gets its own socket and 4 MiB UMEM. A single reader
polls the queues, returning a slice valid until its next read. RX and TX frame
pools are separate. TX uses queue zero and serializes writers. NEED_WAKEUP and
completion tracking avoid reusing kernel-owned buffers. Idle receive uses
blocking polling; this backend does not continuously busy-poll.

BPF links refuse an existing XDP attachment. Nonmatching traffic passes to the
network stack; only matching tunnel traffic redirects to an XSK. Cleanup
detaches this program, removes XSK map entries, closes resources and unmaps
memory. A bounded same-mode bind retry handles asynchronous kernel teardown
without replacing another live owner.

Limits:
- Linux 5.9+ with AF_XDP, eBPF, bpf_link XDP attachment and suitable privileges.
- Hardware zero-copy additionally requires native driver support.
- Interface MTU <=3826 (4096-byte single-buffer frames with headroom).
- Multi-buffer jumbo frames and live RX-queue reconfiguration are unsupported.
- Memory-lock limits must cover per-queue UMEM and BPF allocations.
- Tests verified native-copy and generic-copy on veth. No zero-copy-capable
  hardware was available, so actual NIC zero-copy execution remains unverified.

AF_PACKET uses TPACKET_V3 RX for both transmit options. The ring transmitter
uses a separate protocol-zero TPACKET_V2 socket and about 1 MiB of mmap TX
storage. Publishing and reclaiming slots uses atomic ownership status, with
blocking/backoff under pressure. Concurrent writers are synchronized.
Neither transmitter enables qdisc bypass. PACKET_TX_RING is not guaranteed
NIC zero-copy.

Unlike AF_PACKET tapping, successful XDP redirection consumes matching frames.
The AF_PACKET protocols 6/17 kernel-isolation requirement remains documented in
README.md. The application does not install production firewall rules.

## Measured backend choice

On the supplied Ubuntu 24.04 / Linux 6.8 / 2-vCPU server, use identical isolated
veth namespaces, default MTU 1500, protocol 200/UDP framing, 128 requests in flight,
and 3-second measurements. Three repetitions alternate sendmmsg/ring order;
the middle repetition reverses order. CPU is summed client/server process CPU
per delivered datagram, excluding system-wide softirq and Python CPU.

| Payload | sendmmsg Mbps | TX ring Mbps | AF_XDP native-copy Mbps |
|---|---:|---:|---:|
| 64 bytes |7.622|7.790|10.329|
| 512 bytes |62.474|57.888|74.788|
| 1400 bytes |161.587|175.100|211.764|

| Payload | sendmmsg CPU us/reply | TX ring CPU us/reply | AF_XDP native-copy CPU us/reply |
|---|---:|---:|---:|
| 64 bytes |67.617|67.458|52.538|
| 512 bytes |68.245|76.179|58.053|
| 1400 bytes |71.575|65.667|55.516|

All runs had zero unanswered requests after the bounded drain. Startup logs
confirm the requested transmitters and AF_XDP native-copy mode after zero-copy
bind rejection. These are median local echo measurements, not Internet speeds.
AF_XDP runs occurred after the paired AF_PACKET runs; cross-backend comparisons
are indicative, not randomized statistical evidence.

**Default decision:** retain sendmmsg. TX ring improves 1400-byte throughput
about 8.4% and reduces CPU/reply about 8.3%, but regresses 512-byte throughput
about 7.3% with about 11.6% more CPU/reply. That is insufficient evidence to
switch the general-purpose default. Use -afpacket-tx ring explicitly for bulk
workloads and remeasure on the deployment NIC. AF_XDP remains opt-in.

These measurements do not include WireGuard encryption and do not establish
the maximum throughput between separate hosts or a 1-Gbps capability.
See [performance methodology](PERFORMANCE.md#what-the-benchmarks-establish)
and [WireGuard MTU/CPU troubleshooting](WIREGUARD.md).

## Reproduce

```sh
go test -race ./...
go vet ./...
sudo env SPOOFTUN_NETNS_TEST=1 go test -run TestNetworkNamespaceIntegration -v .
sudo bash scripts/netns-test.sh --backend afpacket --afpacket-tx sendmmsg --bench-only --benchmark --iterations 3
sudo bash scripts/netns-test.sh --backend afpacket --afpacket-tx ring --bench-only --benchmark --iterations 3
sudo bash scripts/netns-test.sh --backend xdp --bench-only --benchmark --iterations 3
```

The scripts create and delete only their own namespaces/veths. Privileged unit
tests also cover the actual kernel filter verifier, generic-copy RX/TX,
existing-program protection, close/reopen, and TX-ring wraparound; see the
opt-in environment variables in xdp_test.go and tx_ring_test.go.

References:
- [AF_XDP kernel documentation](https://docs.kernel.org/networking/af_xdp.html)
- [PACKET_MMAP kernel documentation](https://docs.kernel.org/networking/packet_mmap.html)

Raw Ubuntu test and benchmark evidence: [backend results](test-results/ubuntu-2026-10-23-backends/).

Validation passed: 24 backend/framing integration cases, race tests, real
kernel eBPF filter validation, native/generic-copy RX/TX, XDP owner/lifecycle
protection, TX-ring wraparound, vet, Staticcheck, formatting, and Linux amd64
and arm64 static builds. arm64 was cross-built, not executed.
