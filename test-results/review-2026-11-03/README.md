# Working-tree bug review — 2026-11-03

Five confirmed issues were fixed. One further confirmed AF_PACKET worker startup issue remains unresolved. Native Linux runtime verification is unavailable: this host is Windows/amd64 with Go 1.27.3, WSL is not installed, no container runtime was found, and the user confirmed no disposable Linux runner is available.

The review included the existing uncommitted forwarding changes and untracked `packet_workers.go` / `packet_workers_test.go`. Unrelated changes were preserved. No dependency, default, C program, or embedded BPF object was changed. Valid emitted wire formats remain unchanged; malformed input is now rejected more strictly.

## Findings, ordered by severity

### 1. P2 — frames queued before BPF attachment bypassed capture selection — fixed

Locations: `packet_io.go:88`, `packet_io.go:99`; fix in `bpf.go:35`, `bpf.go:46`, `client.go:106`, `server.go:138`.

Pinned gopacket v1.7.4 creates a protocol-enabled AF_PACKET socket, binds it and sets up its RX ring before returning from `NewTPacket` (`afpacket/afpacket.go:261`, `:271`, `:282` in the module cache). The project attaches BPF only afterward. Attaching a filter does not retroactively remove queued frames. Previously, the userspace loops rechecked only protocol and noninitial fragments.

An unrelated valid UDP packet queued during startup could therefore bypass the configured destination IP/port and create a server session delivering its payload to `127.0.0.1:<captured destination port>` (or the configured outbound override). Client delivery could similarly bypass the directional capture tuple if its destination port selected a live NAT entry.

The loops now apply an immutable userspace copy of the existing capture predicates before accessing NAT/session state: own-source-MAC exclusion, protocol, fragment offset, and the existing protocol-6/17 destination-IP/directional-port rules. Custom-protocol selection semantics remain unchanged.

Proof: concrete construction-order source evidence; `TestTunnelPacketFilterMatchesCaptureFilter` compares the new predicate with the independent BPF VM across protocols, directions, wildcard settings and matching/mismatching packets. The Windows portable VM suite passed. Native startup reproduction was not executed.

### 2. P2 — corrupted wire packets became freshly checksummed local UDP data — fixed

Locations: `framing.go:54`, `framing.go:131`; callers at `client.go:105`, `server.go:137`.

Both raw receive paths bypass normal kernel IPv4/transport validation. The old parsers accepted corrupt IPv4 headers and corrupt TCP/nonzero-UDP checksums; local UDP forwarding then produced a new valid checksum over that corrupt payload. Corrupted addresses could also affect routing/session identity.

IPv4 parsing now verifies the complete IHL header, including options. The shared tunnel transport parser verifies TCP and nonzero UDP checksums before forwarding. It uses cosmetic protocol 6/17 for the pseudoheader, matching the existing encoder even with custom outer protocols. UDP validation covers the declared UDP length. Legal omitted IPv4 UDP checksums, computed-zero TCP checksums and padded first fake fragments remain supported.

Proof before fix: `TestIPv4ChecksumValidation` failed with `corrupted IPv4 header accepted`; all 24 payload/checksum/pseudoheader corruption cases in `TestTunnelTransportChecksumValidation` failed because the transport was accepted. After fix, these tests, IPv4-options corruption, UDP trailing-byte coverage, computed-zero TCP checksum and existing serializer/framing tests passed, including Windows race detection.

Runtime limitation: AF_PACKET can expose offloaded skb checksum metadata that the current receiver API discards. Supported project senders emit complete wire checksums, but native Linux tests with offloads enabled are still required; portable tests do not establish that compatibility.

### 3. P2 — UDP length was ignored, violating datagram boundaries — fixed

Location: `framing.go:118`.

The UDP-shaped parser returned all bytes after its eight-byte header, regardless of the declared UDP length. It accepted zero, undersized and truncated lengths and included trailing IPv4 bytes in local application data.

It now requires `8 <= UDP length <= available IP payload`, returns exactly the declared datagram, and caps the returned slice at its boundary.

Proof: five of six cases in `TestFakeUDPLengthValidation` failed before the fix; all six passed afterward. Existing UDP/TCP and fake-fragment serializer round trips also passed.

### 4. P2 — valid frames can be duplicated during multiqueue startup — unresolved

Locations: `packet_workers.go:145`, `packet_workers.go:153`, together with `packet_io.go:88`.

With more than one receive worker, a later worker starts as a standalone receiving socket before `SetFanout` joins it to the existing group. A valid frame arriving in that interval can queue both in an existing group member and in the standalone socket. Joining fanout does not flush the socket's ring, so both copies can later be forwarded to the application. The userspace tuple fix above does not remove duplicate valid frames.

Evidence: project and pinned gopacket construction order, plus Linux `fanout_add`, which changes receive-hook registration without clearing queued ring data: [Linux v6.12 af_packet.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/packet/af_packet.c).

A complete fix needs controlled receive activation before fanout membership. The current gopacket API exposes neither preactivation filtering nor activation of a dormant socket. A drop filter attached after construction leaves a smaller race; timestamp cutoffs add clock/ordering assumptions. No unverified backend lifecycle rewrite or timestamp workaround was applied without a Linux reproducer. This affects `-packet-workers > 1`; the existing one-worker default does not have this particular duplication window.

### 5. P3 — maximum-size IPv4 frames were truncated by the capture filter — fixed

Location: `bpf.go:116`.

The supported maximum IPv4 MTU is 65,535, but BPF accepted only 65,535 bytes of the entire Ethernet frame. A 65,549-byte frame was truncated by 14 bytes and subsequently rejected as truncated IPv4.

The accepted capture length now includes the Ethernet header. `TestCaptureFilterFullIPv4Frame` failed before the fix with `capture=65535 frame=65549`, then passed in the BPF VM. Actual Linux socket-filter max-frame coverage was added to `TestCaptureFilterKernel`, but could not execute here.

### 6. P3 — TC unicast validation accepted limited broadcast — fixed

Location: `kernel_tc.go:72`; regressions in `kernel_tc_test.go:87`.

`255.255.255.255` passed validation for remote, source, destination-filter and expected peer-source settings, despite the required unicast endpoint invariant. These settings could reach the frozen BPF configuration and produce unusable forwarding or filtering.

The validator now explicitly rejects limited broadcast while preserving link-local unicast. All four broadcast cases failed before the fix and passed afterward; a link-local compatibility case also passed.

## Review coverage

| Subsystem | Traced invariants / outcome |
| --- | --- |
| Startup and CLI | Mode/backend/protocol/port/MTU/timeout validation, worker incompatibilities, TC restrictions and startup cleanup; TC broadcast and AF_PACKET startup findings above. |
| Client/server forwarding | Encoding, borrowed-frame lifetime, reply address copies, directional capture rules, local destination remapping, noise acceptance accounting and reply goroutine ownership. |
| NAT/session state | Full identifier-space exhaustion, copied retained addresses, concurrent creation, atomic refresh versus retirement, identity-aware deletion and replacement. No additional confirmed bug. |
| Framing/encoder | IPv4 bounds, transport boundaries/checksums, padding, fragment model, MTU limits and serializer compatibility. |
| Local UDP | recvmmsg truncation, GRO control validation and segment boundaries, bounded copy queue, sparse flush, sendmmsg partial failures, GSO grouping/fallback and poller backpressure. No additional confirmed bug. |
| AF_PACKET/TX ring | Socket/ring setup, batch descriptors, partial writes, ring slot ownership, submission/waits and cleanup. Startup and max-frame findings above. |
| AF_XDP | Separate RX/TX UMEM pools, borrowed batch lifetime, FILL recycling, completions, TX backpressure, fallback classification, existing-attachment rejection and cleanup. No additional confirmed bug. |
| TC/eBPF | Go/C configuration ABI, hash manifest, immutable maps, tuple/fragment/bounds/MTU validation, incremental checksum error preservation, zero-checksum fallback, offloads, TCX conflict checks and owned-resource cleanup. C/object unchanged. |
| Network setup and support code | Interface/route/neighbor selection, ring sizing, noise, namespace harness ownership and Python syntax. No additional confirmed bug. |

Skills read/applied: installed `golang-how-to`, `golang-concurrency`, `golang-safety`, `golang-security`, `golang-error-handling`, `golang-gopls`, `golang-context`, `golang-testing`, `golang-troubleshooting`, `golang-cli`, `golang-lint`, `graphify`, and `surgical-patch`. All needed skill files were present. Knowledge notes and the existing graph supplied orientation; claims were verified against current source. The code graph was refreshed with `graphify update .`.

## Executed validation

All commands used Go 1.27.3. These results concern the final working tree, including existing uncommitted/untracked source.

| Check | Result and scope |
| --- | --- |
| `go test -race -count=1 config.go nat.go nat_test.go framing.go framing_test.go encoder.go encoder_test.go` | PASS, Windows/amd64, 2.837s. Explicit file selection runs portable production logic despite Linux build constraints; it does not execute Linux networking. |
| `go vet config.go nat.go nat_test.go framing.go framing_test.go encoder.go encoder_test.go` | PASS, Windows portable subset. |
| Focused pre-fix UDP/header/transport corruption regressions | Failed as described above, then passed after fixes. |
| Portable BPF VM suite and vet | PASS, final production copies; command and test adaptation below. |
| TC portable extraction harness | PASS: verbatim `tcOptions.validate`, configuration type and original `TestTCOptionsValidation`, `TestTCConfigABI`, `TestTCEmbeddedObjectMatchesSource`, with actual source/object/manifest fixtures copied. Covers validation, serialization offsets and hashes, not eBPF loading/execution. |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list ./...` | PASS: one package, `spooftun`. |
| Linux/amd64 `go build -trimpath -o <temporary binary> .` | PASS; cross-compilation only. |
| Linux/amd64 `go test -c -o <temporary test binary> .` | PASS; no tests executed. |
| Linux/amd64 `go vet ./...` | PASS. |
| Linux/arm64 build, test compilation and `go vet ./...`, with `CGO_ENABLED=0` | PASS; no arm64 tests executed. |
| Linux-targeted `gopls references` and `gopls check -severity=error` on changed production/tests | PASS, no error diagnostics. The general warning-level baseline also noted an existing unchecked `Scanner.Err` in ARP parsing; no reachable correctness bug was established from it. |
| `gofmt -l` on changed Go files; `git diff --check` | PASS. |
| Python `ast.parse` on `scripts/*.py` | PASS, all three scripts; syntax only. |
| `graphify update .` | PASS, refreshed code graph and backed up curated graph. Graph tool warned that unsupported/empty extraction of JSON evidence/settings produced no nodes. |

The portable BPF check used a temporary directory, unchanged copies of `bpf.go`, `config.go`, `framing.go`, `encoder.go`, `go.mod`, `go.sum`, and a copy of `bpf_test.go` with only the Linux kernel-test section and its `unix` import removed. It ran:

```powershell
go test -count=1 bpf.go config.go framing.go encoder.go bpf_test.go
go vet bpf.go config.go framing.go encoder.go bpf_test.go
```

The final VM test reported PASS in 1.858s. This is policy/VM execution on Windows, not Linux socket execution.

The gopls MCP `go_workspace` and `go_vulncheck {"pattern":"./..."}` checks executed under the Linux target. The first database fetch failed due sandbox DNS; a read-only network retry succeeded using the database updated 2026-11-02 22:01:43 UTC. It reported GO-2026-6860 and GO-2026-6866. The tool labeled affected packages as the standard library, but the actual advisories affect `golang.org/x/net/html`, fixed in x/net v0.62.0. Current x/net is v0.61.0; this project's dependency closure uses `golang.org/x/net/bpf`, not `golang.org/x/net/html`. The vulnerable HTML package is absent from the Linux build dependency list, so these are not confirmed reachable project bugs and no speculative dependency upgrade was applied.

Advisories: [GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860), [GO-2026-6866](https://pkg.go.dev/vuln/GO-2026-6866).

## Unexecuted checks and material gaps

- Native Linux `go test ./...` and whole-project `go test -race ./...`: unavailable. Windows portable race checks cover only the selected pure Go logic.
- Namespace/veth integration, actual Linux socket-filter regression, AF_PACKET startup reproduction, GRO/GSO kernel execution, TX-ring tests, XDP verifier/lifecycle/completions and TC verifier/rewrite/cleanup: unavailable. No production interfaces or firewall rules were changed.
- Hardware AF_XDP zero-copy, offload compatibility and throughput: unverified. No performance claim or measured optimization is made.
- Standalone staticcheck/golangci-lint/gosec were unavailable and were not installed. Vet, gopls and the vulnerability check ran as described.
- One confirmed bug remains: multiqueue startup duplication, finding 4. No further confirmed unfixed issue was identified in the reviewed source; this is not a proof that the project is bug-free.
