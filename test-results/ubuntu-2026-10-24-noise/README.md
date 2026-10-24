# Once-per-flow UDP noise validation — 2026-10-24

Ubuntu 24.04.5, Linux 6.8.0-146-generic, Go 1.27.3, amd64.
Tests used disposable namespaces/veths with scoped ingress isolation. Production
interfaces, routes, firewall rules and services were unchanged. Test namespaces
were removed afterward.

## Behavior verified

`-noise` sends one 32-byte marked UDP payload before the first outgoing data
packet of each local flow/session, using the same IPs and ports. Later packets
in that session send no further noise. Client state follows the NAT session;
server state follows its reply session. Session replacement resets the state.
Receivers discard marked noise even with local noise sending disabled.

`noise-integration.log` runs `SPOOFTUN_NETNS_TEST=1 go test -timeout 120s -run TestNoiseIntegration -v .`:

| Backend | Enabled side | Framing cases | Wire observations per enabled direction |
|---|---|---:|---|
| AF_PACKET/sendmmsg | both | UDP and UDP + fake frag | 2 flows, 2 noise, 10 data packets |
| AF_PACKET/TX ring | both | UDP and UDP + fake frag | 2 flows, 2 noise, 10 data packets |
| XDP native-copy | both | UDP and UDP + fake frag | End-to-end payload preservation |
| AF_PACKET/sendmmsg | client only | UDP and UDP + fake frag | Client: 2 noise; server: 0 noise; 10 data each |
| AF_PACKET/sendmmsg | server only | UDP and UDP + fake frag | Server: 2 noise; client: 0 noise; 10 data each |

All ten cases pass. Eight AF_PACKET cases capture actual Ethernet frames with
ETH_P_ALL, checking that noise precedes each flow's first data, ports match,
and no noise repeats for later data. Non-initial fake-fragment tails are excluded
from UDP counts. XDP redirection bypasses this AF_PACKET capture path, so XDP
cases establish application delivery correctness rather than independent wire
capture. Captured send order cannot guarantee Internet delivery order.

Application checks cover empty datagrams, MTU boundaries, whole-datagram
oversize rejection, and a real application payload identical to the noise
marker. Those real packets retain normal nonzero UDP checksums and survive.

## Other checks

- `noise-unit.log`: full native `go test -race -timeout 90s ./...` passes.
- `noise-focused.log`: 20 race-detector repetitions of focused noise and NAT
  lifecycle tests pass. Tests cover IP checksum/UDP length, zero allocation in
  encoding, random suffixes, buffer lifetime, truncation and invalid modes.
- Failed/partial-first-send tests verify that unsent noise remains pending, while
  accepted noise is not repeated, even if later frames in its batch fail.
- `noise-legacy.log`: 24 existing backend/framing cases and the three outbound
  port/duplicate-delivery regression cases pass with noise disabled.
- `noise-cli.log`: unsupported outgoing protocols, fake TCP and incompatible
  directional protocol overrides are rejected before packet sockets open.
- Linux-targeted vet, Staticcheck, formatting and static amd64/arm64 builds
  pass. arm64 was cross-built, not executed here.

`noise-sources.sha256` identifies the tested source snapshot. Hardware XDP
zero-copy remains unverified. AF_PACKET native kernel delivery still requires
the ingress isolation documented in [README.md](../../README.md#noise-before-udp-data).
