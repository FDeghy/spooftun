# AF_XDP fill-ring regression validation — 2026-10-24

Ubuntu 24.04.5, Linux 6.8.0-146-generic, Go 1.27.3, amd64.
Tests ran in the private test workspace on the authorized Ubuntu server.
Kernel packet tests used disposable network namespaces and veth peers;
the production interface was not attached to XDP. Test namespaces were removed.

## Before and after

`xdp-fill-before.log` runs the new regression tests against the previous
`xdp.go`. Both delayed-publication cases and the shutdown case fail with
`XDP fill ownership invariant violated`.

`xdp-fill-after.log` repeats those tests 20 times under the race detector
against the fix. All pass, including uint32 producer counter wraparound.
The reader retains its borrowed frame while FILL is full, resumes when the
kernel consumer advances, and can be interrupted by Close.

## Real kernel and integration checks

- `xdp-fill-kernel.log`: `go test -race -timeout 120s -count=10 -run TestXDP -v .`
  with `SPOOFTUN_XDP_TEST=1`, `SPOOFTUN_XDP_TEST_IFACE=txa`, and
  `SPOOFTUN_XDP_TEST_PEER=txb` inside an isolated namespace. Both native-copy
  and generic-copy tests receive 128 bursts of 64 packets per repetition:
  **163,840 packets**, checked individually for contents and order, with no
  errors or timeouts. Also verifies real TX, filter behavior, attachment
  ownership, and close/reopen.
- `xdp-fill-suite.log`: `go test -race -timeout 90s ./...` passes.
- `xdp-fill-integration.log`:
  `SPOOFTUN_NETNS_TEST=1 go test -timeout 90s -run TestNetworkNamespaceIntegration/xdp -v .`
  passes all eight XDP framing/protocol cases with native-copy startup evidence.
- Local Linux-targeted vet, Staticcheck, formatting, and static amd64/arm64
  builds pass. arm64 was cross-built, not executed.

`xdp-fill-sources.sha256` identifies the exact Go files used for these tests.
These are correctness checks, not bandwidth measurements or a guarantee for
every NIC/driver. Actual hardware zero-copy execution remains unverified.
