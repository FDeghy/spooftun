# Development

Run commands from the repository root. The module requires Go 1.27.3 and Linux; ordinary builds are pure Go. Native Windows `go test ./...` is not a meaningful validation because the Go files have Linux build tags. Package ownership: [[Package and entry points]].

## Verified in this inspection

On 2026-11-03, Go 1.27.3 on Windows/amd64 successfully ran `go list ./...`, a static Linux/amd64 build, Linux test compilation and Linux-targeted vet. PowerShell equivalents (choose output paths outside the source tree):

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'
go list ./...
go build -trimpath -o "$env:TEMP\spooftun-notes-linux-amd64" .
go test -c -o "$env:TEMP\spooftun-notes-linux-amd64.test" .
go vet ./...
```

The list returned only `spooftun`. Test compilation does **not** execute tests. WSL is unavailable on this host, so native tests, the race detector and privileged packet/network checks were not rerun here. These environment settings are for cross-compilation; use a fresh native Linux shell for the checks below.

## Linux workflow, checked against source and recorded evidence

| Command | Purpose / evidence |
| --- | --- |
| `CGO_ENABLED=0 go build -trimpath -o spooftun .` | Static executable; [README.md](../README.md), [CI build](../.github/workflows/build.yml). |
| `go test ./...` | Default tests; privileged opt-ins remain skipped. Declared in [CI](../.github/workflows/build.yml). |
| `go test -race -timeout 120s ./...` | Concurrency checks; recorded pass in [worker validation](../test-results/ubuntu-2026-10-30-multiqueue/README.md). Requires a race-supported native toolchain and cgo enabled. |
| `go vet ./...` | Static diagnostics; also verified here with Linux target. |
| `gofmt -l *.go` | Lists formatting deviations; CI requires empty output. |
| `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...` | Pinned additional analyzer from [CI](../.github/workflows/build.yml); not rerun here. |

CI defines native Linux amd64/arm64 jobs. A workflow definition is not evidence that a particular CI run passed. The historical results above describe their recorded sources, not a fresh native execution of today's working tree.

## Opt-in integration and kernel checks

Use root on a disposable Linux test host with `ip`, Bash, Python 3 and working iptables raw-table or nftables support. The namespace harness confines traffic and firewall rules to owned temporary namespaces/veths. No production interface is required.

```sh
sudo env PATH="$PATH" SPOOFTUN_NETNS_TEST=1 go test -timeout 360s \
  -run 'TestNetworkNamespaceIntegration|TestServerOutboundPortIntegration|TestNoiseIntegration' -v .
```

This selects backend/framing/GRO/worker cases, target-port remapping and noise delivery tests. The harness builds its own temporary binary unless `SPOOFTUN_BINARY` is supplied. Sources: [integration_test.go](../integration_test.go), [scripts/netns-test.sh](../scripts/netns-test.sh), [scripts/bench-netns.py](../scripts/bench-netns.py). Recorded worker reproduction: [multiqueue results](../test-results/ubuntu-2026-10-30-multiqueue/README.md).

Additional low-level tests require explicit opt-ins: `SPOOFTUN_XDP_TEST=1` for the XDP verifier; isolated veth names in `SPOOFTUN_XDP_TEST_IFACE` / `SPOOFTUN_XDP_TEST_PEER` for socket lifecycle tests, and `SPOOFTUN_TX_TEST_IFACE` / `SPOOFTUN_TX_TEST_PEER` for the TX ring. Inspect [xdp_test.go](../xdp_test.go) and [tx_ring_test.go](../tx_ring_test.go) before running them. Never point these at production interfaces.
