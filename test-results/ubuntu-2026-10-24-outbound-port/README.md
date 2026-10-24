# Server outbound-port validation — 2026-10-24

Ubuntu 24.04.5, Linux 6.8.0-146-generic, Go 1.27.3, amd64.
All network tests used disposable namespaces/veths. Production interfaces,
firewall rules, routes and applications were unchanged. Namespaces were removed.

## Duplicate reproduction and fix

`outbound-port-remap.log` runs:

```sh
SPOOFTUN_NETNS_TEST=1 go test -timeout 90s -run TestServerOutboundPortIntegration -v .
```

The echo application binds all server addresses. Normal kernel UDP processing
is deliberately enabled on the server namespace; the client retains its scoped
ingress isolation. Tunnel protocol is 17 with UDP framing and wire port 18080.

| Server backend | Local destination | Received copies for four requests |
|---|---:|---|
| AF_PACKET, inherited port (`-outbound-port 0`) | 18080 | 2, 2, 2, 2 |
| AF_PACKET, remapped (`-outbound-port 18082`) | 18082 | 1, 1, 1, 1 |
| XDP native-copy, remapped | 18082 | 1, 1, 1, 1 |

This reproduces the normal-stack plus spooftun duplicate path and verifies
single-copy application delivery when the server application uses a separate
port. Successful replies also verify that the server retains source port 18080
on the wire, matching the client's protocol-17 capture filter.

The test harness enables server kernel UDP only with
`SPOOFTUN_TEST_SERVER_KERNEL_UDP=1`, confined to its disposable namespace.
This is a test variable, not a production spooftun setting.

## Compatibility and checks

- `outbound-port-unit.log`: full `go test -race -timeout 90s ./...` passes.
- `outbound-port-legacy.log`: 24 existing backend/framing combinations pass
  with the default inherited local destination port.
- `outbound-port-framing.json`: all eight AF_PACKET framing/protocol cases pass
  with `--outbound-port 18082`, including fake TCP, fake fragments and actual
  protocols 6/17. Command: `bash scripts/netns-test.sh --backend afpacket --outbound-port 18082`.
- Native executable rejects `-outbound-port -1` and `-outbound-port 65536`
  before opening packet sockets.
- Linux-targeted vet, Staticcheck, formatting, and static amd64/arm64 builds
  pass; arm64 is cross-built, not executed here.

`outbound-port-sources.sha256` identifies the tested code and harness files.
CI now runs the duplicate/remap regression alongside namespace integration.
Port separation does not suppress client-side native UDP delivery, server ICMP
responses to an unused tunnel port, or TCP resets; the documented AF_PACKET
ingress-isolation requirements still apply.
