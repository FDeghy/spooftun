# Base64 noise content validation — 2026-10-25

Ubuntu 24.04.5, Linux 6.8.0-146-generic, Go 1.27.3, amd64.
Network tests used disposable namespaces and veths with scoped ingress
isolation. All test namespaces were removed afterward.

`-noise-payload` accepts padded or unpadded standard Base64. The wire UDP
payload is the internal 8-byte marker followed by the decoded bytes. Empty
configuration retains the existing 32-byte random noise format. Sending still
happens once per flow, before its first outgoing data packet.

## Native network checks

`noise-base64-integration.log` records:

```sh
SPOOFTUN_NETNS_TEST=1 go test -timeout 120s -run TestNoiseIntegration -v .
```

All 14 cases passed; each configuration runs UDP and UDP with fake fragmentation:

| Backend | Noise sender | Content | Cases |
|---|---|---|---:|
| AF_PACKET/sendmmsg | Both | Default random | 2 |
| AF_PACKET/TX ring | Both | Default random | 2 |
| XDP native-copy | Both | Default random | 2 |
| AF_PACKET/sendmmsg | Client only | Default random | 2 |
| AF_PACKET/sendmmsg | Server only | Default random | 2 |
| AF_PACKET/sendmmsg | Client only | `AP9oZWxsbw==` | 2 |
| XDP native-copy | Both | `AP9oZWxsbw` | 2 |

The custom content decodes to `00 ff 68 65 6c 6c 6f`, including binary NUL
and 0xff. The ten AF_PACKET cases capture Ethernet frames with ETH_P_ALL;
custom-content captures assert exact decoded bytes after the marker. Each
enabled direction sends two noise packets for two flows and ten data packets,
without repeated noise for later data. Disabled senders emit no noise.

The four XDP cases verify application delivery; XDP redirection bypasses this
AF_PACKET capture path. Zero-copy is unavailable on these veths, and native
copy mode was used. These are correctness checks, not bandwidth measurements.

Application checks preserve ordinary payloads, including marker-like data,
empty datagrams and MTU boundaries. Noise does not reach the application.

## Other checks

- `noise-base64-unit.log`: full native `go test -race -timeout 90s ./...` passes.
- `noise-base64-focused.log`: 20 race-detector repetitions of Base64 decoding
  and custom-content framing/MTU tests pass. These verify buffer ownership,
  checksum and marker recognition, real-data collision preservation, and zero
  allocations during encoding. At MTU 1500, 1464 content bytes fit and 1465
  are rejected; the marker uses another eight bytes.
- `noise-base64-cli.log`: missing `-noise`, malformed Base64, MTU 1500/68
  oversize content, and global oversize content are rejected before packet I/O.
- Linux-targeted vet, Staticcheck, formatting and static amd64/arm64 builds
  pass. arm64 was cross-built, not executed.

`noise-base64-sources.sha256` matches the tested Go sources, module files and
network test script byte-for-byte. Both peers must be updated for variable
noise lengths. AF_PACKET still requires the ingress isolation documented in
[README.md](../../README.md#noise-before-udp-data).
