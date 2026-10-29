# Performance evidence — 2026-10-29

See [PERFORMANCE.md](../../PERFORMANCE.md#udp-receive-and-capacity-tests--2026-10-29)
for interpretation, commands and limitations. All measurements ran in disposable
veth namespaces on one shared two-vCPU Ubuntu server. Hardware zero-copy and
WAN throughput were not measured.

- `final-*` directories contain the final 30-second comparisons, plus the
  five-second GRO/fake-fragment correctness check. Their binaries are identified
  in each `summary.json`. The baseline is commit
  `e5579d595a85a1d075971b2e0203505dc78a886c`.
- Other directories retain exploratory results, including unsuccessful tuning
  experiments. Earlier `candidate-bin` tests precede the reusable fake-fragment
  scratch fix; those capacity runs did not enable fake fragmentation.
- `summary.json` indexes all measurements. Native UDP Mbps includes a one-second
  drain; iperf3 Mbps uses its receiver report. Do not compare these timing
  conventions as if identical. UDP loss is accepted sends minus unique receives.
- `sources.sha256` matches the final tested Go sources, module files and scripts
  byte for byte. `binaries.sha256` identifies the remote binaries. Line-ending
  conversion by Git can change raw file hashes after checkout.
- `final-unit.log` records a fresh `go test -count=1 -race -timeout 120s ./...`.
  `final-integration.log` records 65 passing network cases: 48 framing/backend/GRO,
  14 noise and three outbound-port cases.
- `xdp-profile-*.txt` contains baseline Go CPU-profile summaries. The diagnostic
  helper and patch are included as text, not compiled into the product. Profiling
  starts at process initialization and stops after eight seconds, so includes
  setup/warmup. The logs report zero observed FILL/TX/wakeup waits in that interval.

Local final checks also passed: go vet, Staticcheck and CGO-disabled Linux
amd64/arm64 builds. arm64 was cross-built, not executed. No loss-free 1-Gbps
claim is made; real WireGuard over spooftun remained around 400 Mbps here.
