set -euo pipefail
cd /root/spooftun-multiqueue-20261030-cKYlwW/source
export PATH=/root/spooftun-test-20261023/toolchain/golang.org/toolchain@v0.0.1-go1.27.3.linux-amd64/bin:$PATH
export GOPATH=/root/spooftun-test-20261023/gopath
export GOCACHE=/root/spooftun-test-20261023/buildcache
for round in 1 2 3; do
  order='single flow spread'
  if [ "$round" = 2 ]; then order='spread flow single'; fi
  for flows in 1 8; do
    for variant in $order; do
      workers=2
      distribution="$variant"
      if [ "$variant" = single ]; then workers=1; distribution=flow; fi
      SPOOFTUN_BINARY=../spooftun bash scripts/netns-test.sh --backend afpacket --packet-workers "$workers" --packet-distribution "$distribution" --bench-only --bench-fake-tcp --benchmark --flows "$flows" --duration 3 > "../bench-$variant-$flows-$round.json" 2> "../bench-$variant-$flows-$round.stderr"
      python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], [(b["payload_bytes"],b["echo_payload_mbps"],b["unanswered_after_drain"],b["duplicate_replies"]) for r in d["results"] for b in r.get("benchmarks",[])])' "../bench-$variant-$flows-$round.json"
    done
  done
done
