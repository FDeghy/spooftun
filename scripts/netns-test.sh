#!/usr/bin/env bash
# All traffic and route changes stay within two temporary network namespaces.
# Backend options are forwarded to both endpoints by bench-netns.py:
#   --backend afpacket|xdp --afpacket-tx sendmmsg|ring
# XDP attachment is confined to tun0 inside those namespaces.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $EUID -eq 0 ]] || { echo 'Network namespace tests require root.' >&2; exit 1; }
command -v ip >/dev/null
command -v python3 >/dev/null
WORK=$(mktemp -d)
CLIENT="stc-$$"
SERVER="sts-$$"
LEFT="stl$$"
RIGHT="str$$"
cleanup() {
  set +e
  for ns in "$CLIENT" "$SERVER"; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null; done
  done
  sleep 0.1
  for ns in "$CLIENT" "$SERVER"; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -KILL "$pid" 2>/dev/null; done
    ip netns del "$ns" 2>/dev/null
  done
  ip link del "$LEFT" 2>/dev/null
  ip link del "$RIGHT" 2>/dev/null
  rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
BIN=${SPOOFTUN_BINARY:-$WORK/spooftun}
if [[ -z ${SPOOFTUN_BINARY:-} ]]; then
  (cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" .)
fi
BIN=$(realpath "$BIN")
ip netns add "$CLIENT"
ip netns add "$SERVER"
ip link add "$LEFT" type veth peer name "$RIGHT"
ip link set "$LEFT" netns "$CLIENT"
ip link set "$RIGHT" netns "$SERVER"
ip -n "$CLIENT" link set "$LEFT" name tun0
ip -n "$SERVER" link set "$RIGHT" name tun0
ip -n "$CLIENT" addr add 192.0.2.1/24 dev tun0
ip -n "$SERVER" addr add 192.0.2.2/24 dev tun0
for ns in "$CLIENT" "$SERVER"; do
  ip -n "$ns" link set lo up
  ip -n "$ns" link set tun0 mtu 1500 up
  # AF_PACKET is a tap: it does not consume frames before the IP stack.
  # Suppress duplicate UDP delivery and TCP RSTs only inside these temporary
  # namespaces, after packet sockets have observed the tunnel frames.
  if command -v iptables >/dev/null &&
     ip netns exec "$ns" iptables -t raw -A PREROUTING -i tun0 -p tcp -j DROP &&
     ip netns exec "$ns" iptables -t raw -A PREROUTING -i tun0 -p udp -j DROP; then
    :
  elif command -v nft >/dev/null; then
    ip netns exec "$ns" nft -f - <<'NFT'
table inet spooftun_test {
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iifname "tun0" meta l4proto { tcp, udp } drop
  }
}
NFT
  else
    echo 'Protocol 6/17 tests require working iptables raw-table or nftables support inside temporary namespaces.' >&2
    exit 1
  fi
done
# Prepopulate only the isolated veth neighbors for both baseline and current
# builds. This keeps ARP setup out of measurements and lets historical builds
# whose UDP Dial did not actually trigger ARP run on a route without a gateway.
CLIENT_MAC=$(ip -n "$CLIENT" -o link show dev tun0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
SERVER_MAC=$(ip -n "$SERVER" -o link show dev tun0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
[[ -n "$CLIENT_MAC" && -n "$SERVER_MAC" ]] || { echo 'Cannot read isolated veth MAC addresses.' >&2; exit 1; }
ip -n "$CLIENT" neigh replace 192.0.2.2 lladdr "$SERVER_MAC" nud permanent dev tun0
ip -n "$SERVER" neigh replace 192.0.2.1 lladdr "$CLIENT_MAC" nud permanent dev tun0
python3 "$ROOT/scripts/bench-netns.py" --client-ns "$CLIENT" --server-ns "$SERVER" --binary "$BIN" "$@"
