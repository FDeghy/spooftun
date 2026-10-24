#!/usr/bin/env python3
"""Isolated correctness and bounded echo benchmark harness; stdlib only."""
import argparse
import base64
import json
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.abspath(__file__)
TARGET = ("127.0.0.1", 18080)
LOCAL = ("127.0.0.1", 18081)
NOISE_MAGIC = b"STNOISE\x01"


def target(outbound_port=0, public=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0" if public else TARGET[0], outbound_port or TARGET[1]))
    ports = set()
    count = 0
    while True:
        data, addr = sock.recvfrom(65535)
        if data == b"oneway-data":
            ports.add(addr[1])
            count += 1
        elif data == b"oneway-finish":
            sock.sendto(json.dumps({"ports": sorted(ports), "count": count}).encode(), addr)
            ports.clear()
            count = 0
        else:
            sock.sendto(data, addr)


def exchange(sock, data):
    sock.sendto(data, LOCAL)
    got = sock.recv(65535)
    if got != data:
        raise AssertionError("datagram mismatch: sent %d, received %d" % (len(data), len(got)))


def verify_noise_capture(capture, side, content=None):
    counts = {direction: {"noise": 0, "data": 0} for direction in ("client", "server")}
    pending = {direction: None for direction in counts}
    flows = {direction: set() for direction in counts}
    while True:
        try:
            frame = capture.recv(65535)
        except BlockingIOError:
            break
        if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17:
            continue
        if struct.unpack("!H", frame[20:22])[0] & 0x1fff:
            continue  # The non-initial fake-fragment tail has no UDP header.
        source = frame[26:30]
        direction = "client" if source == bytes([192, 0, 2, 1]) else "server"
        if source not in (bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])):
            continue
        total = struct.unpack("!H", frame[16:18])[0]
        body = frame[14 + (frame[14] & 15) * 4:14 + total]
        if len(body) < 8:
            raise AssertionError("truncated captured UDP frame")
        ports = body[:4]
        noise = (len(body) >= 16 and struct.unpack("!H", body[4:6])[0] == len(body) and body[6:8] == b"\x00\x00" and
                 body[8:16] == NOISE_MAGIC)
        expected = side in ("both", direction)
        if noise:
            if content is not None and body[16:] != content:
                raise AssertionError("decoded custom noise content changed on the wire")
            if not expected or pending[direction] is not None or ports in flows[direction]:
                raise AssertionError("unexpected or repeated noise packet")
            pending[direction] = ports
            counts[direction]["noise"] += 1
        else:
            if expected and ports not in flows[direction] and pending[direction] != ports:
                raise AssertionError("first data was not preceded by same-flow noise")
            pending[direction] = None
            flows[direction].add(ports)
            counts[direction]["data"] += 1
    for direction, count in counts.items():
        if pending[direction] is not None or count["data"] == 0:
            raise AssertionError("incomplete noise/data capture: %r pending=%r" % (counts, pending))
        if side in ("both", direction) and count["noise"] != len(flows[direction]):
            raise AssertionError("noise count does not match flow count")
        count["flows"] = len(flows[direction])
    return counts


def probe(limit, session, noise_side=None, capture_noise=False, noise_payload=""):
    content = base64.b64decode(noise_payload + "=" * (-len(noise_payload) % 4)) if noise_payload else None
    capture = None
    if capture_noise:
        # ETH_P_ALL receives outgoing taps as well as incoming IPv4 frames.
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        capture.bind(("tun0", 0))
        capture.setblocking(False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    # Wait for ARP resolution and both receive loops to be ready.
    for attempt in range(10):
        try:
            exchange(sock, b"ready")
            break
        except socket.timeout:
            if attempt == 9:
                raise
    sizes = [0, 1, 64, limit - 1, limit]
    for size in sizes:
        exchange(sock, bytes((i % 251 for i in range(size))))
    # Both slightly and substantially oversized UDP datagrams must be dropped,
    # not forwarded after truncation to a receive buffer or the configured MTU.
    for size in [limit + 1, 4096, 65507]:
        sock.sendto(b"x" * size, LOCAL)
        sock.settimeout(0.15)
        try:
            got = sock.recv(65535)
        except socket.timeout:
            pass
        else:
            raise AssertionError("oversized %d-byte datagram returned %d bytes" % (size, len(got)))
    sock.settimeout(1.0)
    exchange(sock, b"after-oversize")
    if noise_side:
        # Marker-like application data has a normal nonzero UDP checksum.
        marker_data = NOISE_MAGIC + (content if content is not None else bytes(24))
        if len(marker_data) <= limit:
            exchange(sock, marker_data)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            second.settimeout(1)
            exchange(second, b"second-flow-first")
            exchange(second, b"second-flow-next")
    result = {"accepted_sizes": sizes, "oversized_dropped": [limit + 1, 4096, 65507]}
    if session:
        end = time.monotonic() + 3.2
        sent = 0
        while time.monotonic() < end:
            sock.sendto(b"oneway-data", LOCAL)
            sent += 1
            time.sleep(0.05)
        sock.sendto(b"oneway-finish", LOCAL)
        info = json.loads(sock.recv(65535))
        if len(info["ports"]) != 1 or info["count"] != sent:
            raise AssertionError("active one-way session changed source port or lost data: %r" % info)
        result["active_oneway_session"] = info
    sock.close()
    if capture is not None:
        result["noise_wire_order"] = verify_noise_capture(capture, noise_side, content)
        capture.close()
    elif noise_side:
        result["noise_delivery"] = "application payloads preserved; wire capture covered by AF_PACKET runs"
    return result


def probe_duplicates(expect_duplicate):
    """Check actual app delivery while server ingress UDP remains enabled."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.2)
    counts = []
    try:
        for i in range(4):
            payload = b"port-remap-regression-" + str(i).encode()
            sock.sendto(payload, LOCAL)
            count = 0
            while True:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    break
                if data != payload:
                    raise AssertionError("unexpected reply during duplicate check")
                count += 1
            if count < 1 or (count > 1) != expect_duplicate:
                raise AssertionError("expected %s delivery, received %d copies" %
                                     ("duplicate" if expect_duplicate else "single", count))
            counts.append(count)
    finally:
        sock.close()
    return {"received_copies_per_request": counts,
            "server_kernel_udp_enabled": True,
            "expected_duplicate": expect_duplicate}


def cpu_seconds(pids):
    ticks = os.sysconf("SC_CLK_TCK")
    total = 0
    for pid in pids:
        # A process comm may contain spaces; fields after ')' begin at field 3.
        with open("/proc/%d/stat" % pid, encoding="ascii") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        total += int(fields[11]) + int(fields[12])
    return total / ticks


def benchmark(size, duration, pids):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    exchange(sock, b"warmup")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.setblocking(False)
    if size < 8:
        raise ValueError("benchmark payload must fit an 8-byte sequence number")
    sent = received = duplicates = expired = 0
    seen = set()
    pending = {}
    window = 128
    suffix = b"b" * (size - 8)

    def receive_one():
        nonlocal duplicates
        data = sock.recv(65535)
        if len(data) != size or data[8:] != suffix:
            raise AssertionError("benchmark payload mismatch")
        sequence = struct.unpack("!Q", data[:8])[0]
        if sequence >= sent:
            raise AssertionError("benchmark received unsent sequence")
        if sequence in seen:
            duplicates += 1
            return False
        seen.add(sequence)
        pending.pop(sequence, None)
        return True
    cpu0 = cpu_seconds(pids)
    start = time.monotonic()
    finish = start + duration
    last_expiry_check = start
    # Limit in-flight requests instead of flooding the socket until it drops.
    # Missing replies release their window slot after 200ms; they are counted,
    # not retransmitted, and late replies still count as unique deliveries.
    while time.monotonic() < finish:
        now = time.monotonic()
        if now - last_expiry_check >= 0.01:
            for sequence, sent_at in list(pending.items()):
                if now - sent_at >= 0.2:
                    del pending[sequence]
                    expired += 1
            last_expiry_check = now
        for _ in range(min(32, window - len(pending))):
            try:
                sock.sendto(struct.pack("!Q", sent) + suffix, LOCAL)
                pending[sent] = time.monotonic()
                sent += 1
            except BlockingIOError:
                break
        if len(pending) >= window:
            select.select([sock], [], [], min(0.001, max(0, finish - time.monotonic())))
        for _ in range(128):
            try:
                received += int(receive_one())
            except BlockingIOError:
                break
    elapsed = time.monotonic() - start
    cpu = cpu_seconds(pids) - cpu0
    # Throughput counts unique responses during the measurement interval.
    # A bounded drain separately records replies that were still in flight.
    late = 0
    drain_until = time.monotonic() + 0.25
    sock.settimeout(0.02)
    while time.monotonic() < drain_until:
        try:
            late += int(receive_one())
        except socket.timeout:
            pass
    sock.close()
    return {"payload_bytes": size, "duration_seconds": round(elapsed, 3),
            "sent_datagrams": sent, "received_datagrams": received,
            "duplicate_replies": duplicates, "late_replies": late,
            "expired_requests": expired, "max_inflight_datagrams": window,
            "unanswered_at_interval_end": sent - received,
            "unanswered_after_drain": sent - received - late,
            "echo_payload_mbps": round(received * size * 8 / elapsed / 1e6, 3),
            "echo_datagrams_per_second": round(received / elapsed),
            "tunnel_cpu_seconds": round(cpu, 3),
            "tunnel_cpu_cores": round(cpu / elapsed, 3),
            "tunnel_cpu_microseconds_per_delivered_datagram": round(cpu * 1e6 / received, 3) if received else None}


def run_in(ns, args, **kwargs):
    return subprocess.Popen(["ip", "netns", "exec", ns] + args, **kwargs)


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def read_tunnel_logs(logs):
    output = {}
    for endpoint, log in logs.items():
        log.flush()
        log.seek(0)
        output[endpoint] = log.read()
    return output


def orchestrate(args):
    results = []
    # Cover custom protocol with all framing variants and the special BPF
    # transport-port branches for real IPv4 protocol numbers 6 and 17.
    modes = [(200, False, False), (200, False, True), (200, True, False),
             (200, True, True), (17, False, False), (17, False, True),
             (6, True, False), (6, True, True)]
    if args.bench_only or args.baseline:
        modes = [(200, args.bench_fake_tcp, False)]
    if args.verify_port_remap:
        modes = [(17, False, False)]
    if args.noise:
        modes = [(17, False, False), (17, False, True)]
    with tempfile.TemporaryDirectory(prefix="spooftun-netns-") as work:
        echo_log = open(os.path.join(work, "echo.log"), "w+")
        echo = run_in(args.server_ns, [sys.executable, HERE, "--target",
                      "--outbound-port", str(args.outbound_port)] +
                      (["--public-target"] if args.verify_port_remap else []),
                      stdout=echo_log, stderr=echo_log)
        try:
            for proto, tcp, frag in modes:
                noise_options = ["-noise"] + (["-noise-payload", args.noise_payload] if args.noise_payload else [])
                common = ["-iface", "tun0", "-target-port", "18080", "-proto", str(proto)]
                if not args.baseline:
                    common += ["-session-timeout", "1s", "-backend", args.backend,
                               "-afpacket-tx", args.afpacket_tx]
                    if args.block_timeout:
                        common += ["-block-timeout", args.block_timeout]
                if tcp:
                    common += ["-fake-tcp"]
                if frag:
                    common += ["-fake-frag"]
                processes = []
                logs = {endpoint: open(os.path.join(work, endpoint + ".log"), "w+")
                        for endpoint in ("client", "server")}
                try:
                    server = run_in(args.server_ns, [args.binary, "-mode", "server"] + common +
                                    (["-outbound-port", str(args.outbound_port)] if args.outbound_port else []) +
                                    (noise_options if args.noise and args.noise_side in ("both", "server") else []),
                                    stdout=logs["server"], stderr=logs["server"])
                    processes.append(server)
                    client = run_in(args.client_ns, [args.binary, "-mode", "client", "-listen", "127.0.0.1:18081",
                                    "-remote-ip", "192.0.2.2"] + common +
                                    (noise_options if args.noise and args.noise_side in ("both", "client") else []),
                                    stdout=logs["client"], stderr=logs["client"])
                    processes.append(client)
                    for _ in range(10):
                        time.sleep(0.05)
                        if any(proc.poll() is not None for proc in processes) or echo.poll() is not None:
                            raise RuntimeError("tunnel or echo target exited during startup:\n" +
                                               json.dumps(read_tunnel_logs(logs)))
                    header = 20 if tcp else 8
                    limit = ((1500 - 20) // 8) * 8 - header - 1 if frag else 1500 - 20 - header
                    checks = {"skipped": "baseline performance run"}
                    if not args.baseline:
                        command = [sys.executable, HERE, "--probe", "--limit", str(limit)]
                        if args.noise:
                            command += ["--noise", "--noise-side", args.noise_side, "--backend", args.backend]
                            if args.noise_payload:
                                command += ["--noise-payload", args.noise_payload]
                        if args.verify_port_remap:
                            command += ["--verify-port-remap"]
                            if not args.outbound_port:
                                command += ["--expect-duplicate"]
                        if proto == 200 and not tcp and not frag:
                            command += ["--session"]
                        check = subprocess.run(["ip", "netns", "exec", args.client_ns] + command,
                                               capture_output=True, text=True, timeout=30)
                        if check.returncode:
                            raise RuntimeError("probe failed (proto=%d tcp=%s frag=%s): %s\n%s" %
                                               (proto, tcp, frag, check.stderr,
                                                json.dumps(read_tunnel_logs(logs))))
                        checks = json.loads(check.stdout)
                        if args.backend == "xdp":
                            # ICMP does not match any tunnel framing mode. A reply
                            # verifies that attached XDP leaves other IPv4 traffic
                            # on the namespace's normal network stack.
                            ping = subprocess.run(["ip", "netns", "exec", args.client_ns,
                                                   "ping", "-c", "1", "-W", "1", "192.0.2.2"],
                                                  capture_output=True, text=True, timeout=5)
                            if ping.returncode:
                                raise RuntimeError("XDP unmatched ICMP passthrough failed:\n%s\n%s\n%s" %
                                                   (ping.stdout, ping.stderr,
                                                    json.dumps(read_tunnel_logs(logs))))
                            checks["unmatched_icmp_passthrough"] = "passed"
                    # Preserve observed attachment/copy modes, excluding session
                    # traffic even when startup finishes during the first probe.
                    startup = {endpoint: [line for line in output.splitlines()
                                          if "New Session" not in line and
                                          any(marker in line for marker in
                                              ("packet backend=", "AF_XDP", "XDP"))]
                               for endpoint, output in read_tunnel_logs(logs).items()}
                    entry = {"protocol": proto, "fake_tcp": tcp, "fake_frag": frag,
                             "status": "passed", "checks": checks,
                             "backend_startup": startup}
                    if (args.benchmark or args.baseline) and proto == 200 and not frag and (not tcp or args.bench_fake_tcp):
                        entry["benchmarks"] = []
                        for size, iteration in [(size, i) for i in range(1, args.iterations + 1) for size in [64, 512, 1400]]:
                            try:
                                output = subprocess.check_output(["ip", "netns", "exec", args.client_ns,
                                    sys.executable, HERE, "--measure", "--size", str(size), "--duration", str(args.duration),
                                    "--pids", "%d,%d" % (client.pid, server.pid)], text=True, stderr=subprocess.STDOUT,
                                    timeout=args.duration + 10)
                            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                                raise RuntimeError("benchmark failed (%d bytes): %s\n%s\n%s" %
                                                   (size, exc, getattr(exc, "output", ""),
                                                    json.dumps(read_tunnel_logs(logs)))) from exc
                            measurement = json.loads(output)
                            measurement["iteration"] = iteration
                            entry["benchmarks"].append(measurement)
                    results.append(entry)
                finally:
                    for proc in reversed(processes):
                        stop(proc)
                    for log in logs.values():
                        log.close()
        finally:
            stop(echo)
            echo_log.close()
    return {"status": "passed", "network": "isolated veth network namespaces",
            "baseline_mode": args.baseline,
            "requested_backend": None if args.baseline else args.backend,
            "requested_afpacket_tx": None if args.baseline else args.afpacket_tx,
            "block_timeout": "baseline default" if args.baseline else (args.block_timeout or "current default"),
            "benchmark_scope": "Python echo harness, one flow; not an Internet bandwidth measurement",
            "results": results}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--client-ns")
    p.add_argument("--server-ns")
    p.add_argument("--binary")
    p.add_argument("--benchmark", action="store_true")
    p.add_argument("--bench-only", action="store_true")
    p.add_argument("--bench-fake-tcp", action="store_true", help="use fake TCP framing for the bench-only run")
    p.add_argument("--baseline", action="store_true", help="benchmark original defaults without correctness probes or new flags")
    p.add_argument("--backend", choices=("afpacket", "xdp"), default="afpacket")
    p.add_argument("--afpacket-tx", choices=("sendmmsg", "ring"), default="sendmmsg")
    p.add_argument("--duration", type=float, default=3)
    p.add_argument("--iterations", type=int, default=1)
    p.add_argument("--block-timeout", help="override current-build ring retirement duration, e.g. 1ms or 5ms")
    p.add_argument("--target", action="store_true")
    p.add_argument("--outbound-port", type=int, default=0, help="override server local UDP destination port")
    p.add_argument("--public-target", action="store_true", help="bind isolated test target on all addresses")
    p.add_argument("--verify-port-remap", action="store_true", help="check protocol-17 duplicate delivery")
    p.add_argument("--expect-duplicate", action="store_true")
    p.add_argument("--noise", action="store_true", help="test protocol-17 noise before real data")
    p.add_argument("--noise-side", choices=("both", "client", "server"), default="both")
    p.add_argument("--noise-payload", default="", help="Base64 content for noise sender tests")
    p.add_argument("--probe", action="store_true")
    p.add_argument("--limit", type=int)
    p.add_argument("--session", action="store_true")
    p.add_argument("--measure", action="store_true")
    p.add_argument("--size", type=int, default=1400)
    p.add_argument("--pids", default="")
    args = p.parse_args()
    if args.duration <= 0 or args.iterations < 1:
        p.error("duration and iterations must be positive")
    if args.target:
        target(args.outbound_port, args.public_target)
        return
    if args.probe:
        result = probe_duplicates(args.expect_duplicate) if args.verify_port_remap else probe(
            args.limit, args.session, args.noise_side if args.noise else None,
            args.noise and args.backend != "xdp", args.noise_payload)
    elif args.measure:
        result = benchmark(args.size, args.duration, [int(n) for n in args.pids.split(",")])
    else:
        if not all([args.client_ns, args.server_ns, args.binary]):
            p.error("use scripts/netns-test.sh to create the isolated network")
        result = orchestrate(args)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
