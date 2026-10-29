#!/usr/bin/env python3
"""Isolated TC kernel forwarding correctness test. Requires root, ip, tc, ethtool."""
import argparse
from collections import Counter
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def payloads():
    return [bytes((i * 17 + size) % 256 for i in range(size)) for size in (0, 1, 3, 37, 1200, 1460)]


def gro_payloads():
    return [struct.pack('!I', i) + bytes([i]) * 1196 for i in range(33)] + [b'GSO-short-tail' * 2 + b'end']


def server_worker(out):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('198.18.0.1', 51820))
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw.bind(('tun0', 0))
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    received, wire, bad_wire, udp_leaks = [], [], 0, 0
    (out / 'server-ready').write_text('ready')
    while not stopped:
        for current in select.select([udp, raw], [], [], 0.1)[0]:
            if current is udp:
                data, address = udp.recvfrom(65535)
                received.append(data.hex())
                udp.sendto(data, address)
                continue
            frame, address = raw.recvfrom(65535)
            if address[2] == socket.PACKET_OUTGOING or len(frame) < 42 or frame[12:14] != b'\x08\x00':
                continue
            ihl = (frame[14] & 15) * 4
            if ihl < 20 or len(frame) < 14 + ihl + 8:
                continue
            src, dst = frame[26:30], frame[30:34]
            ports = struct.unpack('!HH', frame[14 + ihl:18 + ihl])
            if ports != (51820, 40000):
                continue
            if frame[23] == 17:
                udp_leaks += 1
                continue
            if frame[23] != 6 or src != socket.inet_aton('198.51.100.1') or dst != socket.inet_aton('192.0.2.2'):
                continue
            length = struct.unpack('!H', frame[16:18])[0]
            tcp = frame[14 + ihl:14 + length]
            assert ihl == 20 and len(tcp) >= 20 and tcp[12:14] == b'\x50\x06', 'wire TCP shape changed'
            assert checksum(frame[14:34]) == 0, 'bad wire IP checksum'
            pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
            if checksum(pseudo + tcp):
                assert tcp[20:] == b'intentionally-bad-checksum', 'unexpected invalid wire checksum'
                bad_wire += 1
            else:
                wire.append(tcp[20:].hex())
    result = {'received': received, 'wire_payloads': wire, 'bad_wire_checksums': bad_wire, 'plaintext_udp_leaks': udp_leaks}
    (out / 'server-result.json').write_text(json.dumps(result, indent=2) + '\n')


def client_worker(src_mac, dst_mac):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('198.18.0.1', 51820))
    udp.connect(('198.18.0.2', 40000))
    udp.settimeout(2)
    for data in payloads():
        udp.send(data)
        assert udp.recv(65535) == data, 'datagram boundary/content changed'
    segments = gro_payloads()
    gso_supported = True
    try:
        udp.sendmsg([b''.join(segments)], [(socket.IPPROTO_UDP, 103, struct.pack('H', 1200))])
    except OSError as error:
        if error.errno not in (errno.EIO, errno.ENOPROTOOPT, errno.EOPNOTSUPP, errno.EINVAL):
            raise
        # The owned veth disables TX checksum offload so TC receives complete
        # checksums. Linux can reject UDP_SEGMENT on this route. Such callers
        # must retry ordinary datagrams; do not report this as GSO coverage.
        gso_supported = False
        for data in segments:
            udp.send(data)
    got = [udp.recv(65535) for _ in segments]
    assert Counter(got) == Counter(segments), 'GSO segments changed, duplicated or lost'
    oversize = False
    try:
        udp.send(b'x' * 1461)
    except OSError as error:
        if error.errno != errno.EMSGSIZE:
            raise
        oversize = True
    if not oversize:
        udp.settimeout(0.3)
        try:
            udp.recv(65535)
            raise AssertionError('oversized datagram forwarded')
        except socket.timeout:
            oversize = True
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw.bind(('tun0', 0))
    src, dst = socket.inet_aton('198.51.100.1'), socket.inet_aton('192.0.2.2')

    def inject(data, corrupt=False):
        tcp = struct.pack('!HHIIBBHHH', 51820, 40000, 1, 0, 0x50, 0x06, 65535, 0, 0)
        value = checksum(src + dst + struct.pack('!BBH', 0, 6, 20 + len(data)) + tcp + data)
        if corrupt:
            value ^= 1
        tcp = tcp[:16] + struct.pack('!H', value) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(data), 0, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        ethernet = bytes.fromhex(dst_mac.replace(':', '')) + bytes.fromhex(src_mac.replace(':', '')) + b'\x08\x00'
        raw.send(ethernet + ip + tcp + data)

    inject(b'intentionally-bad-checksum', True)
    udp.settimeout(0.5)
    try:
        udp.recv(65535)
        raise AssertionError('invalid TCP checksum reached UDP application')
    except socket.timeout:
        pass
    inject(b'valid-raw-control')
    udp.settimeout(2)
    assert udp.recv(65535) == b'valid-raw-control', 'valid raw control failed'
    print(json.dumps({'status': 'passed', 'normal_datagrams': len(payloads()),
                      'batch_datagrams': len(segments), 'gso_datagrams': len(segments) if gso_supported else 0,
                      'gso_supported': gso_supported, 'gso_fallback': not gso_supported,
                      'oversize_rejected': oversize, 'invalid_checksum_rejected': True, 'valid_raw_control': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root')
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary, script = str(Path(args.binary).resolve()), str(Path(__file__).resolve())
    prefix = 'stct%d' % os.getpid()
    client, server, left, right = [prefix + c for c in 'cslr']
    namespaces, processes, logs = [], [], []

    def run(*cmd, **kwargs):
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=20, **kwargs)
        if result.returncode:
            raise RuntimeError('command failed: %r\n%s\n%s' % (cmd, result.stdout, result.stderr))
        return result.stdout.strip()

    def ns(name, *cmd):
        return run('ip', 'netns', 'exec', name, *cmd)

    def start(name, label, cmd):
        log = (out / (label + '.log')).open('w')
        logs.append(log)
        p = subprocess.Popen(['ip', 'netns', 'exec', name, *cmd], stdout=log, stderr=log)
        processes.append(p)
        return p

    try:
        for name in [client, server]:
            run('ip', 'netns', 'add', name)
            namespaces.append(name)
        run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        for name, dev, addr in [(client, left, '192.0.2.1'), (server, right, '192.0.2.2')]:
            run('ip', 'link', 'set', dev, 'netns', name)
            run('ip', '-n', name, 'link', 'set', dev, 'name', 'tun0')
            run('ip', '-n', name, 'addr', 'add', addr + '/24', 'dev', 'tun0')
            run('ip', '-n', name, 'link', 'set', 'tun0', 'up')
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        macs = {n: json.loads(run('ip', '-n', n, '-j', 'link', 'show', 'tun0'))[0]['address'] for n in namespaces}
        for name, other, addr in [(client, server, '192.0.2.2'), (server, client, '192.0.2.1')]:
            run('ip', '-n', name, 'neigh', 'add', addr, 'lladdr', macs[other], 'nud', 'permanent', 'dev', 'tun0')
        baseline_interfaces = {
            name: sorted(i['ifname'] for i in json.loads(run('ip', '-n', name, '-j', 'link', 'show')))
            for name in namespaces
        }
        common = [binary, '-backend', 'tc', '-iface', 'tun0', '-proto', '6', '-fake-tcp', '-tcp-flags', '0x06',
                  '-target-port', '40000', '-tc-local-port', '51820']
        server_cmd = common + ['-mode', 'server', '-remote-ip', '192.0.2.1', '-tc-peer-port', '51820', '-tc-peer-src-ip', '198.51.100.1']
        client_cmd = common + ['-mode', 'client', '-remote-ip', '192.0.2.2', '-src-ip', '198.51.100.1', '-filter-dst-ip', '192.0.2.1']
        tunnels = [start(server, 'server', server_cmd), start(client, 'client', client_cmd)]
        deadline = time.monotonic() + 15
        while not all('packet backend=tc ready' in (out / (n + '.log')).read_text() for n in ['server', 'client']):
            if any(p.poll() is not None for p in tunnels) or time.monotonic() > deadline:
                raise RuntimeError('TC startup failed/timed out; inspect logs')
            time.sleep(0.1)
        # Choose a different virtual subnet so conflict testing reaches the TCX
        # ownership check instead of merely tripping the subnet overlap guard.
        conflict = subprocess.run(['ip', 'netns', 'exec', client, *client_cmd, '-tc-address', '198.18.1.1/30'],
                                  text=True, capture_output=True, timeout=15)
        (out / 'conflict.log').write_text(conflict.stdout + conflict.stderr)
        assert conflict.returncode and 'existing TCX ingress programs' in conflict.stderr, 'existing TCX owner not protected'
        echo = start(server, 'application', [sys.executable, script, '--worker-server', str(out)])
        deadline = time.monotonic() + 5
        while not (out / 'server-ready').exists():
            if echo.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('echo/capture startup failed')
            time.sleep(0.05)
        checks = json.loads(ns(client, sys.executable, script, '--worker-client', macs[client], macs[server]))
        ns(client, 'ping', '-c', '1', '-W', '2', '192.0.2.2')
        echo.terminate()
        assert echo.wait(timeout=3) == 0
        captured = json.loads((out / 'server-result.json').read_text())
        expected = [p.hex() for p in payloads() + gro_payloads() + [b'valid-raw-control']]
        assert Counter(captured['received']) == Counter(expected), 'application received unexpected/lost/duplicate payloads'
        assert Counter(captured['wire_payloads']) == Counter(expected), 'wire capture differs from application payloads'
        assert captured['bad_wire_checksums'] == 1 and captured['plaintext_udp_leaks'] == 0
        for p in tunnels:
            p.terminate()
        for p in tunnels:
            assert p.wait(timeout=10) == 0, 'TC exit/cleanup failed'
        after_interfaces = {}
        for name in namespaces:
            interfaces = json.loads(run('ip', '-n', name, '-j', 'link', 'show'))
            after_interfaces[name] = sorted(i['ifname'] for i in interfaces)
            assert after_interfaces[name] == baseline_interfaces[name], 'interface inventory changed after shutdown'
            routes = json.loads(run('ip', '-n', name, '-j', 'route', 'show', 'table', 'all'))
            assert not any(r.get('dst', '').startswith('198.18.') for r in routes), 'owned route remains after shutdown'
        checks.update(wire_checksums=True, wire_flags='0x06', spoofed_source='198.51.100.1', plaintext_udp_leaks=0,
                      ownership_conflict=True, unrelated_ping=True, cleanup=True,
                      baseline_interfaces=baseline_interfaces, after_interfaces=after_interfaces)
        (out / 'summary.json').write_text(json.dumps(checks, indent=2) + '\n')
        print(json.dumps(checks))
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
        for p in processes:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs:
            log.close()
        for name in reversed(namespaces):
            subprocess.run(['ip', 'netns', 'del', name], capture_output=True)
        for dev in [left, right]:
            subprocess.run(['ip', 'link', 'del', dev], capture_output=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--worker-server':
        server_worker(Path(sys.argv[2]))
    elif len(sys.argv) > 1 and sys.argv[1] == '--worker-client':
        client_worker(sys.argv[2], sys.argv[3])
    else:
        main()
