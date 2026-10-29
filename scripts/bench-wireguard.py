#!/usr/bin/env python3
"""Real iperf3 over isolated veth / WireGuard / WireGuard+spooftun paths.

Requires root, ip, iptables, wg and iperf3. Nothing is attached to production
interfaces. Both endpoints share this host; results are not WAN capacity.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def process_cpu(pid):
    fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')


def host_cpu():
    return [int(n) for n in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--wg', default='wg')
    parser.add_argument('--path', choices=['direct', 'wireguard', 'afpacket', 'ring', 'xdp'], required=True)
    parser.add_argument('--output', required=True, help='New directory for JSON and process logs')
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--streams', type=int, default=1)
    parser.add_argument('--udp-rate', help='iperf3 offered rate, e.g. 1G; omitted means TCP')
    parser.add_argument('--raw-udp', action='store_true', help='Measure spooftun UDP capacity without WireGuard; TCP control uses a separate proxy')
    parser.add_argument('--udp-load', help='Native scripts/udp-load.c executable; replaces iperf3 with a batched UDP generator and validating sink')
    parser.add_argument('--wg-mtu', type=int, default=1420)
    parser.add_argument('--proto', type=int, default=6)
    parser.add_argument('--tcp-flags', default='0x18')
    parser.add_argument('--spoof', action='store_true', help='Use a test-only source IP and explicit return IP')
    parser.add_argument('--extra', action='append', default=[], help='Extra spooftun argument; use --extra=-flag=value')
    opts = parser.parse_args()
    if os.geteuid() != 0 or opts.seconds < 1 or opts.streams < 1:
        parser.error('requires root and positive seconds/streams')
    if opts.raw_udp and (not opts.udp_rate or opts.path not in ('afpacket', 'ring', 'xdp')):
        parser.error('--raw-udp requires a tunnel path and --udp-rate')
    if opts.udp_load and (not opts.udp_rate or opts.reverse or opts.streams != 1):
        parser.error('--udp-load requires --udp-rate, one stream and forward direction')
    for tool in ['ip', 'iptables', 'iperf3', opts.wg]:
        if not shutil.which(tool):
            parser.error('missing tool: ' + tool)
    binary = str(Path(opts.binary).resolve())
    out = Path(opts.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    prefix = 'stp%d' % os.getpid()
    client, server = prefix + 'c', prefix + 's'
    left, right = prefix + 'l', prefix + 'r'
    namespaces, processes, logs, tunnels = [], [], [], []

    def ns(name, *args, **kwargs):
        return run('ip', 'netns', 'exec', name, *args, **kwargs)

    def start(name, label, command):
        log = (out / (label + '.log')).open('w')
        logs.append(log)
        p = subprocess.Popen(['ip', 'netns', 'exec', name, *command], stdout=log, stderr=log)
        processes.append(p)
        return p

    try:
        for name in [client, server]:
            run('ip', 'netns', 'add', name)
            namespaces.append(name)
        run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        for name, dev, address in [(client, left, '192.0.2.1'), (server, right, '192.0.2.2')]:
            run('ip', 'link', 'set', dev, 'netns', name)
            run('ip', '-n', name, 'link', 'set', dev, 'name', 'tun0')
            run('ip', '-n', name, 'addr', 'add', address + '/24', 'dev', 'tun0')
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            run('ip', '-n', name, 'link', 'set', 'tun0', 'mtu', '1500', 'up')
        for name, other, address in [(client, server, '192.0.2.2'), (server, client, '192.0.2.1')]:
            mac = json.loads(run('ip', '-n', other, '-j', 'link', 'show', 'tun0'))[0]['address']
            run('ip', '-n', name, 'neigh', 'replace', address, 'lladdr', mac, 'nud', 'permanent', 'dev', 'tun0')
        tunnel = opts.path in ('afpacket', 'ring', 'xdp')
        if tunnel:
            # Only tunnel protocol/ports are suppressed. Direct iperf control
            # and unrelated traffic are left alone within these namespaces.
            for name, direction in [(server, '--dport'), (client, '--sport')]:
                if opts.proto in (6, 17):
                    ns(name, 'iptables', '-t', 'raw', '-A', 'PREROUTING', '-i', 'tun0',
                       '-p', str(opts.proto), direction, '40000', '-j', 'DROP')
            common = [binary, '-iface', 'tun0', '-proto', str(opts.proto), '-fake-tcp',
                      '-tcp-flags', opts.tcp_flags, '-target-port', '40000', '-mtu', '1500',
                      '-backend', 'xdp' if opts.path == 'xdp' else 'afpacket', *opts.extra]
            if opts.path == 'ring':
                common += ['-afpacket-tx', 'ring']
            server_args = ['-remote-ip', '192.0.2.1'] if opts.spoof else []
            client_args = ['-src-ip', '198.51.100.1', '-filter-dst-ip', '192.0.2.1'] if opts.spoof else []
            tunnels.append(start(server, 'spooftun-server', common + ['-mode', 'server', '-outbound-port', '51820', *server_args]))
            tunnels.append(start(client, 'spooftun-client', common + ['-mode', 'client', '-listen', '127.0.0.1:18081',
                                                                  '-remote-ip', '192.0.2.2', *client_args]))
        dest = '192.0.2.2'
        if opts.raw_udp and not opts.udp_load:
            # iperf3's TCP control connection is distinct from its UDP data.
            # Relay only that control stream; every UDP byte uses spooftun.
            proxy = '''import socket, select
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',18081)); s.listen(1)
a,_=s.accept(); b=socket.create_connection(('192.0.2.2',51820))
while True:
 for c in select.select([a,b],[],[])[0]:
  data=c.recv(65536)
  if not data: raise SystemExit
  (b if c is a else a).sendall(data)
'''
            start(client, 'iperf-control', [sys.executable, '-c', proxy])
        elif not opts.raw_udp and opts.path != 'direct':
            private = [run(opts.wg, 'genkey') for _ in range(2)]
            public = [run(opts.wg, 'pubkey', input=k + '\n') for k in private]
            for i, name in enumerate([client, server]):
                run('ip', '-n', name, 'link', 'add', 'wg0', 'type', 'wireguard')
                endpoint = (['endpoint', '127.0.0.1:18081'] if i == 0 else []) if tunnel else [
                    'endpoint', ('192.0.2.2' if i == 0 else '192.0.2.1') + ':51820']
                ns(name, opts.wg, 'set', 'wg0', 'listen-port', '51820', 'private-key', '/dev/stdin',
                   'peer', public[1-i], 'allowed-ips', '10.203.0.%d/32' % (2-i), *endpoint, input=private[i] + '\n')
                run('ip', '-n', name, 'addr', 'add', '10.203.0.%d/24' % (i+1), 'dev', 'wg0')
                run('ip', '-n', name, 'link', 'set', 'wg0', 'mtu', str(opts.wg_mtu), 'up')
            dest = '10.203.0.2'
        time.sleep(0.5)
        for p in tunnels:
            if p.poll() is not None:
                raise RuntimeError('spooftun startup failed; inspect logs')
        ns(client, 'ping', '-c', '3', '-W', '3', dest)
        if opts.udp_load:
            load = str(Path(opts.udp_load).resolve())
            ip, port = ('127.0.0.1', '51820') if opts.raw_udp else (dest, '18080')
            sink = start(server, 'udp-receiver', [load, 'receive', ip, port])
            time.sleep(0.2)
            rate = opts.udp_rate.upper()
            mbps = float(rate[:-1]) * (1000 if rate.endswith('G') else 1) if rate[-1] in 'MG' else float(rate) / 1e6
            command = [load, 'send', '127.0.0.1' if opts.raw_udp else dest,
                       '18081' if opts.raw_udp else port, str(min(1360, opts.wg_mtu - 28)), str(opts.seconds), str(mbps)]
            cpu0, host0 = [process_cpu(p.pid) for p in tunnels], host_cpu()
            started = time.monotonic()
            sender = json.loads(ns(client, *command, timeout=opts.seconds + 30))
            time.sleep(1)  # Bounded drain, explicitly included in conservative rate.
            sink.terminate()
            if sink.wait(timeout=3) != 0:
                raise RuntimeError('native receiver failed; inspect udp-receiver.log')
            elapsed = time.monotonic() - started
            receiver = json.loads((out / 'udp-receiver.log').read_text())
            cpu1, host1 = [process_cpu(p.pid) for p in tunnels], host_cpu()
            summary = {'scope': 'same-host isolated veth; native validated UDP; drain-inclusive rate; not WAN capacity',
                       'settings': vars(opts), 'sender': sender, 'receiver': receiver,
                       'received_mbps': receiver['received_bytes'] * 8 / elapsed / 1e6,
                       'received_mbps_send_interval': receiver['received_bytes'] * 8 / sender['duration_seconds'] / 1e6,
                       'lost_datagrams': sender['sent_datagrams'] - receiver['received_datagrams'],
                       'tunnel_cpu_seconds': [b-a for a,b in zip(cpu0,cpu1)], 'elapsed_seconds': elapsed,
                       'host_cpu_tick_deltas': dict(zip(['user','nice','system','idle','iowait','irq','softirq','steal'],
                                                      [b-a for a,b in zip(host0,host1)])), 'load_command': command}
            (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            print(json.dumps(summary), flush=True)
            if (receiver['corrupt'] or receiver['sequence_overflows'] or summary['lost_datagrams'] < 0 or
                    receiver['received_datagrams'] + receiver['missing_through_highest'] > sender['sent_datagrams']):
                raise RuntimeError('native UDP verification failed')
            return
        server_cmd = ['iperf3', '-s', '-B', '0.0.0.0' if opts.raw_udp else dest, '-1', '-J']
        if opts.raw_udp:
            server_cmd += ['-p', '51820']
        start(server, 'iperf-server', server_cmd)
        time.sleep(0.2)
        cmd = ['iperf3', '-c', '127.0.0.1' if opts.raw_udp else dest, '-t', str(opts.seconds), '-P', str(opts.streams), '-J', '--get-server-output']
        if opts.raw_udp:
            cmd += ['-p', '18081']
        if opts.reverse:
            cmd += ['-R']
        if opts.udp_rate:
            cmd += ['-u', '-b', opts.udp_rate, '-l', str(min(1360, opts.wg_mtu - 28))]
        cpu0, host0, started = [process_cpu(p.pid) for p in tunnels], host_cpu(), time.monotonic()
        report = json.loads(ns(client, *cmd, timeout=opts.seconds + 30))
        elapsed = time.monotonic() - started
        cpu1, host1 = [process_cpu(p.pid) for p in tunnels], host_cpu()
        (out / 'iperf.json').write_text(json.dumps(report, indent=2) + '\n')
        if 'error' in report:
            raise RuntimeError(report['error'])
        end = report['end']
        receiver = end.get('sum_received', end.get('sum', {}))
        if opts.udp_rate:
            # The server report contains authoritative receiver counts for uplink.
            remote = report.get('server_output_json', {}).get('end', {})
            receiver = end.get('sum_received') or (end if opts.reverse else remote).get('sum', receiver)
        deltas = [b-a for a,b in zip(host0,host1)]
        summary = {'scope': 'same-host isolated veth, both endpoints share CPU; not a WAN measurement',
                   'settings': vars(opts), 'received_mbps': receiver['bits_per_second'] / 1e6,
                   'receiver': receiver, 'tunnel_cpu_seconds': [b-a for a,b in zip(cpu0,cpu1)],
                   'elapsed_seconds': elapsed, 'host_cpu_tick_deltas': dict(zip(
                       ['user','nice','system','idle','iowait','irq','softirq','steal'], deltas)),
                   'iperf_command': cmd}
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary), flush=True)
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
        for p in processes:
            try:
                p.wait(timeout=3)
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
    main()
