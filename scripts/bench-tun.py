#!/usr/bin/env python3
"""Isolated Linux multiqueue TUN correctness and iperf3 benchmark.

Both peers run on this host. Results measure packet processing, not WAN speed.
Requires root, ip, ping and iperf3. Never touches host routes or firewall rules.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--workers', type=int, default=1)
    ap.add_argument('--seconds', type=int, default=5)
    ap.add_argument('--repeat', type=int, default=3)
    ap.add_argument('--streams', type=int, default=4)
    ap.add_argument('--mtu', type=int, default=1500)
    ap.add_argument('--fake-tcp', action='store_true')
    ap.add_argument('--fake-frag', action='store_true')
    ap.add_argument('--verify-only', action='store_true')
    ap.add_argument('--direct', action='store_true')
    ap.add_argument('--ipv6', action='store_true', help='Run iperf3 over inner IPv6')
    opts = ap.parse_args()
    if os.geteuid() or min(opts.seconds, opts.repeat, opts.streams, opts.workers) < 1:
        ap.error('requires root and positive benchmark parameters')
    inner_mtu = opts.mtu-20-(20 if opts.fake_tcp else 8)
    if opts.fake_frag:
        inner_mtu = ((opts.mtu-20)//8)*8-(20 if opts.fake_tcp else 8)-1
    if opts.ipv6 and (opts.direct or inner_mtu < 1280):
        ap.error('--ipv6 requires TUN mode and an inner MTU of at least 1280')
    out = Path(opts.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = str(Path(opts.binary).resolve())
    prefix = 'stt%d' % os.getpid()
    client, server = prefix+'c', prefix+'s'
    namespaces, processes, logs = [], [], []

    def ns(name, *args):
        return run('ip', 'netns', 'exec', name, *args)

    def start(name, label, args):
        log = (out/(label+'.log')).open('w')
        logs.append(log)
        p = subprocess.Popen(['ip', 'netns', 'exec', name, *args], stdout=log, stderr=log)
        processes.append(p)
        return p

    def cpu(p):
        fields = Path('/proc/%d/stat' % p.pid).read_text().rsplit(')', 1)[1].split()
        return (int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')

    def io_calls(p):
        data = dict(line.split(':', 1) for line in Path('/proc/%d/io'%p.pid).read_text().splitlines())
        return {key:int(data[key]) for key in ('syscr','syscw')}

    results = {'options': vars(opts), 'kernel': run('uname', '-a').strip(),
               'cpus': os.cpu_count(), 'runs': []}
    try:
        for name in (client, server):
            run('ip', 'netns', 'add', name)
            namespaces.append(name)
        # Create the veth inside a namespace so failed setup leaves no host link.
        ns(client, 'ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'peer0')
        ns(client, 'ip', 'link', 'set', 'peer0', 'netns', server)
        ns(server, 'ip', 'link', 'set', 'peer0', 'name', 'eth0')
        for name, octet in ((client,1),(server,2)):
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
            ns(name, 'ip', 'address', 'add', '192.0.2.%d/30'%octet, 'dev', 'eth0')
            ns(name, 'ip', 'link', 'set', 'eth0', 'mtu', str(opts.mtu), 'up')
        tunnels = []
        if not opts.direct:
            for name, octet, mode in ((server,2,'server'),(client,1,'client')):
                args = [binary, '-mode', mode, '-iface', 'eth0', '-remote-ip', '192.0.2.%d'%(3-octet),
                        '-tun', 'sttun0', '-tun-address', '198.18.0.%d/30'%octet,
                        '-packet-workers', str(opts.workers), '-mtu', str(opts.mtu)]
                if opts.fake_tcp: args += ['-fake-tcp']
                if opts.fake_frag: args += ['-fake-frag']
                tunnels.append(start(name, mode, args))
            for _ in range(100):
                if any(p.poll() is not None for p in tunnels):
                    raise RuntimeError('tunnel exited; inspect process logs')
                try:
                    for name, process in zip((server, client), tunnels):
                        info = json.loads(ns(name, 'ip', '-j', 'link', 'show', 'sttun0'))[0]
                        assert info['mtu'] == inner_mtu, info
                        attached = sum('iff:\tsttun0' in f.read_text() for f in Path('/proc/%d/fdinfo'%process.pid).iterdir())
                        assert attached == opts.workers, (attached, opts.workers)
                    break
                except (subprocess.CalledProcessError, AssertionError):
                    time.sleep(.1)
            else: raise RuntimeError('TUN did not become ready')
            for name, octet in ((client,1),(server,2)):
                ns(name, 'ping', '-n', '-c', '3', '-i', '.1', '-W', '2', '-M', 'do', '-s', str(inner_mtu-28), '198.18.0.%d'%(3-octet))
                probe = subprocess.run(['ip','netns','exec',name,'ping','-n','-c','1','-W','1','-M','do','-s',str(inner_mtu-27),'198.18.0.%d'%(3-octet)], capture_output=True)
                assert probe.returncode != 0, 'oversized DF packet accepted'
                if inner_mtu >= 1280:
                    ns(name, 'ip', '-6', 'addr', 'add', 'fd42::%d/64'%octet, 'dev', 'sttun0', 'nodad')
            if inner_mtu >= 1280:
                for name, octet in ((client,1),(server,2)):
                    ns(name, 'ping', '-6', '-n', '-c', '2', '-i', '.1', '-W', '2', '-M', 'do', '-s', str(inner_mtu-48), 'fd42::%d'%(3-octet))
            # Validate UDP checksums and packet boundaries independently of
            # the TCP throughput workload.
            udp_server = 'import socket\ns=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\ns.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)\ns.bind(("::",18082))\nwhile True:\n d,a=s.recvfrom(65535); s.sendto(d,a)\n'
            start(server, 'udp-echo', ['python3', '-c', udp_server])
            time.sleep(.1)
            udp_client = 'import socket,sys\ns=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM)\ns.settimeout(3)\nfor n in (0,1,63,int(sys.argv[2])):\n d=bytes(i%251 for i in range(n)); s.sendto(d,(sys.argv[1],18082)); assert s.recv(65535)==d\n'
            ns(client, 'python3', '-c', udp_client, '198.18.0.2', str(inner_mtu-28))
            if inner_mtu >= 1280:
                ns(client, 'python3', '-c', udp_client, 'fd42::2', str(inner_mtu-48))
            results['verified'] = {'inner_mtu':inner_mtu, 'queues':opts.workers,
                                   'ipv4_max_df_both_directions':True, 'oversize_rejected':True,
                                   'ipv6_max_both_directions':inner_mtu >= 1280, 'udp_echo':True}
        else:
            results['verified'] = 'direct veth baseline'
        if not opts.verify_only:
            start(server, 'iperf3', ['iperf3','-s'])
            time.sleep(.3)
            target = '192.0.2.2' if opts.direct else ('fd42::2' if opts.ipv6 else '198.18.0.2')
            for repetition in range(opts.repeat):
                for reverse in (False, True):
                    before = [cpu(p) for p in tunnels]
                    io_before = [io_calls(p) for p in tunnels]
                    command = ['iperf3','-c',target,'-t',str(opts.seconds),'-P',str(opts.streams),'-J']
                    if reverse: command += ['-R']
                    data = json.loads(ns(client,*command))
                    if 'error' in data: raise RuntimeError(data['error'])
                    after = [cpu(p) for p in tunnels]
                    io_after = [io_calls(p) for p in tunnels]
                    label = '%d-%s'%(repetition,'reverse' if reverse else 'forward')
                    (out/(label+'.json')).write_text(json.dumps(data,indent=2))
                    end = data['end']
                    results['runs'].append({'repetition':repetition, 'reverse':reverse,
                        'bits_per_second':end['sum_received']['bits_per_second'],
                        'retransmits':end['sum_sent'].get('retransmits'),
                        'tunnel_cpu_seconds':[b-a for a,b in zip(before,after)],
                        'tunnel_io_calls':[{key:b[key]-a[key] for key in a} for a,b in zip(io_before,io_after)]})
        (out/'summary.json').write_text(json.dumps(results,indent=2))
        print(json.dumps(results,indent=2))
    finally:
        for p in reversed(processes):
            if p.poll() is None: p.terminate()
        for p in reversed(processes):
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
        for log in logs: log.close()
        for name in reversed(namespaces): run('ip','netns','del',name)


if __name__ == '__main__':
    main()
