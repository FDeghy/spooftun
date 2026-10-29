//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Built from bpf/tc.c with scripts/build-tc-bpf.sh. Runtime needs no compiler.
//
//go:embed bpf/tc_bpfel.o
var tcObject []byte

// Must match struct tc_config in bpf/tc.c. IPs and ports are network-order bytes.
type tcConfig struct {
	LocalIP, PeerIP, WireLocalIP, WireSrcIP, WirePeerIP, WirePeerSrc [4]byte
	PhysicalIfindex, VethIfindex, MTU, TXFlags                       uint32
	LocalPort, RemotePort, WireLocalPort, WireRemotePort             [2]byte
	WireDstMAC, WireSrcMAC, LocalDstMAC, LocalSrcMAC                 [6]byte
}

type tcOptions struct {
	Iface, Mode, Address, RemoteIP, SourceIP, FilterIP, PeerSource string
	LocalPort, PeerPort, TargetPort, OutboundPort, MTU             int
	Flags                                                          uint8
}

func (o tcOptions) validate() (netip.Prefix, error) {
	if o.MTU < 80 || o.MTU > 1500 {
		return netip.Prefix{}, fmt.Errorf("TC supports requested outer MTU 80..1500")
	}
	if o.RemoteIP == "" {
		return netip.Prefix{}, fmt.Errorf("TC requires a fixed -remote-ip on both endpoints")
	}
	if o.Mode != "client" && o.Mode != "server" {
		return netip.Prefix{}, fmt.Errorf("invalid TC mode")
	}
	if o.LocalPort < 1 || o.LocalPort > 65535 || o.TargetPort < 1 || o.TargetPort > 65535 ||
		(o.Mode == "server" && (o.PeerPort < 1 || o.PeerPort > 65535)) {
		return netip.Prefix{}, fmt.Errorf("TC requires -tc-local-port 1..65535 and, on server, -tc-peer-port 1..65535")
	}
	if o.Mode == "client" && o.PeerPort != 0 {
		return netip.Prefix{}, fmt.Errorf("-tc-peer-port is server-only")
	}
	if o.OutboundPort != 0 && (o.Mode != "server" || o.OutboundPort != o.LocalPort) {
		return netip.Prefix{}, fmt.Errorf("TC -outbound-port must equal -tc-local-port on server")
	}
	for _, s := range []string{o.RemoteIP, o.SourceIP, o.FilterIP, o.PeerSource} {
		if s == "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return netip.Prefix{}, fmt.Errorf("TC requires unicast IPv4 addresses and a fixed -remote-ip on both endpoints")
		}
	}
	p, err := netip.ParsePrefix(o.Address)
	if err != nil || !p.Addr().Is4() || p.Bits() != 30 || p.Addr() != p.Masked().Addr().Next() ||
		!p.Addr().IsGlobalUnicast() {
		return netip.Prefix{}, fmt.Errorf("-tc-address must be IPv4 network+1/30, for example 198.18.0.1/30")
	}
	return p, nil
}

func tcCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, out)
	}
	return out, nil
}

type kernelTC struct {
	collection *ebpf.Collection
	links      []link.Link
	name       string
	index      int
}

func (k *kernelTC) Close() {
	for i := len(k.links) - 1; i >= 0; i-- {
		_ = k.links[i].Close()
	}
	k.links = nil
	if k.collection != nil {
		k.collection.Close()
		k.collection = nil
	}
	if k.name != "" {
		// Delete only the interface created by this instance, never a reused name.
		if dev, err := net.InterfaceByName(k.name); err == nil && (k.index == 0 || dev.Index == k.index) {
			if _, err := tcCommand("ip", "link", "del", "dev", k.name); err != nil {
				log.Printf("TC cleanup: %v", err)
			}
		}
		k.name = ""
	}
}

func (k *kernelTC) logStats() {
	if k.collection == nil {
		return
	}
	var totals [3]uint64
	for key := uint32(0); key < 3; key++ {
		var values []uint64
		if err := k.collection.Maps["stats"].Lookup(key, &values); err != nil {
			log.Printf("TC counters: %v", err)
			return
		}
		for _, n := range values {
			totals[key] += n
		}
	}
	log.Printf("TC kernel packets tx=%d rx=%d dropped=%d", totals[0], totals[1], totals[2])
}

func tcCheckRoutes(prefix netip.Prefix) error {
	out, err := tcCommand("ip", "-j", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var routes []struct {
		Dst string `json:"dst"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst == "default" || r.Dst == "" {
			continue
		}
		p, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			if a, e := netip.ParseAddr(r.Dst); e == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				continue
			}
		}
		if p.Bits() != 0 && p.Overlaps(prefix) {
			return fmt.Errorf("TC subnet %s overlaps existing route %s; choose unused -tc-address", prefix.Masked(), r.Dst)
		}
	}
	return nil
}

func openKernelTC(o tcOptions) (_ *kernelTC, err error) {
	prefix, err := o.validate()
	if err != nil {
		return nil, err
	}
	for _, tool := range []string{"ip", "tc", "ethtool"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, err
		}
	}
	physical, err := net.InterfaceByName(o.Iface)
	if err != nil {
		return nil, err
	}
	mac, localIP, err := getInterfaceInfo(o.Iface)
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("TC needs an IPv4 Ethernet interface: %v", err)
	}
	mtu := min(o.MTU, physical.MTU)
	if mtu < 80 || mtu > 1500 {
		return nil, fmt.Errorf("TC supports outer MTU 80..1500")
	}
	if err := tcCheckRoutes(prefix); err != nil {
		return nil, err
	}
	// Refuse existing consumers rather than silently changing their ordering.
	info, err := tcCommand("ip", "-j", "link", "show", "dev", o.Iface)
	if err != nil {
		return nil, err
	}
	var devices []map[string]json.RawMessage
	if err := json.Unmarshal(info, &devices); err != nil {
		return nil, err
	}
	for _, d := range devices {
		if x, ok := d["xdp"]; ok && string(x) != "null" && string(x) != "{}" {
			return nil, fmt.Errorf("TC refuses interface with an XDP attachment")
		}
	}
	filters, err := tcCommand("tc", "-j", "filter", "show", "dev", o.Iface, "ingress")
	if err != nil {
		return nil, err
	}
	var existing []json.RawMessage
	if err := json.Unmarshal(filters, &existing); err != nil {
		return nil, err
	}
	if len(existing) != 0 {
		return nil, fmt.Errorf("TC refuses existing ingress filters on %s", o.Iface)
	}
	query, err := link.QueryPrograms(link.QueryOptions{Target: physical.Index, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		return nil, fmt.Errorf("TC requires Linux 6.6+ TCX: %w", err)
	}
	if len(query.Programs) != 0 {
		return nil, fmt.Errorf("TC refuses existing TCX ingress programs")
	}
	peerMAC, err := getNeighborMAC(o.Iface, net.ParseIP(o.RemoteIP))
	if err != nil {
		return nil, err
	}
	if len(peerMAC) != 6 {
		return nil, fmt.Errorf("TC could not resolve peer/gateway Ethernet address")
	}
	k := &kernelTC{}
	defer func() {
		if err != nil {
			k.Close()
		}
	}()
	var random [4]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	name := "stc" + hex.EncodeToString(random[:])
	a, b := name+"a", name+"b"
	if _, err = tcCommand("ip", "link", "add", a, "type", "veth", "peer", "name", b); err != nil {
		return nil, err
	}
	k.name = a
	local, err := net.InterfaceByName(a)
	if err != nil {
		return nil, err
	}
	k.index = local.Index
	peer, err := net.InterfaceByName(b)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{a, b} {
		if _, err = tcCommand("ethtool", "-K", name, "tx", "off", "gso", "off", "tso", "off", "gro", "off", "tx-udp-segmentation", "off"); err != nil {
			return nil, err
		}
		features, e := tcCommand("ethtool", "-k", name)
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(string(features), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "on" {
				switch fields[0] {
				case "tx-checksumming:", "generic-segmentation-offload:", "generic-receive-offload:", "tx-udp-segmentation:":
					return nil, fmt.Errorf("TC requires disabled offload on owned veth: %s", line)
				}
			}
		}
		if _, err = tcCommand("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu-12)); err != nil {
			return nil, err
		}
	}
	var cfg tcConfig
	cfg.LocalIP, cfg.PeerIP = prefix.Addr().As4(), prefix.Addr().Next().As4()
	copy(cfg.WireLocalIP[:], localIP.To4())
	copy(cfg.WireSrcIP[:], localIP.To4())
	copy(cfg.WirePeerIP[:], net.ParseIP(o.RemoteIP).To4())
	cfg.WirePeerSrc = cfg.WirePeerIP
	if o.SourceIP != "" {
		copy(cfg.WireSrcIP[:], net.ParseIP(o.SourceIP).To4())
	}
	if o.FilterIP != "" {
		copy(cfg.WireLocalIP[:], net.ParseIP(o.FilterIP).To4())
	}
	if o.PeerSource != "" {
		copy(cfg.WirePeerSrc[:], net.ParseIP(o.PeerSource).To4())
	}
	cfg.PhysicalIfindex, cfg.VethIfindex, cfg.MTU, cfg.TXFlags = uint32(physical.Index), uint32(peer.Index), uint32(mtu), uint32(o.Flags)
	remotePort, wireLocal, wireRemote := o.TargetPort, o.LocalPort, o.TargetPort
	if o.Mode == "server" {
		remotePort, wireLocal, wireRemote = o.PeerPort, o.TargetPort, o.PeerPort
	}
	binary.BigEndian.PutUint16(cfg.LocalPort[:], uint16(o.LocalPort))
	binary.BigEndian.PutUint16(cfg.RemotePort[:], uint16(remotePort))
	binary.BigEndian.PutUint16(cfg.WireLocalPort[:], uint16(wireLocal))
	binary.BigEndian.PutUint16(cfg.WireRemotePort[:], uint16(wireRemote))
	copy(cfg.WireDstMAC[:], peerMAC)
	copy(cfg.WireSrcMAC[:], mac)
	copy(cfg.LocalDstMAC[:], local.HardwareAddr)
	copy(cfg.LocalSrcMAC[:], peer.HardwareAddr)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcObject))
	if err != nil {
		return nil, err
	}
	k.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load TC eBPF: %w", err)
	}
	if err = k.collection.Maps["config"].Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = k.collection.Maps["config"].Freeze(); err != nil {
		return nil, err
	}
	for _, attach := range []struct {
		idx  int
		prog string
		rev  uint64
	}{{peer.Index, "tc_out", 1}, {physical.Index, "tc_in", query.Revision}} {
		l, e := link.AttachTCX(link.TCXOptions{Interface: attach.idx, Program: k.collection.Programs[attach.prog], Attach: ebpf.AttachTCXIngress, ExpectedRevision: attach.rev})
		if e != nil {
			return nil, e
		}
		k.links = append(k.links, l)
	}
	if _, err = tcCommand("ip", "addr", "add", prefix.String(), "dev", a); err != nil {
		return nil, err
	}
	if _, err = tcCommand("ip", "neigh", "add", prefix.Addr().Next().String(), "lladdr", peer.HardwareAddr.String(), "nud", "permanent", "dev", a); err != nil {
		return nil, err
	}
	for _, name := range []string{a, b} {
		if _, err = tcCommand("ip", "link", "set", "dev", name, "up"); err != nil {
			return nil, err
		}
	}
	log.Printf("packet backend=tc ready iface=%s veth=%s/%s local=%s:%d endpoint=%s:%d outer-mtu=%d", o.Iface, a, b, prefix.Addr(), o.LocalPort, prefix.Addr().Next(), remotePort, mtu)
	return k, nil
}

func runKernelTC(iface string, upProto, downProto uint8) error {
	if upProto != 6 || downProto != 6 || !*fakeTCP || *fakeFrag || *noise || *udpGRO {
		return fmt.Errorf("TC requires -proto 6 -fake-tcp; fake-frag, noise and udp-gro are unsupported (use afpacket/xdp for those modes)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	k, err := openKernelTC(tcOptions{Iface: iface, Mode: *mode, Address: *tcAddress, RemoteIP: *tunnelIP, SourceIP: *customSrc, FilterIP: *filterDstIP, PeerSource: *tcPeerSrc, LocalPort: *tcLocalPort, PeerPort: *tcPeerPort, TargetPort: *targetPort, OutboundPort: *outboundPort, MTU: *tunnelMTU, Flags: tcpFlagByte})
	if err != nil {
		return err
	}
	defer k.Close()
	<-ctx.Done()
	k.logStats()
	return nil
}
