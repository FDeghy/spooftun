//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// getInterfaceInfo returns the MAC address and IP of the specified interface
func getInterfaceInfo(name string) (mac net.HardwareAddr, ip net.IP, err error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s not found: %v", name, err)
	}
	mac = iface.HardwareAddr
	if mac == nil {
		return nil, nil, fmt.Errorf("interface %s has no MAC address", name)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get addresses for %s: %v", name, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				ip = ipv4
				break
			}
		}
	}

	if ip == nil {
		return nil, nil, fmt.Errorf("interface %s has no IPv4 address", name)
	}

	return mac, ip, nil
}

// findDefaultInterface finds the interface used for routing to the given destination
func findDefaultInterface(dstIP net.IP) (string, error) {
	if dstIP == nil {
		dstIP = net.ParseIP("8.8.8.8")
	}

	conn, err := net.DialTimeout("udp4", dstIP.String()+":80", time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to determine route: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localAddr.IP) {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find interface for %s", localAddr.IP)
}

// parseARPCache only accepts complete Ethernet entries on the selected interface.
func parseARPCache(r io.Reader, iface string, ip net.IP) net.HardwareAddr {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != ip.String() || fields[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(fields[2], 0, 32)
		if err != nil || flags&2 == 0 { // ATF_COM: a complete hardware address
			continue
		}
		hardwareType, err := strconv.ParseUint(fields[1], 0, 32)
		if err != nil || hardwareType != 1 { // ARPHRD_ETHER
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err == nil && len(mac) == 6 && mac[0]&1 == 0 && !allZeroMAC(mac) {
			return mac
		}
	}
	return nil
}

func allZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func lookupARPCache(iface string, ip net.IP) net.HardwareAddr {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer file.Close()
	return parseARPCache(file, iface, ip)
}

// routeNextHop selects the longest matching UP route on iface in Linux's main
// IPv4 routing table. Equal prefixes use the lowest metric. A direct route must
// resolve the destination itself; an unresolved direct neighbor must never fall
// back to an unrelated default gateway.
func routeNextHop(r io.Reader, iface string, dstIP net.IP) (net.IP, error) {
	dst := dstIP.To4()
	if dst == nil {
		return nil, fmt.Errorf("destination must be IPv4")
	}
	destination := binary.LittleEndian.Uint32(dst)
	bestPrefix, bestMetric := -1, ^uint64(0)
	var nextHop net.IP
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[0] != iface {
			continue
		}
		network, e1 := strconv.ParseUint(fields[1], 16, 32)
		gateway, e2 := strconv.ParseUint(fields[2], 16, 32)
		flags, e3 := strconv.ParseUint(fields[3], 16, 32)
		metric, e4 := strconv.ParseUint(fields[6], 10, 64)
		mask, e5 := strconv.ParseUint(fields[7], 16, 32)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || flags&1 == 0 {
			continue
		}
		maskBytes := make(net.IPMask, 4)
		binary.LittleEndian.PutUint32(maskBytes, uint32(mask))
		prefix, bits := maskBytes.Size()
		if bits != 32 || destination&uint32(mask) != uint32(network)&uint32(mask) {
			continue
		}
		if prefix < bestPrefix || prefix == bestPrefix && metric >= bestMetric {
			continue
		}
		bestPrefix, bestMetric = prefix, metric
		nextHop = nil
		if flags&0x200 != 0 {
			continue
		} // RTF_REJECT wins over a less specific route
		if flags&2 == 0 {
			nextHop = append(net.IP(nil), dst...)
		} else if gateway != 0 {
			nextHop = net.IPv4(byte(gateway), byte(gateway>>8), byte(gateway>>16), byte(gateway>>24))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}
	if nextHop == nil {
		return nil, fmt.Errorf("no usable IPv4 route to %s on %s", dstIP, iface)
	}
	return nextHop, nil
}

// getNeighborMAC resolves the routed next hop rather than assuming every
// off-link destination uses the first default gateway in /proc/net/route.
func getNeighborMAC(iface string, dstIP net.IP) (net.HardwareAddr, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	nextHop, err := routeNextHop(file, iface, dstIP)
	file.Close()
	if err != nil {
		return nil, err
	}
	if mac := lookupARPCache(iface, nextHop); mac != nil {
		return mac, nil
	}

	// Dial alone does not send a datagram and therefore need not initiate ARP.
	// Pin the actual probe to the same device used by the AF_PACKET socket.
	dialer := net.Dialer{
		Timeout: 500 * time.Millisecond,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var bindErr error
			if err := raw.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
	conn, err := dialer.Dial("udp4", net.JoinHostPort(nextHop.String(), "1"))
	if err != nil {
		return nil, fmt.Errorf("probe neighbor %s on %s: %w", nextHop, iface, err)
	}
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Write([]byte{0})
	conn.Close()
	if err != nil {
		return nil, fmt.Errorf("probe neighbor %s on %s: %w", nextHop, iface, err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if mac := lookupARPCache(iface, nextHop); mac != nil {
			return mac, nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("could not resolve neighbor %s on %s", nextHop, iface)
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {
	const mib = 1024 * 1024
	maxInt := int(^uint(0) >> 1)
	if targetSizeMb <= 0 || targetSizeMb > maxInt/mib || snaplen <= 0 || pageSize < 16 || pageSize&(pageSize-1) != 0 {
		return 0, 0, 0, fmt.Errorf("invalid packet ring size, snaplen, or page size")
	}
	budget := targetSizeMb * mib
	if snaplen > budget || pageSize > budget {
		return 0, 0, 0, fmt.Errorf("interface buffersize is too small")
	}
	// A power-of-two frame is 16-byte aligned and divides any larger Linux
	// page. Integer division of pageSize by a slot count can produce frames
	// that violate both constraints, notably with small MTUs or 64 KiB pages.
	frameSize = 16
	for frameSize < snaplen {
		if frameSize > maxInt/2 {
			return 0, 0, 0, fmt.Errorf("packet frame size overflows int")
		}
		frameSize *= 2
	}
	blockSize = max(pageSize, frameSize)
	if blockSize > budget {
		return 0, 0, 0, fmt.Errorf("interface buffersize is too small")
	}
	// Prefer 128 frames per block, reducing the block for small requested
	// rings. Both divisibility requirements survive each power-of-two step.
	desiredBlock := budget
	if frameSize <= budget/128 {
		desiredBlock = frameSize * 128
	}
	for blockSize < desiredBlock && blockSize <= budget/2 {
		blockSize *= 2
	}
	numBlocks = budget / blockSize
	return frameSize, blockSize, numBlocks, nil
}
