//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
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

// lookupARPCache reads /proc/net/arp to find MAC for an IP
func lookupARPCache(ip net.IP) net.HardwareAddr {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header line

	ipStr := ip.String()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ipStr {
			mac, err := net.ParseMAC(fields[3])
			if err == nil && fields[2] != "0x0" { // 0x0 means incomplete
				return mac
			}
		}
	}
	return nil
}

// getNeighborMAC gets the MAC address for a destination IP (via ARP cache or probe)
func getNeighborMAC(iface string, dstIP net.IP) (net.HardwareAddr, error) {
	// First check ARP cache
	if mac := lookupARPCache(dstIP); mac != nil {
		return mac, nil
	}

	// Trigger ARP by sending a probe packet
	conn, err := net.DialTimeout("udp4", dstIP.String()+":1", 500*time.Millisecond)
	if err == nil {
		conn.Close()
	}

	// Wait for ARP to populate
	time.Sleep(200 * time.Millisecond)

	if mac := lookupARPCache(dstIP); mac != nil {
		return mac, nil
	}

	// Try default gateway
	return getDefaultGatewayMAC(iface)
}

// getDefaultGatewayMAC finds the default gateway and gets its MAC
func getDefaultGatewayMAC(iface string) (net.HardwareAddr, error) {
	// Read /proc/net/route to find default gateway
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		// Look for default route (Destination = 00000000)
		if fields[1] == "00000000" {
			// Gateway is in hex, little-endian (Linux)
			var gw uint32
			fmt.Sscanf(fields[2], "%x", &gw)

			gwIP := net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24))

			// Now get MAC for gateway
			if mac := lookupARPCache(gwIP); mac != nil {
				return mac, nil
			}

			// Trigger ARP for gateway
			conn, err := net.DialTimeout("udp4", gwIP.String()+":1", 500*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			time.Sleep(200 * time.Millisecond)

			if mac := lookupARPCache(gwIP); mac != nil {
				return mac, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find gateway MAC")
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}
