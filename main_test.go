//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCLIUnsupportedOptions(t *testing.T) {
	// Run main in a subprocess because flag parsing and log.Fatal exit.
	if os.Getenv("SPOOFTUN_CLI_TEST_HELPER") == "1" {
		main()
		return
	}
	for _, tt := range []struct {
		name, option, want string
	}{
		{"removed-backend", "-backend=tc", "Invalid -backend: use afpacket or xdp"},
		{"local-port", "-tc-local-port=51820", "flag provided but not defined: -tc-local-port"},
		{"peer-port", "-tc-peer-port=51820", "flag provided but not defined: -tc-peer-port"},
		{"address", "-tc-address=198.18.0.1/30", "flag provided but not defined: -tc-address"},
		{"peer-source", "-tc-peer-src-ip=192.0.2.1", "flag provided but not defined: -tc-peer-src-ip"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestCLIUnsupportedOptions$", tt.option)
			cmd.Env = append(os.Environ(), "SPOOFTUN_CLI_TEST_HELPER=1")
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), tt.want) {
				t.Fatalf("option %s: got %v, %s; want failure containing %q", tt.option, err, output, tt.want)
			}
		})
	}
}

func TestCLITUNOptions(t *testing.T) {
	if os.Getenv("SPOOFTUN_TUN_CLI_TEST_HELPER") == "1" {
		main()
		return
	}
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"missing-name", []string{"-tun-address=10.77.0.1/30"}, "-tun-address requires -tun"},
		{"missing-address", []string{"-tun=sttun0"}, "valid -tun-address CIDR"},
		{"missing-peer", []string{"-tun=sttun0", "-tun-address=10.77.0.1/30"}, "-remote-ip on both peers"},
		{"udp-only-option", []string{"-tun=sttun0", "-tun-address=10.77.0.1/30", "-remote-ip=192.0.2.2", "-udp-gro"}, "-tun cannot use"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestCLITUNOptions$"}, tt.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "SPOOFTUN_TUN_CLI_TEST_HELPER=1")
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), tt.want) {
				t.Fatalf("got %v, %s; want failure containing %q", err, output, tt.want)
			}
		})
	}
}
