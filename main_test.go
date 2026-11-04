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
