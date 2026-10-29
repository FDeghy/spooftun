//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in because the integration suite needs root and network namespaces.
// Run: SPOOFTUN_NETNS_TEST=1 go test -run TestNetworkNamespaceIntegration -v .
func TestNetworkNamespaceIntegration(t *testing.T) {
	if os.Getenv("SPOOFTUN_NETNS_TEST") != "1" {
		t.Skip("set SPOOFTUN_NETNS_TEST=1 to enable isolated Linux network tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network namespace integration requires root")
	}
	for _, configuration := range []struct {
		backend, tx string
		gro         bool
	}{
		{"afpacket", "sendmmsg", false}, {"afpacket", "ring", false}, {"xdp", "sendmmsg", false},
		{"afpacket", "sendmmsg", true}, {"afpacket", "ring", true}, {"xdp", "sendmmsg", true},
	} {
		name := configuration.backend + "/" + configuration.tx
		if configuration.gro {
			name += "/gro"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "scripts/netns-test.sh",
				"--backend", configuration.backend, "--afpacket-tx", configuration.tx)
			if configuration.gro {
				cmd.Args = append(cmd.Args, "--udp-gro")
			}
			// Signal the whole harness so its EXIT trap can clean up namespaces
			// even when a hung subprocess reaches the test timeout.
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
			cmd.WaitDelay = 10 * time.Second
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("network integration failed: %v\n%s", err, output)
			}
			var result struct {
				Status  string `json:"status"`
				Results []struct {
					Status         string              `json:"status"`
					BackendStartup map[string][]string `json:"backend_startup"`
				} `json:"results"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("invalid integration JSON: %v\n%s", err, output)
			}
			if result.Status != "passed" || len(result.Results) != 8 {
				t.Fatalf("incomplete integration results: %s", output)
			}
			for _, mode := range result.Results {
				if mode.Status != "passed" {
					t.Fatalf("framing mode did not pass: %s", output)
				}
				for _, endpoint := range []string{"client", "server"} {
					startup := strings.Join(mode.BackendStartup[endpoint], "\n")
					if !strings.Contains(startup, "packet backend="+configuration.backend) {
						t.Fatalf("%s missing actual backend startup evidence: %s", endpoint, output)
					}
					if configuration.backend == "afpacket" && !strings.Contains(startup, "tx="+configuration.tx) {
						t.Fatalf("%s missing actual AF_PACKET TX evidence: %s", endpoint, output)
					}
				}
			}
			t.Log(string(output))
		})
	}
}

func TestServerOutboundPortIntegration(t *testing.T) {
	if os.Getenv("SPOOFTUN_NETNS_TEST") != "1" {
		t.Skip("set SPOOFTUN_NETNS_TEST=1 to enable isolated Linux network tests")
	}
	for _, tc := range []struct{ name, backend, port string }{
		{"afpacket-reproduces-duplicates", "afpacket", "0"},
		{"afpacket-remapped", "afpacket", "18082"},
		{"xdp-remapped", "xdp", "18082"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "scripts/netns-test.sh", "--backend", tc.backend,
				"--verify-port-remap", "--outbound-port", tc.port)
			cmd.Env = append(os.Environ(), "SPOOFTUN_TEST_SERVER_KERNEL_UDP=1")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
			cmd.WaitDelay = 10 * time.Second
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("port remap failed: %v\n%s", err, output)
			}
			var result struct {
				Status  string `json:"status"`
				Results []struct {
					Checks struct {
						Copies []int `json:"received_copies_per_request"`
					} `json:"checks"`
				} `json:"results"`
			}
			if err := json.Unmarshal(output, &result); err != nil || result.Status != "passed" || len(result.Results) != 1 || len(result.Results[0].Checks.Copies) != 4 {
				t.Fatalf("invalid port remap evidence: %v\n%s", err, output)
			}
			for _, copies := range result.Results[0].Checks.Copies {
				if tc.port == "0" && copies < 2 || tc.port != "0" && copies != 1 {
					t.Fatalf("unexpected delivery count %d\n%s", copies, output)
				}
			}
			t.Log(string(output))
		})
	}
}

func TestNoiseIntegration(t *testing.T) {
	if os.Getenv("SPOOFTUN_NETNS_TEST") != "1" {
		t.Skip("set SPOOFTUN_NETNS_TEST=1 to enable isolated Linux network tests")
	}
	for _, tc := range []struct{ backend, tx, side, payload string }{
		{"afpacket", "sendmmsg", "both", ""}, {"afpacket", "ring", "both", ""},
		{"xdp", "sendmmsg", "both", ""}, {"afpacket", "sendmmsg", "client", ""},
		{"afpacket", "sendmmsg", "server", ""},
		{"afpacket", "sendmmsg", "client", "AP9oZWxsbw=="},
		{"xdp", "sendmmsg", "both", "AP9oZWxsbw"},
	} {
		name := tc.backend + "/" + tc.tx + "/" + tc.side
		if tc.payload != "" {
			name += "/base64"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "scripts/netns-test.sh", "--backend", tc.backend,
				"--afpacket-tx", tc.tx, "--noise", "--noise-side", tc.side, "--outbound-port", "18082")
			if tc.payload != "" {
				cmd.Args = append(cmd.Args, "--noise-payload", tc.payload)
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
			cmd.WaitDelay = 10 * time.Second
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("noise integration: %v\n%s", err, output)
			}
			var result struct {
				Status  string `json:"status"`
				Results []struct {
					Status string `json:"status"`
				} `json:"results"`
			}
			if err := json.Unmarshal(output, &result); err != nil || result.Status != "passed" || len(result.Results) != 2 {
				t.Fatalf("invalid noise evidence: %v\n%s", err, output)
			}
			for _, mode := range result.Results {
				if mode.Status != "passed" {
					t.Fatalf("noise framing failed: %s", output)
				}
			}
			t.Log(string(output))
		})
	}
}
