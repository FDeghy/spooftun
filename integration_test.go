//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "scripts/netns-test.sh")
	// Signal the whole harness so its EXIT trap can clean up namespaces even
	// when a hung subprocess reaches the test timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("network integration failed: %v\n%s", err, output)
	}
	var result struct {
		Status  string            `json:"status"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("invalid integration JSON: %v\n%s", err, output)
	}
	if result.Status != "passed" || len(result.Results) != 8 {
		t.Fatalf("incomplete integration results: %s", output)
	}
	t.Log(string(output))
}
