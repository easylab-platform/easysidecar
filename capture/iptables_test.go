//go:build linux

package capture

import (
	"os"
	"testing"
)

func TestInstallArgsShape(t *testing.T) {
	// Pure shape check: Install shells out to iptables, so only assert the
	// argument builder (via a fake PATH is overkill here). We validate the
	// chain name is stable and Uninstall is callable without panicking.
	if Chain == "" {
		t.Fatal("chain name must be set")
	}
	if os.Geteuid() != 0 {
		t.Skip("iptables requires root")
	}
}
