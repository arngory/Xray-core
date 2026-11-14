//go:build !windows

package internet_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

// A process that was killed leaves its socket file behind. The next one
// must listen on the same path all the same: it holds the lock, so the file
// is nobody's.
func TestListenOverStaleUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false) // as after SIGKILL
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no stale socket to test with: %v", err)
	}
	l, err := internet.ListenSystem(context.Background(), &net.UnixAddr{Name: path, Net: "unix"}, nil)
	if err != nil {
		t.Fatalf("listen over a stale socket: %v", err)
	}
	defer l.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial the new listener: %v", err)
	}
	c.Close()
}

// A path that holds something else than a socket is not removed.
func TestListenLeavesOtherFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := internet.ListenSystem(context.Background(), &net.UnixAddr{Name: path, Net: "unix"}, nil); err == nil {
		l.Close()
		t.Fatal("listened over a regular file")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "not a socket" {
		t.Fatalf("the file was touched: %q, %v", b, err)
	}
}
