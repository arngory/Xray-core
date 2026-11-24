package main

import (
	"testing"

	"github.com/xtls/xray-core/common/memlimit"
)

// The line names the cgroup's limits, the host and the limit set; a limit
// at or above the host is "none".
func TestMemoryLine(t *testing.T) {
	l := memlimit.Limits{Max: 512 << 20, High: 8 << 30, MemTotal: 4 << 30}
	n := l.GoLimit(goLimitNum, goLimitDen)
	if n != 420<<20 { // 512 MiB / 16 * 15 = 480 MiB; 7/8 of it
		t.Fatalf("GoLimit %d MiB, want 420", n>>20)
	}
	want := "Memory: cgroup's memory.max 512 MiB, memory.high none, host 4096 MiB: Go memory limit 420 MiB (7/8 of the less of high and 15/16 of max, 64 MiB at least)"
	if got := memoryLine(l, n); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
