package main

// fork: raycontrol docs/spec/memory-v1.md §3: the Go memory limit from the
// process's cgroup (FORK.md §6).

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/xtls/xray-core/common/memlimit"
)

// The Go memory limit's share of the cgroup's limit (memlimit.GoLimit):
// 7/8, as raycontrol's other backends; the rest is for the sockets'
// buffers the kernel charges to the cgroup and the runtime does not see.
const goLimitNum, goLimitDen = 7, 8

// setMemoryLimit gives the Go runtime a memory limit from the process's
// cgroup at its start, when GOMEMLIMIT is not set and the cgroup has a
// limit below the host's memory; one line says so, with the figures.
// Without such a limit it does nothing: a soft limit at the host's memory
// would do nothing either. Go (1.27) reads cpu.max of its cgroup, not
// memory.max.
func setMemoryLimit() {
	l := memlimit.Read(memlimit.System)
	if n := memlimit.SetGoLimit(l, goLimitNum, goLimitDen, os.Getenv, debug.SetMemoryLimit); n > 0 {
		fmt.Println(memoryLine(l, n))
	}
}

// memoryLine is the line setMemoryLimit prints for the limit n it set.
func memoryLine(l memlimit.Limits, n int64) string {
	return fmt.Sprintf("Memory: cgroup's memory.max %s, memory.high %s, host %d MiB: Go memory limit %d MiB (%d/%d of the less of high and 15/16 of max, 64 MiB at least)",
		mibOrNone(l.Max, l), mibOrNone(l.High, l), l.MemTotal>>20, n>>20, goLimitNum, goLimitDen)
}

// mibOrNone is n in MiB, or "none" when it limits nothing below the host.
func mibOrNone(n int64, l memlimit.Limits) string {
	if (memlimit.Limits{Max: n, MemTotal: l.MemTotal}).Limit() == 0 {
		return "none"
	}
	return strconv.FormatInt(n>>20, 10) + " MiB"
}
