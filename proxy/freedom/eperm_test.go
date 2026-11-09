package freedom

import (
	goerrors "errors"
	gonet "net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/connlimit"
)

// EPERM from the kernel (the node's conntrack guard, its egress policy) is
// a dropped packet, with limits or without: the session lives and sends
// the next one. Upstream ends the session.
func TestEPERMDropsThePacketNotTheSession(t *testing.T) {
	for _, limits := range []*connlimit.Config{nil, {UDPLive: 8, UDPRate: 1, UDPBurst: 8}} {
		lt := newLimitTest(t, limits)
		ud := newUDPDialer()
		s := lt.start("u5", udpDest, ud, paid)
		pc := <-ud.conns
		refuse := true
		pc.writeErr = func() error {
			if refuse {
				return &gonet.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EPERM)}
			}
			return nil
		}
		s.packet(t, "")
		s.packet(t, "203.0.113.2:53")
		pc.writes(t, 2)
		s.running(t)
		pc.mu.Lock()
		refuse = false
		pc.mu.Unlock()
		s.packet(t, "")
		s.packet(t, "203.0.113.2:53")
		pc.wrote(t, "203.0.113.1:443", "203.0.113.2:53")
		s.running(t)
		// Another error still ends the session, as upstream.
		pc.mu.Lock()
		pc.writeErr = func() error { return &gonet.OpError{Op: "write", Err: os.NewSyscallError("sendto", syscall.EACCES)} }
		pc.mu.Unlock()
		s.packet(t, "")
		if err := s.wait(t, 5*time.Second); !goerrors.Is(err, syscall.EACCES) {
			t.Fatal("the session ended with ", err)
		}
		lt.counts(map[string]int64{})
	}
}
