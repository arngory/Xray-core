package freedom

import (
	goerrors "errors"
	gonet "net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/log"
)

// EPERM from the kernel (the node's conntrack guard, its egress policy) is
// a dropped packet, with limits or without: the session lives and sends
// the next one. Upstream ends the session. The drop is logged at debug,
// once a session, without the destination.
func TestEPERMDropsThePacketNotTheSession(t *testing.T) {
	logs := &capture{}
	log.RegisterHandler(logs)
	defer log.RegisterHandler(discard{})
	for _, limits := range []*connlimit.Config{nil, {UDPLive: 8, UDPRate: 1, UDPBurst: 8}} {
		logs.reset()
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
		var said []string
		for _, line := range logs.lines() {
			if strings.Contains(line, "EPERM") {
				said = append(said, line)
			}
		}
		if len(said) != 1 || !strings.Contains(said[0], "[Debug]") || strings.Contains(said[0], "203.0.113") {
			t.Fatalf("the log of two refused packets of a session: %q", said)
		}
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

// capture keeps the lines logged.
type capture struct {
	mu  sync.Mutex
	got []string
}

func (c *capture) Handle(msg log.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, msg.String())
}

func (c *capture) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.got...)
}

func (c *capture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = nil
}

type discard struct{}

func (discard) Handle(log.Message) {}
