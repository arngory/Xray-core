package freedom

import (
	"context"
	"fmt"
	"io"
	gonet "net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// The tests of this package run Handler.Process as the outbound handler
// does, with a dialer of their own in place of the network, and the limits
// of the users on a clock of their own. The tests through a VLESS inbound
// are in limit_inbound_test.go.

// limitPolicy is a policy manager whose level 0 has limits.
type limitPolicy struct {
	policy.DefaultManager
	lim *connlimit.Limiter
}

func (p *limitPolicy) ConnLimits(level uint32) *connlimit.Limiter {
	if level != 0 {
		return nil
	}
	return p.lim
}

// limitTest is a freedom handler, the limits of its users and what they
// refused.
type limitTest struct {
	t *testing.T
	h *Handler

	mu      sync.Mutex
	now     int64
	refused map[string]int64
}

type refusedCounter struct {
	lt  *limitTest
	key string
}

func (c refusedCounter) Add(n int64) int64 {
	c.lt.mu.Lock()
	defer c.lt.mu.Unlock()
	c.lt.refused[c.key] += n
	return 0
}

// newLimitTest makes a handler; limits nil for none. Port 9 is blocked by a
// final rule, and blackholed for 30 s.
func newLimitTest(t *testing.T, limits *connlimit.Config) *limitTest {
	lt := &limitTest{t: t, h: new(Handler), now: int64(time.Hour), refused: map[string]int64{}}
	var pm policy.Manager = policy.DefaultManager{}
	if limits != nil {
		r := connlimit.NewRegistry()
		r.SetClock(func() int64 {
			lt.mu.Lock()
			defer lt.mu.Unlock()
			return lt.now
		}, func(ctx context.Context, d time.Duration) error {
			lt.advance(d)
			return ctx.Err()
		})
		r.SetCounters(func(user, kind string) connlimit.Counter { return refusedCounter{lt, user + "/" + kind} })
		pm = &limitPolicy{lim: r.Limiter(*limits)}
	}
	err := lt.h.Init(&Config{FinalRules: []*FinalRuleConfig{{
		Action:   RuleAction_Block,
		PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(9)}},
		Delay:    &Range{Min: 30, Max: 30},
	}}}, pm)
	if err != nil {
		t.Fatal(err)
	}
	return lt
}

func (lt *limitTest) advance(d time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.now += int64(d)
}

// counts waits for the refusals counted to be these.
func (lt *limitTest) counts(want map[string]int64) {
	lt.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		lt.mu.Lock()
		got := fmt.Sprint(lt.refused)
		lt.mu.Unlock()
		if got == fmt.Sprint(want) {
			return
		}
		if time.Now().After(deadline) {
			lt.t.Fatalf("refused %v, want %v", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// testDialer is the dialer Process gets.
type testDialer struct {
	mu    sync.Mutex
	dials int
	dial  func(n int, ctx context.Context, dest net.Destination) (stat.Connection, error)
}

func (d *testDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	d.mu.Lock()
	d.dials++
	n := d.dials
	d.mu.Unlock()
	return d.dial(n, ctx, dest)
}

func (d *testDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func (*testDialer) DestIpAddress() net.IP                                 { return nil }
func (*testDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// failWith is a dialer whose every dial fails.
func failWith(err error) *testDialer {
	return &testDialer{dial: func(int, context.Context, net.Destination) (stat.Connection, error) { return nil, err }}
}

func dialError(errno syscall.Errno) error {
	return errors.New("failed to dial").Base(&gonet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)})
}

type dialTimeout struct{}

func (dialTimeout) Error() string   { return "i/o timeout" }
func (dialTimeout) Timeout() bool   { return true }
func (dialTimeout) Temporary() bool { return true }

// call is one connection in Process.
type call struct {
	done   chan error
	cancel context.CancelFunc
	// The inbound's ends of the link.
	up   *pipe.Writer
	down *pipe.Reader
}

type callOption func(ctx context.Context) context.Context

// paid: the dispatcher took the connection's token.
func paid(ctx context.Context) context.Context { return connlimit.ContextWithPaid(ctx) }

// detached: as an XUDP session, which only its idle timer ends.
func detached(ctx context.Context) context.Context { return session.ContextWithTimeoutOnly(ctx, true) }

// start runs Process for a connection of the user with the email, "" for
// no user.
func (lt *limitTest) start(email string, dest net.Destination, d internet.Dialer, opts ...callOption) *call {
	ctx, cancel := context.WithCancel(context.Background())
	lt.t.Cleanup(cancel)
	inbound := &session.Inbound{Tag: "in"}
	if email != "" {
		inbound.User = &protocol.MemoryUser{Email: email}
	}
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
	for _, o := range opts {
		ctx = o(ctx)
	}
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	c := &call{done: make(chan error, 1), cancel: cancel, up: upW, down: downR}
	go func() { c.done <- lt.h.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, d) }()
	return c
}

// wait is what Process returned, within d.
func (c *call) wait(t *testing.T, d time.Duration) error {
	t.Helper()
	select {
	case err := <-c.done:
		return err
	case <-time.After(d):
		t.Fatal("Process did not return in ", d)
		return nil
	}
}

func (c *call) running(t *testing.T) {
	t.Helper()
	select {
	case err := <-c.done:
		t.Fatal("Process returned: ", err)
	case <-time.After(50 * time.Millisecond):
	}
}

var tcpDest = net.TCPDestination(net.ParseAddress("203.0.113.1"), 443)

// pipeDialer connects every dial to a pipe, and keeps the far ends.
type pipeDialer struct {
	testDialer
	far chan gonet.Conn
}

func newPipeDialer() *pipeDialer {
	p := &pipeDialer{far: make(chan gonet.Conn, 16)}
	p.dial = func(int, context.Context, net.Destination) (stat.Connection, error) {
		near, far := gonet.Pipe()
		p.far <- far
		return near, nil
	}
	return p
}

// testPacketConn is the socket of a UDP session.
type testPacketConn struct {
	gonet.PacketConn // nil: the methods not set here are not called
	mu               sync.Mutex
	sent             []string     // the destinations of the packets sent
	tried            int          // writes, failed ones too
	writeErr         func() error // the error of the next write
	in               chan gonet.Addr
	closed           chan struct{}
	once             sync.Once
}

func newTestPacketConn() *testPacketConn {
	return &testPacketConn{in: make(chan gonet.Addr, 16), closed: make(chan struct{})}
}

func (c *testPacketConn) WriteTo(p []byte, addr gonet.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tried++
	if c.writeErr != nil {
		if err := c.writeErr(); err != nil {
			return 0, err
		}
	}
	c.sent = append(c.sent, addr.String())
	return len(p), nil
}

func (c *testPacketConn) ReadFrom(p []byte) (int, gonet.Addr, error) {
	select {
	case from := <-c.in:
		return copy(p, "answer"), from, nil
	case <-c.closed:
		return 0, nil, io.EOF
	}
}

func (c *testPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *testPacketConn) LocalAddr() gonet.Addr { return &gonet.UDPAddr{IP: gonet.IPv4zero} }

// writes waits for n writes, failed ones too.
func (c *testPacketConn) writes(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		got := c.tried
		c.mu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d writes, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// wrote waits for the packets sent to be these destinations.
func (c *testPacketConn) wrote(t *testing.T, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		got := fmt.Sprint(c.sent)
		c.mu.Unlock()
		if got == fmt.Sprint(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("packets sent to %v, want %v", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

var udpDest = net.UDPDestination(net.ParseAddress("203.0.113.1"), 443)

// udpDialer gives every dial a socket, as the system dialer does.
type udpDialer struct {
	testDialer
	conns chan *testPacketConn
}

func newUDPDialer() *udpDialer {
	u := &udpDialer{conns: make(chan *testPacketConn, 16)}
	u.dial = func(_ int, _ context.Context, dest net.Destination) (stat.Connection, error) {
		pc := newTestPacketConn()
		u.conns <- pc
		return &net.PacketConnWrapper{PacketConn: pc, Dest: &gonet.UDPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}}, nil
	}
	return u
}

// packet sends a packet of the client's: to the session's destination
// when to is "", as XUDP names its destination otherwise.
func (c *call) packet(t *testing.T, to string) {
	t.Helper()
	b := buf.New()
	b.WriteString("packet")
	if to != "" {
		d, err := net.ParseDestination("udp:" + to)
		if err != nil {
			t.Fatal(err)
		}
		b.UDP = &d
	}
	if err := c.up.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
}
