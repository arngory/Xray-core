package freedom

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	gonet "net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Without limits the dial loop is upstream's: five dials whatever the
// error, and the dialer is the outbound's own.
func TestNoLimitsDialLoopIsUpstreams(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.EPERM} {
		lt := newLimitTest(t, nil)
		d := failWith(dialError(errno))
		if err := lt.start("u5", tcpDest, d).wait(t, 5*time.Second); err == nil {
			t.Fatal(errno, ": no error")
		}
		if d.count() != 5 {
			t.Error(errno, ": dials without limits: ", d.count(), ", want 5")
		}
	}
	// A user without an email, and no user, have no limits either.
	lt := newLimitTest(t, &connlimit.Config{Rate: 1, Burst: 1})
	d := failWith(dialError(syscall.ECONNREFUSED))
	lt.start("", tcpDest, d).wait(t, 5*time.Second)
	if d.count() != 5 {
		t.Error("dials of a connection without a user: ", d.count(), ", want 5")
	}
	lt.counts(map[string]int64{})
}

// Each dial after a connection's first pays a token, and the dials end when
// there is none.
func TestRetriesPayTokens(t *testing.T) {
	// The dispatcher paid the first: two more with a burst of 2.
	lt := newLimitTest(t, &connlimit.Config{Rate: 1, Burst: 2, FoldAt: "-"})
	d := failWith(dialError(syscall.EHOSTUNREACH))
	err := lt.start("u5-0123456789abcdef", tcpDest, d, paid).wait(t, 5*time.Second)
	if d.count() != 3 {
		t.Fatal("dials: ", d.count(), ", want 3: one paid by the dispatcher, two by the burst")
	}
	if errors.Cause(err) != connlimit.ErrLimit {
		t.Fatal("the dials ended with ", err)
	}
	lt.counts(map[string]int64{"u5/rate": 1})

	// Not through the dispatcher, the first is paid here.
	lt = newLimitTest(t, &connlimit.Config{Rate: 1, Burst: 2})
	d = failWith(&gonet.OpError{Op: "dial", Err: dialTimeout{}})
	lt.start("u5", tcpDest, d).wait(t, 5*time.Second)
	if d.count() != 2 {
		t.Fatal("dials: ", d.count(), ", want 2")
	}
	lt.counts(map[string]int64{"u5/rate": 1})

	// With tokens for all, five dials as upstream.
	lt = newLimitTest(t, &connlimit.Config{Rate: 1, Burst: 10})
	d = failWith(dialError(syscall.EHOSTUNREACH))
	err = lt.start("u5", tcpDest, d, paid).wait(t, 5*time.Second)
	if d.count() != 5 {
		t.Fatal("dials: ", d.count(), ", want 5")
	}
	if !goerrors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatal("the dials ended with ", err)
	}
	lt.counts(map[string]int64{})
}

// ECONNREFUSED, ENETUNREACH and EPERM are not dialed again.
func TestNoRetryOnFinalErrors(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EPERM} {
		lt := newLimitTest(t, &connlimit.Config{Rate: 1, Burst: 10})
		d := failWith(dialError(errno))
		err := lt.start("u5", tcpDest, d, paid).wait(t, 5*time.Second)
		if d.count() != 1 {
			t.Error(errno, ": dials: ", d.count(), ", want 1")
		}
		if !goerrors.Is(err, errno) {
			t.Error(errno, ": Process returned ", err)
		}
		lt.counts(map[string]int64{})
	}
}

// A dial that sent a SYN for nothing is charged to the user's failed
// dials; ENETUNREACH and EPERM, the conntrack guard's refusals, are not.
func TestFailedDialsAreCharged(t *testing.T) {
	for _, c := range []struct {
		err     error
		charged bool
	}{
		{dialError(syscall.ECONNREFUSED), true},
		{dialError(syscall.EHOSTUNREACH), true},
		{&gonet.OpError{Op: "dial", Err: dialTimeout{}}, true},
		{dialError(syscall.ENETUNREACH), false},
		{dialError(syscall.EPERM), false},
	} {
		// A burst of 1: the second failure is paid into debt.
		lt := newLimitTest(t, &connlimit.Config{FailedRate: 1, FailedBurst: 1})
		for range 2 {
			lt.start("u5", tcpDest, failWith(c.err), paid).wait(t, 5*time.Second)
		}
		d := newPipeDialer()
		u5 := lt.start("u5", tcpDest, d)
		if !c.charged {
			u5.running(t)
			lt.counts(map[string]int64{})
			continue
		}
		if err := u5.wait(t, 5*time.Second); errors.Cause(err) != connlimit.ErrLimit || d.count() != 0 {
			t.Errorf("%v: a connection in debt returned %v after %d dials", c.err, err, d.count())
		}
		lt.counts(map[string]int64{"u5/failed": 1})
		// Another user owes nothing, and time pays the debt off.
		lt.start("u6", tcpDest, d).running(t)
		lt.advance(10 * time.Second)
		lt.start("u5", tcpDest, d).running(t)
	}
}

// The pause between dials ends with the connection's context.
func TestRetryPauseEndsWithContext(t *testing.T) {
	lt := newLimitTest(t, &connlimit.Config{Rate: 1, Burst: 10})
	calls := make(chan *call, 1)
	canceled := make(chan time.Time, 1)
	d := &testDialer{}
	d.dial = func(n int, _ context.Context, _ net.Destination) (stat.Connection, error) {
		if n == 4 { // the pause after it is 300 ms: the client leaves 50 ms into it
			c := <-calls
			go func() {
				time.Sleep(50 * time.Millisecond)
				canceled <- time.Now()
				c.cancel()
			}()
		}
		return nil, dialError(syscall.EHOSTUNREACH)
	}
	c := lt.start("u5", tcpDest, d, paid)
	calls <- c
	c.wait(t, 5*time.Second)
	if took := time.Since(<-canceled); took > 150*time.Millisecond {
		t.Error("Process returned ", took, " after its context ended")
	}
	if d.count() != 4 {
		t.Error("dials: ", d.count(), ", want 4: none after the context ended")
	}
}

// A connection holds a place among its user's from its first dial to its
// end, and one refused for want of a place ends with an error that is no
// normal end.
func TestTCPPlace(t *testing.T) {
	lt := newLimitTest(t, &connlimit.Config{Connections: 2, FoldAt: "-"})
	block := make(chan struct{})
	slow := &testDialer{dial: func(_ int, ctx context.Context, _ net.Destination) (stat.Connection, error) {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil, dialError(syscall.ECONNREFUSED)
	}}
	dialing := lt.start("u5-0123456789abcdef", tcpDest, slow, paid) // a dial in flight
	pd := newPipeDialer()
	open := lt.start("u5-fedcba9876543210", tcpDest, pd, paid)
	far := <-pd.far
	open.running(t)

	third := newPipeDialer()
	err := lt.start("u5-n", tcpDest, third, paid).wait(t, 5*time.Second)
	if errors.Cause(err) != connlimit.ErrLimit {
		t.Fatal("the third connection of u5: ", err)
	}
	for _, normal := range []error{io.EOF, io.ErrClosedPipe, context.Canceled} {
		if goerrors.Is(err, normal) {
			t.Error("the refusal is ", normal, ": the outbound handler would end the link as if nothing happened")
		}
	}
	if third.count() != 0 {
		t.Error("a refused connection dialed")
	}
	// Another user is not held.
	other := lt.start("u6-0123456789abcdef", tcpDest, pd, paid)
	<-pd.far
	other.running(t)

	// The dial in flight ends: its place is free.
	close(block)
	dialing.wait(t, 5*time.Second)
	again := lt.start("u5-n", tcpDest, pd, paid)
	<-pd.far
	again.running(t)
	// The open one ends: so is its place.
	far.Close()
	open.up.Close()
	open.wait(t, 5*time.Second)
	last := lt.start("u5-p", tcpDest, pd, paid)
	<-pd.far
	last.running(t)
	lt.counts(map[string]int64{"u5/tcp": 1})
}

// A connection to a destination freedom blackholes gives its place back
// before the blackhole holds it for its 30 s.
func TestPlaceBackBeforeBlackhole(t *testing.T) {
	allowed := func(lt *limitTest, network net.Network) {
		t.Helper()
		pd := newPipeDialer()
		next := lt.start("u5", net.Destination{Network: network, Address: net.ParseAddress("203.0.113.1"), Port: 443}, pd, paid)
		select {
		case <-pd.far:
		case err := <-next.done:
			t.Fatal(network, ": the blackholed connection holds the user's only place: ", err)
		case <-time.After(5 * time.Second):
			t.Fatal(network, ": no dial")
		}
		lt.counts(map[string]int64{})
	}
	// Blocked by its address, before any dial.
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		lt := newLimitTest(t, &connlimit.Config{Connections: 1, UDPSessions: 1})
		pd := newPipeDialer()
		hole := lt.start("u5", net.Destination{Network: network, Address: net.ParseAddress("203.0.113.1"), Port: 9}, pd, paid)
		hole.running(t) // in the blackhole
		if pd.count() != 0 {
			t.Fatal(network, ": a blocked destination was dialed")
		}
		allowed(lt, network)
	}

	// Blocked by where its name led the dial: after the connection.
	internet.InitSystemDialer(&testDNS{fail: true}, nil)
	defer internet.InitSystemDialer(nil, nil)
	lt := newLimitTest(t, &connlimit.Config{Connections: 1})
	lt.h.resolveStrategy = internet.DomainStrategy_USE_IP
	d := &testDialer{dial: func(int, context.Context, net.Destination) (stat.Connection, error) {
		near, _ := gonet.Pipe()
		return &connTo{Conn: near, remote: &gonet.TCPAddr{IP: gonet.IPv4(203, 0, 113, 1), Port: 9}}, nil
	}}
	hole := lt.start("u5", net.TCPDestination(net.DomainAddress("name.example"), 443), d, paid)
	hole.running(t)
	if d.count() != 1 {
		t.Fatal("dials: ", d.count())
	}
	allowed(lt, net.Network_TCP)
}

// connTo is a connection that says where it leads.
type connTo struct {
	gonet.Conn
	remote gonet.Addr
}

func (c *connTo) RemoteAddr() gonet.Addr { return c.remote }

// A UDP session's pairs: a packet to a new destination past the user's
// pairs is dropped, an answer makes a pair live 120 s after it, and a pair
// without one ends 30 s after its last packet.
func TestUDPPairs(t *testing.T) {
	lt := newLimitTest(t, &connlimit.Config{UDPLive: 2})
	ud := newUDPDialer()
	s := lt.start("u5", udpDest, ud, paid)
	pc := <-ud.conns
	s.packet(t, "")               // the session's own destination
	s.packet(t, "203.0.113.2:53") // a second pair
	s.packet(t, "203.0.113.3:53") // a third: dropped
	s.packet(t, "203.0.113.2:53")
	pc.wrote(t, "203.0.113.1:443", "203.0.113.2:53", "203.0.113.2:53")
	lt.counts(map[string]int64{"u5/live": 1})

	// 203.0.113.2 answers; the session's destination does not.
	pc.in <- &gonet.UDPAddr{IP: gonet.IPv4(203, 0, 113, 2), Port: 53}
	if mb, err := s.down.ReadMultiBuffer(); err != nil || mb.String() != "answer" {
		t.Fatal("the answer: ", mb, err)
	}
	lt.advance(30 * time.Second)
	s.packet(t, "203.0.113.3:53") // the unanswered pair ended: room for one
	s.packet(t, "203.0.113.4:53") // the answered one did not: dropped
	pc.wrote(t, "203.0.113.1:443", "203.0.113.2:53", "203.0.113.2:53", "203.0.113.3:53")
	lt.counts(map[string]int64{"u5/live": 2})

	// The session ends; its pairs do not: a new session of the user finds
	// them counted, until their time runs out.
	pc.Close()
	s.wait(t, 5*time.Second)
	n := lt.start("u5", udpDest, ud, paid)
	npc := <-ud.conns
	n.packet(t, "")
	lt.counts(map[string]int64{"u5/live": 3})
	npc.wrote(t)
	lt.advance(30 * time.Second) // 30 s after 203.0.113.3 was sent to; the answered pair has 60 s more
	n.packet(t, "")
	n.packet(t, "203.0.113.5:53")
	npc.wrote(t, "203.0.113.1:443")
	lt.advance(60 * time.Second)
	n.packet(t, "203.0.113.5:53")
	npc.wrote(t, "203.0.113.1:443", "203.0.113.5:53")
	lt.counts(map[string]int64{"u5/live": 4})
}

// New destinations pay a token each, but the session's first, which the
// dispatcher paid.
func TestUDPNewDestinations(t *testing.T) {
	lt := newLimitTest(t, &connlimit.Config{UDPRate: 1, UDPBurst: 1})
	ud := newUDPDialer()
	s := lt.start("u5", udpDest, ud, paid)
	pc := <-ud.conns
	s.packet(t, "")
	s.packet(t, "203.0.113.2:53")
	s.packet(t, "203.0.113.3:53") // no token
	s.packet(t, "203.0.113.2:53")
	s.packet(t, "")
	pc.wrote(t, "203.0.113.1:443", "203.0.113.2:53", "203.0.113.2:53", "203.0.113.1:443")
	lt.counts(map[string]int64{"u5/dest": 1})
	// Not through the dispatcher, the session pays its first destination:
	// no token, no session.
	d := newUDPDialer()
	err := lt.start("u5", udpDest, d).wait(t, 5*time.Second)
	if errors.Cause(err) != connlimit.ErrLimit || d.count() != 0 {
		t.Fatal("a session without a token for its first destination: ", err)
	}
	lt.counts(map[string]int64{"u5/dest": 2})
}

// A new UDP session at the user's limit takes the place of the quietest
// one, 10 s silent both ways: that one ends, though it is an XUDP session
// whose context is detached from its connection.
func TestUDPSessionGivesWay(t *testing.T) {
	lt := newLimitTest(t, &connlimit.Config{UDPSessions: 2})
	ud := newUDPDialer()
	quiet := lt.start("u5", udpDest, ud, paid, detached)
	quietConn := <-ud.conns
	busy := lt.start("u5", udpDest, ud, paid, detached)
	busyConn := <-ud.conns
	quiet.packet(t, "")
	quietConn.wrote(t, "203.0.113.1:443")
	lt.advance(9 * time.Second)
	busy.packet(t, "")
	busyConn.wrote(t, "203.0.113.1:443")

	// Nobody has been silent for 10 s: no place.
	d := newUDPDialer()
	if err := lt.start("u5", udpDest, d, paid, detached).wait(t, 5*time.Second); errors.Cause(err) != connlimit.ErrLimit || d.count() != 0 {
		t.Fatal("a third session with none quiet: ", err)
	}
	quiet.running(t)
	// Another user's session takes nobody's place.
	other := lt.start("u6", udpDest, ud, paid, detached)
	<-ud.conns
	other.running(t)

	lt.advance(time.Second)
	third := lt.start("u5", udpDest, ud, paid, detached)
	<-ud.conns
	// The quiet one ends as when its idle timer runs out: a normal end, an
	// End frame without the error bit for XUDP.
	if err := quiet.wait(t, 5*time.Second); !goerrors.Is(errors.Cause(err), context.Canceled) {
		t.Fatal("the session that gave way ended with ", err)
	}
	third.running(t)
	busy.running(t)
	lt.counts(map[string]int64{"u5/udp": 1, "u5/evicted": 1})
}

// A session whose connection is not a socket of the system dialer's (the
// outbound has a dialer proxy) holds its place, and is never taken for
// quiet: its packets are not seen.
func TestUDPSessionWithoutASocketDoesNotGiveWay(t *testing.T) {
	lt := newLimitTest(t, &connlimit.Config{UDPSessions: 1, UDPLive: 1})
	pd := newPipeDialer()
	s := lt.start("u5", udpDest, pd, paid)
	far := <-pd.far
	go io.Copy(io.Discard, far)
	s.packet(t, "")
	lt.advance(time.Hour)
	d := newUDPDialer()
	if err := lt.start("u5", udpDest, d, paid).wait(t, 5*time.Second); errors.Cause(err) != connlimit.ErrLimit {
		t.Fatal("a second session: ", err)
	}
	s.running(t)
	lt.counts(map[string]int64{"u5/udp": 1})
}

// testDNS answers every name with 127.0.0.1, or none when it fails, and
// counts the lookups.
type testDNS struct {
	fail    bool
	mu      sync.Mutex
	lookups []string
}

func (*testDNS) Type() interface{} { return dns.ClientType() }
func (*testDNS) Start() error      { return nil }
func (*testDNS) Close() error      { return nil }

func (d *testDNS) LookupIP(domain string, _ dns.IPOption) ([]net.IP, uint32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lookups = append(d.lookups, domain)
	if d.fail {
		return nil, 0, dns.ErrEmptyResponse
	}
	return []net.IP{{127, 0, 0, 1}}, 600, nil
}

func (d *testDNS) looked() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprint(d.lookups)
}

// A name in a packet takes the user's lookup token before it is looked up:
// without one the packet is dropped and nothing is asked. A name the
// session resolved is not looked up again.
func TestLookupTokenBeforeLookup(t *testing.T) {
	resolver := &testDNS{}
	internet.InitSystemDialer(resolver, nil)
	defer internet.InitSystemDialer(nil, nil)

	lt := newLimitTest(t, &connlimit.Config{LookupRate: 1, LookupBurst: 2})
	lt.h.resolveStrategy = internet.DomainStrategy_FORCE_IP
	ud := newUDPDialer()
	s := lt.start("u5", udpDest, ud, paid)
	pc := <-ud.conns
	s.packet(t, "a.example:53")
	s.packet(t, "b.example:53")
	s.packet(t, "c.example:53") // no token
	s.packet(t, "a.example:53") // remembered
	s.packet(t, "c.example:53") // still none
	pc.wrote(t, "127.0.0.1:53", "127.0.0.1:53", "127.0.0.1:53")
	if got := resolver.looked(); got != "[a.example b.example]" {
		t.Fatal("looked up ", got)
	}
	lt.counts(map[string]int64{"u5/lookup": 2})
	lt.advance(time.Second)
	s.packet(t, "c.example:53")
	pc.wrote(t, "127.0.0.1:53", "127.0.0.1:53", "127.0.0.1:53", "127.0.0.1:53")
	if got := resolver.looked(); got != "[a.example b.example c.example]" {
		t.Fatal("looked up ", got)
	}

	// Without limits every name is looked up, as upstream.
	resolver.lookups = nil
	lt = newLimitTest(t, nil)
	lt.h.resolveStrategy = internet.DomainStrategy_FORCE_IP
	s = lt.start("u5", udpDest, ud, paid)
	pc = <-ud.conns
	for _, name := range []string{"a", "b", "c", "a"} {
		s.packet(t, name+".example:53")
	}
	pc.wrote(t, "127.0.0.1:53", "127.0.0.1:53", "127.0.0.1:53", "127.0.0.1:53")
	if got := resolver.looked(); got != "[a.example b.example c.example]" {
		t.Fatal("looked up without limits ", got)
	}
}

// The names a session of a limited user remembers are bounded.
func TestResolvedNamesAreBounded(t *testing.T) {
	resolver := &testDNS{}
	internet.InitSystemDialer(resolver, nil)
	defer internet.InitSystemDialer(nil, nil)

	r := connlimit.NewRegistry()
	lim := r.Limiter(connlimit.Config{LookupRate: 1, LookupBurst: 1 << 20})
	session, err := lim.UDP("u5", true)
	if err != nil {
		t.Fatal(err)
	}
	h := new(Handler)
	h.resolveStrategy = internet.DomainStrategy_FORCE_IP
	pc := newTestPacketConn()
	conn := &net.PacketConnWrapper{PacketConn: &limitPacketConn{PacketConn: pc, s: session}, Dest: &gonet.UDPAddr{IP: gonet.IPv4(203, 0, 113, 1), Port: 443}}
	w := NewPacketWriter(conn, h, nil, net.UDPDestination(nil, 0), udpDest, nil).(*PacketWriter)
	most := 0
	for i := range 4 * maxResolved {
		b := buf.New()
		b.WriteString("packet")
		d := net.UDPDestination(net.DomainAddress(fmt.Sprint("n", i, ".example")), 53)
		b.UDP = &d
		if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
		n := 0
		w.ResolvedUDPAddr.Range(func(string, net.Address) bool { n++; return true })
		most = max(most, n)
	}
	if len(pc.sent) != 4*maxResolved {
		t.Fatal("packets sent: ", len(pc.sent))
	}
	if most > maxResolved {
		t.Fatal("names remembered: ", most, ", want ", maxResolved, " at most")
	}
	if most < maxResolved/2 {
		t.Fatal("names remembered: ", most, ": the session forgets what it resolved")
	}
}
