package freedom

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// The per-user connection limits in freedom (fork: common/connlimit,
// FORK.md). The dispatcher took the token of the connection's first dial,
// or of the UDP session's first destination, before routing; here the
// connection takes its place among the user's, pays for each dial after
// the first and for the ones that fail, and a UDP session accounts for the
// pairs it sends to.

// limitLease is what a connection holds of its user's limits; nil when the
// user has none, and every method is then upstream's behaviour.
type limitLease struct {
	ctx context.Context
	tcp *connlimit.TCPConn
	udp *connlimit.UDPSession
	// dials counts the TCP dials; final says the last one's error is not
	// worth another dial, or there was no token for it.
	dials int
	final bool
}

// limit takes the connection's place among its user's TCP connections or
// UDP sessions, and puts the accounting of its dials and packets around
// the dialer. connlimit.ErrLimit when the user has no place for it.
func (h *Handler) limit(ctx context.Context, network net.Network, dialer *internet.Dialer) (*limitLease, error) {
	lim, name := connlimit.FromContext(ctx, h.policyManager)
	if lim == nil || (network != net.Network_TCP && network != net.Network_UDP) || !lim.Limits(network == net.Network_UDP) {
		return nil, nil // upstream's way: none of the network's limits is on
	}
	paid := connlimit.PaidFromContext(ctx)
	l := &limitLease{ctx: ctx}
	var err error
	switch network {
	case net.Network_TCP:
		if !paid { // not through the dispatcher
			if err := lim.Admit(ctx, name, false); err != nil {
				return nil, err
			}
		}
		l.tcp, err = lim.TCP(name)
	case net.Network_UDP:
		l.udp, err = lim.UDP(name, paid)
	}
	if err != nil {
		return nil, err
	}
	*dialer = &limitDialer{Dialer: *dialer, l: l}
	return l, nil
}

// done gives the place back; a UDP session's pairs live out their time in
// the user's journal.
func (l *limitLease) done() {
	if l == nil {
		return
	}
	if l.tcp != nil {
		l.tcp.Done()
	}
	if l.udp != nil {
		l.udp.Done()
	}
}

// evictable lets a UDP session give way to a new one of its user when it
// is the quietest: it then ends as when its idle timer runs out.
func (l *limitLease) evictable(timer *signal.ActivityTimer) {
	if l != nil && l.udp != nil {
		l.udp.OnEvict(func() { timer.SetTimeout(0) })
	}
}

// retry is the strategy of the dial loop: upstream's without limits.
func (l *limitLease) retry(upstream retry.Strategy) retry.Strategy {
	if l == nil {
		return upstream
	}
	return l
}

// On implements retry.Strategy as upstream's ExponentialBackoff(5, 100)
// does, five attempts with no pause before the second and 100 ms more
// before each next one, but: no attempt follows an error that is final
// (connlimit.Final) or a refused token, and the pause ends with the
// context.
func (l *limitLease) On(method func() error) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 1 {
			t := time.NewTimer(time.Duration(attempt-1) * 100 * time.Millisecond)
			select {
			case <-l.ctx.Done():
				t.Stop()
				return err
			case <-t.C:
			}
		}
		if err = method(); err == nil || l.final || l.ctx.Err() != nil {
			break
		}
	}
	return err
}

// limitDialer is the outbound's dialer with the limits' accounting.
type limitDialer struct {
	internet.Dialer
	l *limitLease
}

// Dial implements internet.Dialer. A TCP dial after the connection's
// first takes a token of its own, and one that sent a SYN for nothing is
// charged to the user's failed dials. A UDP socket's packets are accounted
// for by the session.
func (d *limitDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	l := d.l
	if l.tcp != nil {
		if l.dials > 0 && !l.tcp.Retry() {
			l.final = true
			return nil, connlimit.ErrLimit
		}
		l.dials++
	}
	conn, err := d.Dialer.Dial(ctx, dest)
	if err != nil {
		if l.tcp != nil {
			l.tcp.Failed(err)
		}
		l.final = connlimit.Final(err)
		return conn, err
	}
	if l.udp != nil {
		var c net.Conn = conn
		if counted, ok := c.(*stat.CounterConnection); ok {
			c = counted.Connection
		}
		if p, ok := c.(*net.PacketConnWrapper); ok {
			p.PacketConn = &limitPacketConn{PacketConn: p.PacketConn, s: l.udp}
		} else {
			// Not a socket of the system's (a dialer proxy): its packets
			// are not seen here, so it is never taken for quiet.
			l.udp.Pin()
		}
	}
	return conn, nil
}

// limitPacketConn is a UDP session's socket: PacketWriter and PacketReader
// send and receive through it.
type limitPacketConn struct {
	net.PacketConn
	s *connlimit.UDPSession
	// lookups counts the names looked up since the session's names were
	// last forgotten.
	lookups int
}

// WriteTo implements net.PacketConn. A packet to a new destination the
// user's limits do not let through is dropped, as a path would drop it.
func (c *limitPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	to, ok := addr.(*net.UDPAddr)
	if !ok {
		return c.PacketConn.WriteTo(p, addr)
	}
	if !c.s.Send(to.AddrPort()) {
		return len(p), nil
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	if err != nil && connlimit.IsEPERM(err) {
		c.s.Unsent(to.AddrPort())
	}
	return n, err
}

// ReadFrom implements net.PacketConn.
func (c *limitPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if from, ok := addr.(*net.UDPAddr); ok && err == nil {
		c.s.Heard(from.AddrPort())
	}
	return n, addr, err
}

// maxResolved bounds the names a UDP session of a limited user remembers
// the addresses of.
const maxResolved = 256

// limitLookup takes the user's token for the lookup of a name in a packet,
// before the lookup; false when there is none, and the packet is dropped.
// Each name looked up may be remembered in ResolvedUDPAddr for the
// session's life: past maxResolved they are all forgotten and looked up
// again when next sent to, each for a token.
func (w *PacketWriter) limitLookup() bool {
	c, ok := w.PacketConn.(*limitPacketConn)
	if !ok {
		return true
	}
	if !c.s.Lookup() {
		return false
	}
	if c.lookups++; c.lookups > maxResolved {
		c.lookups = 1
		w.ResolvedUDPAddr.Clear()
	}
	return true
}

// droppedEPERM logs, at debug and once a session, that the kernel refused
// a packet of the session and it was dropped: the conntrack guard or the
// egress policy (upstream ended the session there, and logged that at
// info). Neither the user nor the destination is said.
func (w *PacketWriter) droppedEPERM() {
	if !w.epermLogged {
		w.epermLogged = true
		errors.LogDebug(context.Background(), "a UDP packet was dropped: the kernel refused it (EPERM); the session goes on")
	}
}
