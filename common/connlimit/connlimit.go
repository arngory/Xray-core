// Package connlimit limits the new connections of each user of a process.
//
// It is not in upstream Xray-core: see FORK.md. The limits of a user, by the
// base name of its email, count what the kernel will hold for it: every TCP
// dial and the ones that failed, UDP sessions, and UDP pairs (local port,
// destination) for as long as conntrack keeps them, even after their
// session. A user's tokens outlive its connections until they have
// refilled: closing gives none back.
package connlimit

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config is the limits of each user of a policy level. A zero number turns
// its limit off.
type Config struct {
	// Connections is the TCP connections of a user at once, dials in flight
	// included.
	Connections int
	// Rate and Burst are the bucket of TCP attempts: a token for every dial,
	// retries too. A new connection waits for its token attemptWait at most.
	Rate, Burst float64
	// FailedRate and FailedBurst are the bucket of failed dials, paid after
	// the failure, into debt: while it is below zero new connections are
	// refused.
	FailedRate, FailedBurst float64
	// UDPSessions is the UDP sessions of a user at once: a new one past it
	// takes the place of the quietest, silent quietAfter both ways.
	UDPSessions int
	// UDPRate and UDPBurst are the bucket of new UDP destinations.
	UDPRate, UDPBurst float64
	// UDPLive is the UDP pairs of a user that conntrack still keeps.
	UDPLive int
	// LookupRate and LookupBurst are the bucket of lookups of names in UDP
	// packets.
	LookupRate, LookupBurst float64
	// FoldAt cuts an email at its first occurrence to get the base name
	// ("-": u5-0123456789abcdef is u5), and FoldSuffixes are endings cut
	// off it ("-n": u5-n is u5): the emails of one user's credentials share
	// one set of limits.
	FoldAt       string
	FoldSuffixes []string
}

// Off reports whether the config limits nothing: every number is zero.
func (c Config) Off() bool { return !c.limitsTCP() && !c.limitsUDP() }

func (c Config) limitsTCP() bool { return c.Connections > 0 || c.Rate > 0 || c.FailedRate > 0 }

func (c Config) limitsUDP() bool {
	return c.UDPSessions > 0 || c.UDPRate > 0 || c.UDPLive > 0 || c.LookupRate > 0
}

const (
	// attemptWait is less than the first SYN retry (1 s): the application
	// does not send its SYN again while its connection waits for a token.
	attemptWait = 500 * time.Millisecond
	quietAfter  = 10 * time.Second
	// A pair as conntrack keeps it: 30 s after the last packet sent while
	// unanswered, 120 s after the last packet either way once answered.
	pairAnswered   = 120 * time.Second
	pairUnanswered = 30 * time.Second
	// ageEvery: a user's pairs are aged this often at most.
	ageEvery   = time.Second
	sweepEvery = 10 * time.Second
	// The process's ceiling of pairs is a quarter of nf_conntrack_max, read
	// again every ceilingEvery; defaultCeiling where it cannot be read.
	ceilingEvery   = time.Minute
	defaultCeiling = 65536 / 4
	// defaultDebt floors the debt of failed dials where Connections is off.
	defaultDebt = 1024
)

// ErrLimit refuses a connection at a limit. It wraps none of io.EOF,
// io.ErrClosedPipe and context.Canceled, which an outbound handler takes
// for a normal end.
var ErrLimit = errors.New("too many connections")

// The kinds of refusals, counted by base name.
const (
	kindTCP     = iota // TCP at once
	kindRate           // TCP attempts
	kindFailed         // failed dials in debt
	kindUDP            // UDP sessions, none quiet to give way
	kindEvicted        // a quiet UDP session gave way
	kindDest           // new UDP destinations
	kindLive           // UDP pairs
	kindLookup         // name lookups
	kinds
)

var kindNames = [kinds]string{"tcp", "rate", "failed", "udp", "evicted", "dest", "live", "lookup"}

// Counter counts refusals; a stats.Counter is one.
type Counter interface {
	Add(int64) int64
}

// Registry is what the limiters of a process share: the lock, the clock,
// the ceiling of pairs and the counters of refusals.
type Registry struct {
	mu sync.Mutex
	// now is a monotonic clock, in nanoseconds: the wall clock may step
	// back, and a step back would hold every pair and bucket.
	now   func() int64
	sleep func(ctx context.Context, d time.Duration) error
	// counter gives the counter of a user's refusals of a kind, or nil.
	counter func(user, kind string) Counter
	// ctMax reads nf_conntrack_max.
	ctMax func() (uint64, error)

	limiters  []*Limiter
	ceiling   int
	ceilingAt int64
	pairs     int // counted pairs of all users
	withPairs int // users with pairs counted: the fair share's divisor
	agedAll   int64
}

var monoStart = time.Now()

// NewRegistry makes a process's registry.
func NewRegistry() *Registry {
	return &Registry{
		now:   func() int64 { return int64(time.Since(monoStart)) },
		sleep: sleep,
		ctMax: conntrackMax,
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// conntrackMax reads the live nf_conntrack_max.
func conntrackMax() (uint64, error) {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// SetClock replaces the registry's clock, nanoseconds that only go
// forward, and its sleep: for tests.
func (r *Registry) SetClock(now func() int64, sleep func(ctx context.Context, d time.Duration) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now, r.sleep = now, sleep
}

// SetCounters sets where refusals are counted: f gives the counter of a
// user's refusals of a kind (tcp, rate, failed, udp, evicted, dest, live,
// lookup), made at the first one, or nil for none.
func (r *Registry) SetCounters(f func(user, kind string) Counter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counter = f
}

// Limiter makes the limiter of a policy level. Its users are its own; the
// ceiling of pairs is the process's.
func (r *Registry) Limiter(c Config) *Limiter {
	// A bucket holds a token at least.
	for _, b := range []struct{ rate, burst *float64 }{{&c.Rate, &c.Burst}, {&c.FailedRate, &c.FailedBurst},
		{&c.UDPRate, &c.UDPBurst}, {&c.LookupRate, &c.LookupBurst}} {
		if *b.rate > 0 && *b.burst < 1 {
			*b.burst = max(1, *b.rate)
		}
	}
	c.FoldSuffixes = slices.Clone(c.FoldSuffixes)
	l := &Limiter{r: r, c: c, debt: defaultDebt, users: map[string]*user{}}
	if c.Connections > 0 {
		// As many failures as dials may be in flight.
		l.debt = float64(c.Connections)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limiters = append(r.limiters, l)
	return l
}

// Limiter is the limits of the users of a policy level.
type Limiter struct {
	r     *Registry
	c     Config
	debt  float64
	users map[string]*user // under r.mu
	swept int64
}

type user struct {
	tcp      int // connections, and those that wait for their token
	sessions map[*UDPSession]struct{}
	// attempts, failures (in debt below zero), new UDP destinations,
	// lookups.
	attempts, failed, dests, lookups bucket
	journal                          []int64 // when the pairs of ended sessions end
	pairs                            int     // counted: live sessions' and the journal's
	aged                             int64
	refused                          [kinds]Counter
}

// Limits reports whether the limiter limits TCP connections, or with udp
// UDP sessions: whether any of their numbers is on. A network it does not
// limit is left as upstream has it.
func (l *Limiter) Limits(udp bool) bool {
	if udp {
		return l.c.limitsUDP()
	}
	return l.c.limitsTCP()
}

// Name is the base name an email is limited by.
func (l *Limiter) Name(email string) string {
	if l.c.FoldAt != "" {
		if i := strings.Index(email, l.c.FoldAt); i > 0 {
			email = email[:i]
		}
	}
	for _, s := range l.c.FoldSuffixes {
		if s != "" && len(email) > len(s) && strings.HasSuffix(email, s) {
			return email[:len(email)-len(s)]
		}
	}
	return email
}

// userLocked is a user's state, made at first sight with full buckets.
func (l *Limiter) userLocked(name string, now int64) *user {
	if now-l.swept > int64(sweepEvery) {
		l.sweepLocked(now)
	}
	u := l.users[name]
	if u == nil {
		c := &l.c
		u = &user{attempts: bucket{c.Burst, now}, failed: bucket{c.FailedBurst, now}, dests: bucket{c.UDPBurst, now},
			lookups: bucket{c.LookupBurst, now}, aged: now}
		l.users[name] = u
	}
	return u
}

// sweepLocked forgets the users with nothing open, nothing owed and full
// buckets, after aging their pairs.
func (l *Limiter) sweepLocked(now int64) {
	l.swept = now
	c := &l.c
	for name, u := range l.users {
		l.recountLocked(u, now)
		if u.tcp == 0 && len(u.sessions) == 0 && u.pairs == 0 && u.attempts.full(now, c.Rate, c.Burst) &&
			u.failed.full(now, c.FailedRate, c.FailedBurst) && u.dests.full(now, c.UDPRate, c.UDPBurst) &&
			u.lookups.full(now, c.LookupRate, c.LookupBurst) {
			delete(l.users, name)
		}
	}
}

// refuseLocked counts a refusal of the user's.
func (l *Limiter) refuseLocked(u *user, name string, kind int) {
	c := u.refused[kind]
	if c == nil && l.r.counter != nil {
		c = l.r.counter(name, kindNames[kind])
		u.refused[kind] = c
	}
	if c != nil {
		c.Add(1)
	}
}

// Admit takes what a new connection of the user pays before it is routed.
// TCP: a token for its first dial, waited for attemptWait at most and no
// longer than ctx, the waiter holding a place among the user's connections;
// and no debt of failed dials. UDP: a token for the session's first
// destination. ErrLimit when refused.
func (l *Limiter) Admit(ctx context.Context, name string, udp bool) error {
	r := l.r
	r.mu.Lock()
	now := r.now()
	u := l.userLocked(name, now)
	if udp {
		ok := u.dests.take(now, l.c.UDPRate, l.c.UDPBurst)
		if !ok {
			l.refuseLocked(u, name, kindDest)
		}
		r.mu.Unlock()
		if !ok {
			return ErrLimit
		}
		return nil
	}
	if l.c.Connections > 0 && u.tcp >= l.c.Connections {
		l.refuseLocked(u, name, kindTCP)
		r.mu.Unlock()
		return ErrLimit
	}
	u.tcp++
	r.mu.Unlock()
	ok := l.waitAttempt(ctx, u, name)
	r.mu.Lock()
	u.tcp--
	if ok && u.failed.level(r.now(), l.c.FailedRate, l.c.FailedBurst) < 0 {
		l.refuseLocked(u, name, kindFailed)
		ok = false
	}
	r.mu.Unlock()
	if !ok {
		return ErrLimit
	}
	return nil
}

// waitAttempt takes an attempt token, waiting for one up to attemptWait
// while ctx lasts; a refusal is counted. The caller holds a place of u's.
func (l *Limiter) waitAttempt(ctx context.Context, u *user, name string) bool {
	r := l.r
	var start int64
	for first := true; ; first = false {
		r.mu.Lock()
		now := r.now()
		if first {
			start = now
		}
		if u.attempts.take(now, l.c.Rate, l.c.Burst) {
			r.mu.Unlock()
			return true
		}
		// Until the next token comes; a millisecond at least: a float's
		// dust must not spin the loop.
		need := max(time.Millisecond, time.Duration((1-u.attempts.tokens)/l.c.Rate*float64(time.Second)))
		if now+int64(need)-start > int64(attemptWait) || ctx.Err() != nil {
			l.refuseLocked(u, name, kindRate)
			r.mu.Unlock()
			return false
		}
		r.mu.Unlock()
		if r.sleep(ctx, need) != nil {
			r.mu.Lock()
			l.refuseLocked(u, name, kindRate)
			r.mu.Unlock()
			return false
		}
	}
}

// TCPConn is a user's place among its TCP connections.
type TCPConn struct {
	l    *Limiter
	u    *user
	name string
	done bool // under l.r.mu
}

// TCP takes a place among the user's TCP connections, until Done; ErrLimit
// when there is none.
func (l *Limiter) TCP(name string) (*TCPConn, error) {
	r := l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	u := l.userLocked(name, r.now())
	if l.c.Connections > 0 && u.tcp >= l.c.Connections {
		l.refuseLocked(u, name, kindTCP)
		return nil, ErrLimit
	}
	u.tcp++
	return &TCPConn{l: l, u: u, name: name}, nil
}

// Retry takes a token for one more dial of the connection, without waiting.
func (c *TCPConn) Retry() bool {
	r := c.l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if !c.u.attempts.take(r.now(), c.l.c.Rate, c.l.c.Burst) {
		c.l.refuseLocked(c.u, c.name, kindRate)
		return false
	}
	return true
}

// Failed charges a dial that sent a SYN and got no connection (Chargeable)
// to the user's failed dials.
func (c *TCPConn) Failed(err error) {
	if c.l.c.FailedRate <= 0 || !Chargeable(err) {
		return
	}
	r := c.l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	c.u.failed.charge(r.now(), c.l.c.FailedRate, c.l.c.FailedBurst, c.l.debt)
}

// Done gives the place back.
func (c *TCPConn) Done() {
	r := c.l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if !c.done {
		c.done = true
		c.u.tcp--
	}
}

// Chargeable reports whether a dial's error means a SYN went and nothing
// came of it: a timeout, ECONNREFUSED, EHOSTUNREACH. ENETUNREACH and EPERM
// sent none (no route, or the node's conntrack guard refused it), nor is a
// dial its caller gave up the user's failure.
func Chargeable(err error) bool {
	switch {
	case err == nil, errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EPERM), errors.Is(err, context.Canceled):
		return false
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH):
		return true
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Final reports whether a dial's error is not worth another dial: the
// destination refused (ECONNREFUSED), or the node itself did (ENETUNREACH,
// EPERM: no route, or the conntrack guard).
func Final(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EPERM)
}

// IsEPERM reports whether the kernel refused to send a packet (EPERM: the
// node's conntrack guard or egress policy): the packet is dropped, as on
// the path, and its UDP session lives.
func IsEPERM(err error) bool { return errors.Is(err, syscall.EPERM) }

// bucket is a token bucket: rate tokens a second, up to burst. With no
// rate it is off: every take passes.
type bucket struct {
	tokens float64
	at     int64
}

// level is the tokens now, refilled.
func (b *bucket) level(now int64, rate, burst float64) float64 {
	if rate <= 0 {
		return burst
	}
	b.tokens = min(burst, b.tokens+float64(now-b.at)/float64(time.Second)*rate)
	b.at = now
	return b.tokens
}

func (b *bucket) full(now int64, rate, burst float64) bool {
	return rate <= 0 || b.tokens+float64(now-b.at)/float64(time.Second)*rate >= burst
}

func (b *bucket) take(now int64, rate, burst float64) bool {
	if rate <= 0 {
		return true
	}
	if b.level(now, rate, burst) < 1 {
		return false
	}
	b.tokens--
	return true
}

// charge takes a token in debt: down to -debt.
func (b *bucket) charge(now int64, rate, burst, debt float64) {
	b.tokens = max(-debt, b.level(now, rate, burst)-1)
}
