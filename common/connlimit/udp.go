package connlimit

import (
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// UDPSession is a user's place among its UDP sessions, and the pairs
// (destination; the local port is the session's socket) the session sent
// to: each is a conntrack entry until its time runs out.
type UDPSession struct {
	l    *Limiter
	u    *user
	name string

	// last is when the last packet went either way.
	last atomic.Int64
	// ended: the session is gone, as its packets see it; set under mu.
	ended atomic.Bool

	// Under l.r.mu.
	gone   bool   // ended or gave way: its place is free, its pairs in the journal
	evict  func() // ends the session, set by OnEvict
	asked  bool   // evicted before OnEvict
	free   bool   // the first destination is paid for
	paired bool   // the limiter keeps pairs

	mu    sync.Mutex
	pairs map[netip.AddrPort]pairTimes
	aged  int64
}

// pairTimes are a pair's last packet sent, last either way, and whether an
// answer came. refused: the kernel refused the last packet to it (the
// conntrack guard, the egress policy), so there is no entry to count.
type pairTimes struct {
	sent, any int64
	answered  bool
	refused   bool
}

// end is when conntrack lets the pair go.
func (p pairTimes) end() int64 {
	if p.answered {
		return p.any + int64(pairAnswered)
	}
	return p.sent + int64(pairUnanswered)
}

// UDP takes a place among the user's UDP sessions, until Done: at the
// limit the quietest session, silent quietAfter both ways, gives way.
// paid says Admit took the token of the session's first destination;
// otherwise it is taken now. ErrLimit when refused.
func (l *Limiter) UDP(name string, paid bool) (*UDPSession, error) {
	r := l.r
	r.mu.Lock()
	now := r.now()
	u := l.userLocked(name, now)
	if !paid && !u.dests.take(now, l.c.UDPRate, l.c.UDPBurst) {
		l.refuseLocked(u, name, kindDest)
		r.mu.Unlock()
		return nil, ErrLimit
	}
	var evict func()
	if l.c.UDPSessions > 0 && len(u.sessions) >= l.c.UDPSessions {
		var quiet *UDPSession
		for s := range u.sessions {
			last := s.last.Load()
			if now-last >= int64(quietAfter) && (quiet == nil || last < quiet.last.Load()) {
				quiet = s
			}
		}
		if quiet == nil {
			l.refuseLocked(u, name, kindUDP)
			r.mu.Unlock()
			return nil, ErrLimit
		}
		l.endLocked(quiet, now)
		quiet.asked = true
		evict, quiet.evict = quiet.evict, nil
		l.refuseLocked(u, name, kindEvicted)
	}
	s := &UDPSession{l: l, u: u, name: name, free: true, paired: l.c.UDPLive > 0 || l.c.UDPRate > 0,
		pairs: map[netip.AddrPort]pairTimes{}, aged: now}
	s.last.Store(now)
	if u.sessions == nil {
		u.sessions = map[*UDPSession]struct{}{}
	}
	u.sessions[s] = struct{}{}
	r.mu.Unlock()
	if evict != nil {
		evict() // not under the lock: it cancels contexts
	}
	return s, nil
}

// OnEvict sets what ends the session when it gives way to a new one; it
// runs at once if the session gave way already.
func (s *UDPSession) OnEvict(end func()) {
	r := s.l.r
	r.mu.Lock()
	asked := s.asked
	if !asked {
		s.evict = end
	}
	r.mu.Unlock()
	if asked {
		end()
	}
}

// Pin keeps the session from ever being the quiet one that gives way: for
// a session whose packets the limiter does not see (Send and Heard are not
// called for them).
func (s *UDPSession) Pin() { s.last.Store(math.MaxInt64) }

// Done gives the place back and moves the session's pairs to the user's
// journal, to live out their time there.
func (s *UDPSession) Done() {
	r := s.l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	s.evict = nil
	s.l.endLocked(s, r.now())
}

// endLocked takes a session out of its user's: once.
func (l *Limiter) endLocked(s *UDPSession, now int64) {
	if s.gone {
		return
	}
	s.gone = true
	u := s.u
	delete(u.sessions, s)
	s.mu.Lock()
	s.ended.Store(true)
	for _, t := range s.pairs {
		if end := t.end(); !t.refused && end > now {
			u.journal = append(u.journal, end)
		}
	}
	s.pairs = nil
	s.mu.Unlock()
	l.recountLocked(u, now)
}

// Send reports whether the session may send a packet to a destination: one
// it has a pair with, or a new one while the user's limits let it. A
// packet it may not send is dropped.
func (s *UDPSession) Send(to netip.AddrPort) bool {
	if s.ended.Load() {
		return false
	}
	now := s.l.r.now()
	s.last.Store(now)
	if !s.paired {
		return true
	}
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	s.mu.Lock()
	// A pair whose time ran out is a new one, as conntrack's entry is.
	t, ok := s.pairs[to]
	known := ok && now < t.end()
	if known && !t.refused {
		t.sent, t.any = now, now
		s.pairs[to] = t
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	// Not under s.mu: the limiter ages the user's sessions under its own lock.
	// A pair the kernel refused is not counted: the packet that would make
	// it a conntrack entry is a new pair, within the user's pairs and the
	// process's ceiling, but its destination is paid for already.
	if !s.l.newPair(s, known) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended.Load() {
		return false
	}
	s.pairs[to] = pairTimes{sent: now, any: now}
	return true
}

// Heard notes a packet that came from an address: an answer, if the
// session sent there.
func (s *UDPSession) Heard(from netip.AddrPort) {
	now := s.l.r.now()
	s.last.Store(now)
	if !s.paired {
		return
	}
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	s.mu.Lock()
	if t, ok := s.pairs[from]; ok {
		t.any, t.answered, t.refused = now, true, false
		s.pairs[from] = t
	}
	s.mu.Unlock()
}

// Unsent notes that the kernel refused the packet just sent to a
// destination: its pair is no conntrack entry, and is not counted (from
// the user's next recount, within ageEvery) until a packet goes through,
// which Send admits as a new pair.
func (s *UDPSession) Unsent(to netip.AddrPort) {
	if !s.paired {
		return
	}
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	s.mu.Lock()
	if t, ok := s.pairs[to]; ok && !t.answered {
		t.refused = true
		s.pairs[to] = t
	}
	s.mu.Unlock()
}

// Lookup takes a token for the lookup of a name in a packet.
func (s *UDPSession) Lookup() bool {
	r := s.l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if !s.u.lookups.take(r.now(), s.l.c.LookupRate, s.l.c.LookupBurst) {
		s.l.refuseLocked(s.u, s.name, kindLookup)
		return false
	}
	return true
}

// age drops the pairs whose time ran out, once in ageEvery at most, and
// says how many conntrack keeps.
func (s *UDPSession) age(now int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now-s.aged >= int64(ageEvery) {
		s.aged = now
		for p, t := range s.pairs {
			if now >= t.end() {
				delete(s.pairs, p)
			}
		}
	}
	n := 0
	for _, t := range s.pairs {
		if !t.refused {
			n++
		}
	}
	return n
}

// newPair admits a session's new pair: within the user's pairs, the
// process's ceiling, and a token for a new destination unless paid (the
// session's first is paid for). A refusal is counted.
func (l *Limiter) newPair(s *UDPSession, paid bool) bool {
	r := l.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.gone {
		return false
	}
	now := r.now()
	u := s.u
	if l.c.UDPLive > 0 {
		if now-u.aged >= int64(ageEvery) {
			l.recountLocked(u, now)
		}
		if u.pairs >= l.c.UDPLive {
			l.refuseLocked(u, s.name, kindLive)
			return false
		}
		if c := r.ceilingLocked(now); r.pairs >= c {
			// Every user's pairs aged first, once in ageEvery at most: the
			// count may be behind.
			if now-r.agedAll >= int64(ageEvery) {
				r.agedAll = now
				for _, x := range r.limiters {
					for _, xu := range x.users {
						x.recountLocked(xu, now)
					}
				}
			}
			// At the ceiling only those above their fair share are refused.
			if r.pairs >= c && u.pairs > c/max(1, r.withPairs) {
				l.refuseLocked(u, s.name, kindLive)
				return false
			}
		}
	}
	if s.free {
		s.free = false
	} else if !paid && !u.dests.take(now, l.c.UDPRate, l.c.UDPBurst) {
		l.refuseLocked(u, s.name, kindDest)
		return false
	}
	r.setPairsLocked(u, u.pairs+1)
	return true
}

// recountLocked ages a user's pairs, the live sessions' and the journal's,
// and sets the counts anew.
func (l *Limiter) recountLocked(u *user, now int64) {
	u.aged = now
	u.journal = slices.DeleteFunc(u.journal, func(end int64) bool { return now >= end })
	n := len(u.journal)
	for s := range u.sessions {
		n += s.age(now)
	}
	l.r.setPairsLocked(u, n)
}

// setPairsLocked sets a user's count of pairs, and the process's counts:
// its pairs, and how many users have some (the fair share of the ceiling
// is the ceiling over them; counted as it goes, not by walking the users
// at each new pair).
func (r *Registry) setPairsLocked(u *user, n int) {
	switch {
	case u.pairs == 0 && n > 0:
		r.withPairs++
	case u.pairs > 0 && n == 0:
		r.withPairs--
	}
	r.pairs += n - u.pairs
	u.pairs = n
}

// ceilingLocked is the process's ceiling of pairs: a quarter of the live
// nf_conntrack_max, read again every ceilingEvery.
func (r *Registry) ceilingLocked(now int64) int {
	if r.ceiling > 0 && now-r.ceilingAt < int64(ceilingEvery) {
		return r.ceiling
	}
	r.ceilingAt = now
	if v, err := r.ctMax(); err == nil && v >= 4 {
		r.ceiling = int(min(v/4, 1<<30))
	} else {
		r.ceiling = defaultCeiling
	}
	return r.ceiling
}
