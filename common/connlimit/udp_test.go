package connlimit

import (
	"net/netip"
	"testing"
	"time"
)

// pairsOf is the user's counted pairs, aged now.
func pairsOf(l *Limiter, name string) int {
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	u := l.users[name]
	if u == nil {
		return 0
	}
	l.recountLocked(u, l.r.now())
	return u.pairs
}

func mustUDP(t *testing.T, l *Limiter, name string) *UDPSession {
	t.Helper()
	s, err := l.UDP(name, true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestUDPSessionsAndEviction(t *testing.T) {
	l, f := newLimiter(t, Config{UDPSessions: 2})
	a, b := mustUDP(t, l, "u5"), mustUDP(t, l, "u5")
	var ended []string
	a.OnEvict(func() { ended = append(ended, "a") })
	b.OnEvict(func() { ended = append(ended, "b") })
	// Neither has been quiet for 10 s: the third is refused.
	f.advance(9 * time.Second)
	if _, err := l.UDP("u5", true); err != ErrLimit {
		t.Fatal("the third session: ", err)
	}
	// Another user has its own.
	mustUDP(t, l, "u6")
	// a hears an answer, b stays silent: b is the quietest, and at 10 s
	// gives way.
	a.Heard(ap(1))
	f.advance(time.Second)
	c := mustUDP(t, l, "u5")
	if len(ended) != 1 || ended[0] != "b" {
		t.Fatal("gave way: ", ended, ", want b")
	}
	// The one that gave way sends nothing more, and its Done changes nothing.
	if b.Send(ap(2)) {
		t.Error("a session that gave way sent a packet")
	}
	b.Done()
	// a sent 1 s ago, c is new: nobody is quiet.
	if _, err := l.UDP("u5", true); err != ErrLimit {
		t.Fatal("a fourth with none quiet: ", err)
	}
	// Packets sent keep a session from being the quiet one too.
	f.advance(9 * time.Second)
	c.Send(ap(3))
	f.advance(time.Second)
	mustUDP(t, l, "u5")
	if len(ended) != 2 || ended[1] != "a" {
		t.Fatal("gave way: ", ended, ", want b then a")
	}
	// A session's end frees its place.
	c.Done()
	mustUDP(t, l, "u5")
	f.counts(t, map[string]int64{"u5/udp": 2, "u5/evicted": 2})
}

// A session evicted before it could say how to end is ended when it does.
func TestEvictedBeforeOnEvict(t *testing.T) {
	l, f := newLimiter(t, Config{UDPSessions: 1})
	a := mustUDP(t, l, "u5")
	f.advance(10 * time.Second)
	mustUDP(t, l, "u5")
	ended := false
	a.OnEvict(func() { ended = true })
	if !ended {
		t.Fatal("the session that gave way was not ended")
	}
}

// A session whose packets are not seen is never the quiet one.
func TestPinnedSessionDoesNotGiveWay(t *testing.T) {
	l, f := newLimiter(t, Config{UDPSessions: 1})
	mustUDP(t, l, "u5").Pin()
	f.advance(time.Hour)
	if _, err := l.UDP("u5", true); err != ErrLimit {
		t.Fatal("a pinned session gave way: ", err)
	}
	f.counts(t, map[string]int64{"u5/udp": 1})
}

func TestNewDestinations(t *testing.T) {
	l, f := newLimiter(t, Config{UDPRate: 1, UDPBurst: 2})
	// The dispatcher pays a session's first destination: Admit, then the
	// first pair is free.
	if err := l.Admit(bg, "u5", true); err != nil {
		t.Fatal(err)
	}
	s := mustUDP(t, l, "u5")
	if !s.Send(ap(1)) {
		t.Fatal("the first destination, paid for")
	}
	if !s.Send(ap(2)) {
		t.Fatal("the second destination: a token was left")
	}
	if s.Send(ap(3)) {
		t.Fatal("a third destination without a token")
	}
	// A destination the session sent to is not new.
	for range 100 {
		if !s.Send(ap(1)) || !s.Send(ap(2)) {
			t.Fatal("a packet to a known destination dropped")
		}
	}
	// IPv4 and the same address mapped into IPv6 are one destination.
	mapped := netip.AddrPortFrom(netip.AddrFrom16(ap(1).Addr().As16()), ap(1).Port())
	if !s.Send(mapped) {
		t.Fatal("the mapped form of a known destination was new")
	}
	// A session not through the dispatcher pays its first destination
	// itself, and with no token there is no session.
	if _, err := l.UDP("u5", false); err != ErrLimit {
		t.Fatal("a session without a token for its first destination: ", err)
	}
	if err := l.Admit(bg, "u5", true); err != ErrLimit {
		t.Fatal("admitted without a token: ", err)
	}
	f.advance(time.Second)
	if !s.Send(ap(3)) {
		t.Fatal("a second later a token is back")
	}
	f.counts(t, map[string]int64{"u5/dest": 3})
}

// A pair is counted as conntrack keeps it: 30 s after the last packet sent
// while unanswered, 120 s after the last packet either way once answered;
// in a live session.
func TestPairsAgeInALiveSession(t *testing.T) {
	l, f := newLimiter(t, Config{UDPLive: 2})
	s := mustUDP(t, l, "u5")
	if !s.Send(ap(1)) || !s.Send(ap(2)) {
		t.Fatal("two pairs")
	}
	s.Heard(ap(2)) // answered
	if s.Send(ap(3)) {
		t.Fatal("a third pair past the limit of 2")
	}
	// Known pairs still send at the limit.
	if !s.Send(ap(1)) {
		t.Fatal("a known pair dropped at the limit")
	}
	f.advance(29 * time.Second)
	if s.Send(ap(3)) {
		t.Fatal("29 s after its last packet the unanswered pair is still counted")
	}
	f.advance(time.Second)
	// 30 s: the unanswered pair is gone, the answered one is not. A long
	// socket that stopped sending to old destinations takes new ones again.
	if !s.Send(ap(3)) {
		t.Fatal("30 s after its last packet the unanswered pair still held its place")
	}
	if n := pairsOf(l, "u5"); n != 2 {
		t.Fatal("pairs: ", n)
	}
	// The answered pair: 120 s after the last packet either way, and an
	// answer at 100 s moves that.
	f.advance(70 * time.Second) // 100 s after the answer; 3 is gone again
	s.Heard(ap(2))
	if n := pairsOf(l, "u5"); n != 1 {
		t.Fatal("pairs at 100 s: ", n)
	}
	f.advance(119 * time.Second)
	if n := pairsOf(l, "u5"); n != 1 {
		t.Fatal("119 s after its last answer the pair is gone")
	}
	f.advance(time.Second)
	if n := pairsOf(l, "u5"); n != 0 {
		t.Fatal("120 s after its last answer the pair is still counted")
	}
	// A pair whose time ran out is a new one when sent to again.
	if !s.Send(ap(2)) || pairsOf(l, "u5") != 1 {
		t.Fatal("the old pair, sent to again")
	}
	f.counts(t, map[string]int64{"u5/live": 2})
}

// The pairs of a session that ended, or gave way, live out their time in
// the user's journal.
func TestPairsOutliveTheirSession(t *testing.T) {
	l, f := newLimiter(t, Config{UDPSessions: 1, UDPLive: 3})
	s := mustUDP(t, l, "u5")
	s.Send(ap(1))
	s.Send(ap(2))
	s.Heard(ap(2))
	s.Done()
	n := mustUDP(t, l, "u5")
	if !n.Send(ap(3)) {
		t.Fatal("the third pair of the user")
	}
	if n.Send(ap(4)) {
		t.Fatal("the pairs of the ended session were forgotten")
	}
	// The same destination from a new session is another pair: another
	// local port.
	if n.Send(ap(1)) {
		t.Fatal("a pair of the ended session was taken for the new session's")
	}
	// It sends once more at 10 s and gives way at 20 s, after 10 s of
	// silence: its pair goes to the journal too.
	f.advance(10 * time.Second)
	n.Send(ap(3))
	f.advance(10 * time.Second)
	m := mustUDP(t, l, "u5")
	if m.Send(ap(4)) {
		t.Fatal("the pair of the session that gave way was forgotten")
	}
	f.advance(10 * time.Second) // 30 s: the first session's unanswered pair ends
	if !m.Send(ap(4)) {
		t.Fatal("30 s after its last packet the unanswered pair of an ended session still held")
	}
	if m.Send(ap(5)) {
		t.Fatal("the answered pair of the ended session or the evicted one's was forgotten")
	}
	f.advance(10 * time.Second) // 40 s: the evicted session's pair, last sent at 10 s, ends
	if !m.Send(ap(5)) {
		t.Fatal("30 s after its last packet the pair of the session that gave way still held")
	}
	f.advance(30 * time.Second) // 70 s: the new session's pairs end; the answered one is left
	if got := pairsOf(l, "u5"); got != 1 {
		t.Fatal("pairs at 70 s: ", got)
	}
	f.advance(49 * time.Second)
	if got := pairsOf(l, "u5"); got != 1 {
		t.Fatal("119 s after its last packet the answered pair of the ended session is gone")
	}
	f.advance(time.Second)
	if got := pairsOf(l, "u5"); got != 0 {
		t.Fatal("pairs at 120 s: ", got)
	}
	f.counts(t, map[string]int64{"u5/live": 4, "u5/evicted": 1})
}

// A pair the kernel refused the packet of (EPERM: the conntrack guard, the
// egress policy) is no conntrack entry: not counted, in the session or the
// journal, until a packet goes through.
func TestRefusedPairsAreNotCounted(t *testing.T) {
	l, _ := newLimiter(t, Config{UDPLive: 2})
	s := mustUDP(t, l, "u5")
	for i := range 2 {
		if !s.Send(ap(i)) {
			t.Fatal("pair ", i)
		}
		s.Unsent(ap(i))
	}
	if n := pairsOf(l, "u5"); n != 0 {
		t.Fatal("refused pairs counted: ", n)
	}
	if !s.Send(ap(2)) || !s.Send(ap(3)) {
		t.Fatal("refused pairs held the places of real ones")
	}
	// Sent again, and not refused, it is a new pair: no room for it.
	if s.Send(ap(0)) {
		t.Fatal("a refused pair revived past the user's pairs")
	}
	if n := pairsOf(l, "u5"); n != 2 {
		t.Fatal("pairs: ", n)
	}
	// Refused pairs do not go to the journal either.
	s.Unsent(ap(3))
	s.Done()
	if n := pairsOf(l, "u5"); n != 1 {
		t.Fatal("pairs in the journal: ", n)
	}
}

// A pair the kernel refused is not counted, but the packet that revives it
// is a new pair: within the user's pairs and the process's ceiling, without
// a second token for its destination. Otherwise refusals while the guard is
// on would let a user hold any number of pairs once it is off.
func TestRefusedPairsCannotExceedTheLimit(t *testing.T) {
	l, f := newLimiter(t, Config{UDPLive: 4, UDPRate: 4, UDPBurst: 4})
	s := mustUDP(t, l, "u5")
	// The guard is on: 4 new destinations a second, each refused.
	for i := range 20 {
		if !s.Send(ap(i)) {
			t.Fatal("refused pairs held the places of new ones: ", i)
		}
		s.Unsent(ap(i))
		if i%4 == 3 {
			f.advance(time.Second)
		}
	}
	if n := pairsOf(l, "u5"); n != 0 {
		t.Fatal("refused pairs counted: ", n)
	}
	// It is off: the session sends to all 20 again, no token for a new
	// destination left.
	sent := 0
	for i := range 20 {
		if s.Send(ap(i)) {
			sent++
		}
	}
	if sent != 4 || pairsOf(l, "u5") != 4 {
		t.Fatal("pairs revived: ", sent, ", counted ", pairsOf(l, "u5"), "; want the limit, 4")
	}
	f.counts(t, map[string]int64{"u5/live": 16})

	// At the process's ceiling, a revived pair is a new one too.
	r, f := newFake(t)
	r.ctMax = func() (uint64, error) { return 8, nil } // a ceiling of 2
	l = r.Limiter(Config{UDPLive: 100})
	s, o := mustUDP(t, l, "u5"), mustUDP(t, l, "u6")
	for i := range 2 {
		s.Send(ap(i))
		s.Unsent(ap(i))
	}
	f.advance(time.Second)
	s.Send(ap(2))
	s.Send(ap(3))
	o.Send(ap(0))
	// 3 pairs of 2 users at a ceiling of 2: u5, with 2, is above the share
	// of 1.
	if s.Send(ap(0)) {
		t.Fatal("a refused pair revived past the ceiling, above the share")
	}
	f.counts(t, map[string]int64{"u5/live": 1})
}

// At the process's ceiling, a quarter of nf_conntrack_max, only the users
// above their fair share are refused.
func TestProcessCeiling(t *testing.T) {
	r, f := newFake(t)
	max := uint64(40)
	reads := 0
	r.ctMax = func() (uint64, error) { reads++; return max, nil }
	l := r.Limiter(Config{UDPLive: 100})
	other := r.Limiter(Config{UDPLive: 100}) // another level: the same ceiling
	big, small, third := mustUDP(t, l, "big"), mustUDP(t, l, "small"), mustUDP(t, other, "third")
	for i := range 7 {
		if !big.Send(ap(i)) {
			t.Fatal("big ", i)
		}
	}
	small.Send(ap(0))
	third.Send(ap(0))
	if !big.Send(ap(7)) {
		t.Fatal("the tenth pair of the process")
	}
	// 10 pairs of 3 users: the ceiling. The share is 3.
	if big.Send(ap(8)) {
		t.Fatal("big, with 8 pairs, got one more at the ceiling")
	}
	for i := 1; i <= 3; i++ {
		if !small.Send(ap(i)) || !third.Send(ap(i)) {
			t.Fatal("small and third are not above their share: pair ", i)
		}
	}
	if small.Send(ap(4)) {
		t.Fatal("small, with 4 pairs, is above the share of 3")
	}
	if reads != 1 {
		t.Fatal("nf_conntrack_max read ", reads, " times")
	}
	// The ceiling follows nf_conntrack_max within a minute. (The pairs are
	// answered: they live through it.)
	for i := range 8 {
		big.Heard(ap(i))
		small.Heard(ap(i))
		third.Heard(ap(i))
	}
	max = 400
	f.advance(59 * time.Second)
	if big.Send(ap(8)) {
		t.Fatal("the ceiling moved before its minute")
	}
	f.advance(time.Second)
	if !big.Send(ap(8)) {
		t.Fatal("the ceiling did not follow nf_conntrack_max")
	}
	if reads != 2 {
		t.Fatal("nf_conntrack_max read ", reads, " times")
	}
	f.counts(t, map[string]int64{"big/live": 2, "small/live": 1})

	// Unreadable: the default.
	r.ctMax = func() (uint64, error) { return 0, errTest }
	f.advance(time.Minute)
	r.mu.Lock()
	c := r.ceilingLocked(r.now())
	r.mu.Unlock()
	if c != 65536/4 {
		t.Fatal("the default ceiling: ", c)
	}
}

var errTest = &testErr{}

type testErr struct{}

func (*testErr) Error() string { return "test" }

// At the ceiling the pairs that ran out are aged for every user before
// anyone is refused, once a second at most.
func TestCeilingAgesEveryone(t *testing.T) {
	r, f := newFake(t)
	r.ctMax = func() (uint64, error) { return 16, nil } // a ceiling of 4
	l := r.Limiter(Config{UDPLive: 100})
	old, s := mustUDP(t, l, "old"), mustUDP(t, l, "u5")
	old.Send(ap(0))
	f.advance(15 * time.Second)
	for i := range 3 {
		s.Send(ap(i))
	}
	// u5 has 3 of the share of 2. 15 s later the pair of old ran out, though
	// nothing aged it: there is room, and u5 is the only user with pairs.
	f.advance(15 * time.Second)
	for i := range 3 {
		s.Send(ap(i))
	}
	if !s.Send(ap(3)) {
		t.Fatal("refused at a ceiling that counted a pair long gone")
	}
	// The ceiling is u5's whole share now: one above it, no more.
	if !s.Send(ap(4)) || s.Send(ap(5)) {
		t.Fatal("u5 alone at the ceiling of 4: a fifth pair, not a sixth")
	}
}

func TestLookups(t *testing.T) {
	l, f := newLimiter(t, Config{LookupRate: 2, LookupBurst: 3})
	s, o := mustUDP(t, l, "u5"), mustUDP(t, l, "u5")
	if !s.Lookup() || !o.Lookup() || !s.Lookup() {
		t.Fatal("three lookups within the burst, of the user's sessions together")
	}
	if s.Lookup() {
		t.Fatal("a fourth lookup")
	}
	if !mustUDP(t, l, "u6").Lookup() {
		t.Fatal("u6")
	}
	f.advance(500 * time.Millisecond)
	if !o.Lookup() {
		t.Fatal("half a second later one is back")
	}
	f.counts(t, map[string]int64{"u5/lookup": 1})
}

// A packet to a pair the session has takes no lock but the session's own
// and allocates nothing.
func TestPacketPathAllocatesNothing(t *testing.T) {
	r := NewRegistry()
	l := r.Limiter(Config{UDPLive: 16, UDPRate: 100, UDPBurst: 100})
	s := mustUDP(t, l, "u5")
	to := ap(1)
	s.Send(to)
	r.mu.Lock() // a packet that took the registry's lock would hang here
	n := testing.AllocsPerRun(1000, func() {
		if !s.Send(to) {
			t.Fatal("dropped")
		}
		s.Heard(to)
	})
	r.mu.Unlock()
	if n != 0 {
		t.Fatal("allocations a packet: ", n)
	}
}
