package connlimit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fake is a registry's clock, sleeps and counters in a test's hands.
type fake struct {
	mu      sync.Mutex
	now     int64
	slept   []time.Duration
	onSleep func() // runs in each sleep, before the clock moves
	refused map[string]int64
}

type fakeCounter struct {
	f   *fake
	key string
}

func (c fakeCounter) Add(n int64) int64 {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.refused[c.key] += n
	return 0
}

func (f *fake) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now += int64(d)
}

// count is the user's refusals of a kind.
func (f *fake) count(user, kind string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refused[user+"/"+kind]
}

// counts checks all the refusals counted: "user/kind" to their number.
func (f *fake) counts(t *testing.T, want map[string]int64) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, n := range want {
		if f.refused[k] != n {
			t.Errorf("refused %s: %d, want %d", k, f.refused[k], n)
		}
	}
	for k, n := range f.refused {
		if _, ok := want[k]; !ok {
			t.Errorf("refused %s: %d, want none", k, n)
		}
	}
}

func newFake(t *testing.T) (*Registry, *fake) {
	f := &fake{now: int64(time.Hour), refused: map[string]int64{}}
	r := NewRegistry()
	r.now = func() int64 {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	r.sleep = func(ctx context.Context, d time.Duration) error {
		if f.onSleep != nil {
			f.onSleep()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		f.mu.Lock()
		f.slept = append(f.slept, d)
		f.now += int64(d)
		f.mu.Unlock()
		return nil
	}
	r.ctMax = func() (uint64, error) { return 65536, nil }
	r.SetCounters(func(user, kind string) Counter { return fakeCounter{f, user + "/" + kind} })
	return r, f
}

func newLimiter(t *testing.T, c Config) (*Limiter, *fake) {
	r, f := newFake(t)
	return r.Limiter(c), f
}

func ap(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 443)
}

var bg = context.Background()

func TestTCPAtOnce(t *testing.T) {
	l, f := newLimiter(t, Config{Connections: 2})
	a, err := l.TCP("u5")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.TCP("u5"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.TCP("u5"); err != ErrLimit {
		t.Fatal("the third connection: ", err)
	}
	// At the limit a new connection is refused before it pays or waits.
	if err := l.Admit(bg, "u5", false); err != ErrLimit {
		t.Fatal("admitted at the limit: ", err)
	}
	// Another user is not held by it.
	if _, err := l.TCP("u6"); err != nil {
		t.Fatal("u6: ", err)
	}
	a.Done()
	a.Done() // once
	if _, err := l.TCP("u5"); err != nil {
		t.Fatal("after one closed: ", err)
	}
	if _, err := l.TCP("u5"); err != ErrLimit {
		t.Fatal("Done gave two places back: ", err)
	}
	f.counts(t, map[string]int64{"u5/tcp": 3})
	if len(f.slept) != 0 {
		t.Error("waited at the limit: ", f.slept)
	}
}

func TestAttemptBucket(t *testing.T) {
	l, f := newLimiter(t, Config{Rate: 4, Burst: 3})
	for i := range 3 {
		if err := l.Admit(bg, "u5", false); err != nil {
			t.Fatal(i, err)
		}
	}
	if len(f.slept) != 0 {
		t.Fatal("waited within the burst: ", f.slept)
	}
	// The fourth waits for its token: a quarter of a second at 4 a second.
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal("the fourth: ", err)
	}
	if len(f.slept) != 1 || f.slept[0] != 250*time.Millisecond {
		t.Fatal("waited ", f.slept, ", want 250ms")
	}
	f.counts(t, map[string]int64{})
	// Time refills it, up to the burst and no further.
	f.advance(time.Hour)
	for i := range 3 {
		if err := l.Admit(bg, "u5", false); err != nil {
			t.Fatal(i, err)
		}
	}
	if len(f.slept) != 1 {
		t.Fatal("the burst grew past 3: waited ", f.slept)
	}
}

func TestAttemptWaitsHalfASecondAtMost(t *testing.T) {
	// A token a second: the next one is a second away, more than the wait.
	l, f := newLimiter(t, Config{Rate: 1, Burst: 1})
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal(err)
	}
	if err := l.Admit(bg, "u5", false); err != ErrLimit {
		t.Fatal("admitted without a token: ", err)
	}
	if len(f.slept) != 0 {
		t.Fatal("waited for a token too far away: ", f.slept)
	}
	// Half a second later the token is half a second away: waited for.
	f.advance(500 * time.Millisecond)
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal(err)
	}
	if len(f.slept) != 1 || f.slept[0] != 500*time.Millisecond {
		t.Fatal("waited ", f.slept, ", want 500ms")
	}
	f.counts(t, map[string]int64{"u5/rate": 1})
}

func TestAttemptWaitHoldsAPlaceAndEndsWithContext(t *testing.T) {
	l, f := newLimiter(t, Config{Connections: 1, Rate: 4, Burst: 1})
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	f.onSleep = func() {
		// The one that waits holds the user's only place.
		if _, err := l.TCP("u5"); err != ErrLimit {
			t.Error("a place was free while one waited: ", err)
		}
		cancel() // the client leaves
	}
	if err := l.Admit(ctx, "u5", false); err != ErrLimit {
		t.Fatal("admitted after its context ended: ", err)
	}
	f.onSleep = nil
	if len(f.slept) != 0 {
		t.Fatal("slept on after the context ended: ", f.slept)
	}
	// The place is back.
	c, err := l.TCP("u5")
	if err != nil {
		t.Fatal("the place of the one that left: ", err)
	}
	c.Done()
	f.counts(t, map[string]int64{"u5/tcp": 1, "u5/rate": 1})
}

func TestRetryPaysAToken(t *testing.T) {
	l, f := newLimiter(t, Config{Rate: 1, Burst: 3})
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal(err)
	}
	c, err := l.TCP("u5")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Done()
	if !c.Retry() || !c.Retry() {
		t.Fatal("no token for a retry within the burst")
	}
	if c.Retry() {
		t.Fatal("a retry without a token")
	}
	if len(f.slept) != 0 {
		t.Fatal("a retry waited: ", f.slept)
	}
	f.counts(t, map[string]int64{"u5/rate": 1})
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func dialErr(err error) error {
	return fmt.Errorf("dial: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)})
}

func TestChargeable(t *testing.T) {
	for _, c := range []struct {
		err    error
		charge bool
		final  bool
	}{
		{nil, false, false},
		{dialErr(syscall.ECONNREFUSED), true, true},
		{dialErr(syscall.EHOSTUNREACH), true, false},
		{dialErr(syscall.ETIMEDOUT), true, false},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, true, false},
		{context.DeadlineExceeded, true, false},
		{os.ErrDeadlineExceeded, true, false},
		// No SYN went: no route, or the conntrack guard refused it.
		{dialErr(syscall.ENETUNREACH), false, true},
		{dialErr(syscall.EPERM), false, true},
		// The client left.
		{context.Canceled, false, false},
		{errors.New("no such host"), false, false},
	} {
		if got := Chargeable(c.err); got != c.charge {
			t.Errorf("Chargeable(%v) = %v", c.err, got)
		}
		if got := Final(c.err); got != c.final {
			t.Errorf("Final(%v) = %v", c.err, got)
		}
	}
	if !IsEPERM(dialErr(syscall.EPERM)) || IsEPERM(dialErr(syscall.EACCES)) || IsEPERM(nil) {
		t.Error("IsEPERM is EPERM alone")
	}
	for _, err := range []error{io.EOF, io.ErrClosedPipe, context.Canceled} {
		if errors.Is(ErrLimit, err) {
			t.Error("ErrLimit is ", err, ": an outbound would take it for a normal end")
		}
	}
}

func TestFailedDialsInDebt(t *testing.T) {
	l, f := newLimiter(t, Config{Connections: 8, FailedRate: 1, FailedBurst: 2})
	c, err := l.TCP("u5")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Done()
	// What sent no SYN, or the client gave up, is not charged.
	for range 10 {
		c.Failed(dialErr(syscall.ENETUNREACH))
		c.Failed(dialErr(syscall.EPERM))
		c.Failed(context.Canceled)
		c.Failed(nil)
	}
	// Two failures empty the bucket; nothing is owed yet.
	c.Failed(dialErr(syscall.ECONNREFUSED))
	c.Failed(dialErr(syscall.EHOSTUNREACH))
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal("refused with nothing owed: ", err)
	}
	// The third is paid into debt: new connections are refused, at once.
	c.Failed(&net.OpError{Op: "dial", Err: timeoutErr{}})
	if err := l.Admit(bg, "u5", false); err != ErrLimit {
		t.Fatal("admitted in debt: ", err)
	}
	if len(f.slept) != 0 {
		t.Fatal("waited in debt: ", f.slept)
	}
	// Another user owes nothing.
	if err := l.Admit(bg, "u6", false); err != nil {
		t.Fatal("u6: ", err)
	}
	// One a second pays it off.
	f.advance(time.Second)
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal("refused with the debt paid: ", err)
	}
	f.counts(t, map[string]int64{"u5/failed": 1})

	// The debt has a floor: as many failures as dials may be in flight.
	for range 1000 {
		c.Failed(dialErr(syscall.ECONNREFUSED))
	}
	f.advance(7 * time.Second)
	if err := l.Admit(bg, "u5", false); err != ErrLimit {
		t.Fatal("admitted 7 s into a debt of 8: ", err)
	}
	f.advance(time.Second)
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal("the debt went below its floor of 8: ", err)
	}
}

func TestNames(t *testing.T) {
	l, _ := newLimiter(t, Config{FoldAt: "-"})
	for email, want := range map[string]string{
		"u5": "u5", "u5-0123456789abcdef": "u5", "u5-n": "u5", "u5-p": "u5", "u51-n": "u51", "-n": "-n", "": "",
	} {
		if got := l.Name(email); got != want {
			t.Errorf("FoldAt: Name(%q) = %q, want %q", email, got, want)
		}
	}
	l, _ = newLimiter(t, Config{FoldSuffixes: []string{"-n", "-p", ""}})
	for email, want := range map[string]string{
		"u5": "u5", "u5-n": "u5", "u5-p": "u5", "u5-x": "u5-x", "u5-n-p": "u5-n", "-n": "-n", "": "",
	} {
		if got := l.Name(email); got != want {
			t.Errorf("FoldSuffixes: Name(%q) = %q, want %q", email, got, want)
		}
	}
	l, _ = newLimiter(t, Config{})
	if got := l.Name("u5-n"); got != "u5-n" {
		t.Errorf("no folding: Name = %q", got)
	}
}

// The emails of a user's credentials spend one budget.
func TestCredentialsShareTheBudget(t *testing.T) {
	l, f := newLimiter(t, Config{Connections: 2, FoldAt: "-"})
	for _, email := range []string{"u5-0123456789abcdef", "u5-fedcba9876543210"} {
		if _, err := l.TCP(l.Name(email)); err != nil {
			t.Fatal(email, err)
		}
	}
	if _, err := l.TCP(l.Name("u5-n")); err != ErrLimit {
		t.Fatal("a third credential of u5 got a place of its own: ", err)
	}
	if _, err := l.TCP(l.Name("u6-0123456789abcdef")); err != nil {
		t.Fatal("u6: ", err)
	}
	f.counts(t, map[string]int64{"u5/tcp": 1})
}

func TestOffLimitsPass(t *testing.T) {
	l, f := newLimiter(t, Config{})
	c, err := l.TCP("u5")
	if err != nil {
		t.Fatal(err)
	}
	for range 5000 {
		if err := l.Admit(bg, "u5", false); err != nil {
			t.Fatal(err)
		}
		if err := l.Admit(bg, "u5", true); err != nil {
			t.Fatal(err)
		}
		if _, err := l.TCP("u5"); err != nil {
			t.Fatal(err)
		}
		if !c.Retry() {
			t.Fatal("retry")
		}
		c.Failed(dialErr(syscall.ECONNREFUSED))
	}
	s, err := l.UDP("u5", false)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5000 {
		if _, err := l.UDP("u5", false); err != nil {
			t.Fatal(err)
		}
		if !s.Send(ap(i)) || !s.Lookup() {
			t.Fatal("a packet dropped with no limits")
		}
	}
	if len(s.pairs) != 0 {
		t.Error("pairs kept with nothing to limit: ", len(s.pairs))
	}
	f.counts(t, map[string]int64{})
}

func TestBucketBurstDefaults(t *testing.T) {
	// A rate without a burst still lets a connection through.
	l, _ := newLimiter(t, Config{Rate: 30})
	if l.c.Burst != 30 {
		t.Error("burst ", l.c.Burst)
	}
	if err := l.Admit(bg, "u5", false); err != nil {
		t.Fatal(err)
	}
}

// A user with nothing open, nothing owed and full buckets is forgotten; its
// counters are not.
func TestSweep(t *testing.T) {
	l, f := newLimiter(t, Config{Connections: 1, Rate: 1, Burst: 2, UDPLive: 8, UDPRate: 1, UDPBurst: 2})
	c, _ := l.TCP("open")
	s, _ := l.UDP("udp", true)
	s.Send(ap(1))
	p, _ := l.UDP("pairs", true)
	p.Send(ap(1))
	p.Done()
	if err := l.Admit(bg, "spent", false); err != nil {
		t.Fatal(err)
	}
	g, _ := l.TCP("gone")
	g.Done()
	if _, err := l.TCP("open"); err != ErrLimit {
		t.Fatal(err)
	}
	users := func() int {
		l.r.mu.Lock()
		defer l.r.mu.Unlock()
		l.userLocked("probe", l.r.now())
		return len(l.users) - 1
	}
	f.advance(11 * time.Second)
	if n := users(); n != 3 { // spent has refilled; open, udp and pairs stay
		t.Fatal("users after 11 s: ", n)
	}
	c.Done()
	s.Done()
	f.advance(31 * time.Second) // the pairs' time ran out
	if n := users(); n != 0 {
		t.Fatal("users after all ended: ", n)
	}
	if l.r.pairs != 0 || l.r.withPairs != 0 {
		t.Error("pairs left counted: ", l.r.pairs, l.r.withPairs)
	}
	f.counts(t, map[string]int64{"open/tcp": 1})
}

// Counters set while refusals are counted, and limits used from many
// goroutines: for the race detector.
func TestConcurrent(t *testing.T) {
	r := NewRegistry()
	l := r.Limiter(Config{Connections: 4, Rate: 1000, Burst: 50, FailedRate: 100, FailedBurst: 5,
		UDPSessions: 4, UDPRate: 1000, UDPBurst: 50, UDPLive: 16, LookupRate: 100, LookupBurst: 5})
	var refused sync.Map
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			r.SetCounters(func(user, kind string) Counter {
				c, _ := refused.LoadOrStore(user+"/"+kind, new(atomicCounter))
				return c.(*atomicCounter)
			})
		}
	}()
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprint("u", g%3)
			ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
			defer cancel()
			for i := range 300 {
				if l.Admit(ctx, name, false) == nil {
					if c, err := l.TCP(name); err == nil {
						c.Retry()
						c.Failed(dialErr(syscall.ECONNREFUSED))
						c.Done()
					}
				}
				if l.Admit(ctx, name, true) == nil {
					if s, err := l.UDP(name, true); err == nil {
						s.OnEvict(func() {})
						s.Send(ap(i % 40))
						s.Heard(ap(i % 40))
						s.Unsent(ap(i % 7))
						s.Lookup()
						s.Done()
						s.Send(ap(1))
					}
				}
			}
		}()
	}
	wg.Wait()
}

type atomicCounter struct {
	mu sync.Mutex
	n  int64
}

func (c *atomicCounter) Add(n int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += n
	return c.n - n
}
