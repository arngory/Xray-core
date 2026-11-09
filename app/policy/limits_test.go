package policy_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	featurestats "github.com/xtls/xray-core/features/stats"
)

func userContext(email string, level uint32) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: email, Level: level}})
}

// A level with "limits" has a limiter, a level without has none, and a
// policy without any is as upstream's.
func TestLimitsByLevel(t *testing.T) {
	m, err := New(context.Background(), &Config{Level: map[uint32]*Policy{
		0: {Limits: &Policy_Limits{Connections: 1, FoldAt: "-"}},
		1: {},
		2: {Limits: &Policy_Limits{Connections: 1, FoldSuffixes: []string{"-n", "-p"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if m.ConnLimits(0) == nil || m.ConnLimits(2) == nil {
		t.Fatal("no limiter for a level with limits")
	}
	if m.ConnLimits(1) != nil || m.ConnLimits(7) != nil {
		t.Fatal("a limiter for a level without limits")
	}
	// The user of a connection is limited by its level's limiter, under its
	// base name.
	for _, c := range []struct {
		email string
		level uint32
		name  string
	}{
		{"u5-0123456789abcdef", 0, "u5"},
		{"u5-n", 2, "u5"},
		{"u5-0123456789abcdef", 2, "u5-0123456789abcdef"},
	} {
		l, name := connlimit.FromContext(userContext(c.email, c.level), m)
		if l != m.ConnLimits(c.level) || name != c.name {
			t.Errorf("%s at level %d: limited as %q by %p", c.email, c.level, name, l)
		}
	}
	// Not limited: a level without limits, a user without an email, no user.
	for _, ctx := range []context.Context{userContext("u5", 1), userContext("", 0), context.Background(),
		session.ContextWithInbound(context.Background(), &session.Inbound{})} {
		if l, _ := connlimit.FromContext(ctx, m); l != nil {
			t.Error("a limiter where there is nothing to limit")
		}
	}

	// "limits" with every number zero (how emails fold is no limit) is no
	// limits.
	m, err = New(context.Background(), &Config{Level: map[uint32]*Policy{0: {}, 1: {Limits: &Policy_Limits{}},
		2: {Limits: &Policy_Limits{FoldAt: "-", FoldSuffixes: []string{"-n"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for level := range uint32(3) {
		if m.ConnLimits(level) != nil {
			t.Fatal("a limiter without limits, level ", level)
		}
	}
	if l, _ := connlimit.FromContext(userContext("u5", 0), m); l != nil {
		t.Fatal("limited without limits")
	}
	if l, _ := connlimit.FromContext(userContext("u5", 0), policy.DefaultManager{}); l != nil {
		t.Fatal("limited by the default policy manager")
	}
}

// Refusals are counted in the stats as user>>>NAME>>>limit>>>KIND, each
// counter made at its first refusal; without the stats app nothing breaks.
func TestLimitCounters(t *testing.T) {
	limits := serial.ToTypedMessage(&Config{Level: map[uint32]*Policy{0: {Limits: &Policy_Limits{Connections: 1, FoldAt: "-"}}}})
	for _, withStats := range []bool{true, false} {
		config := &core.Config{App: []*serial.TypedMessage{limits}}
		if withStats {
			// After the policy: the counters are tied once the stats are there.
			config.App = append(config.App, serial.ToTypedMessage(&stats.Config{}))
		}
		inst, err := core.New(config)
		if err != nil {
			t.Fatal(err)
		}
		defer inst.Close()
		pm := inst.GetFeature(policy.ManagerType())
		sm := inst.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
		l, name := connlimit.FromContext(userContext("u5-0123456789abcdef", 0), pm)
		if l == nil || name != "u5" {
			t.Fatal("the user's limiter: ", l, name)
		}
		if LimitCounterName(name, "tcp") != "user>>>u5>>>limit>>>tcp" {
			t.Fatal(LimitCounterName(name, "tcp"))
		}
		if sm.GetCounter("user>>>u5>>>limit>>>tcp") != nil {
			t.Fatal("a counter before any refusal")
		}
		if _, err := l.TCP(name); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if _, err := l.TCP(name); err != connlimit.ErrLimit {
				t.Fatal("a second connection: ", err)
			}
		}
		c := sm.GetCounter("user>>>u5>>>limit>>>tcp")
		if withStats && (c == nil || c.Value() != 3) {
			t.Fatal("the counter of refusals: ", c)
		}
		if !withStats && c != nil {
			t.Fatal("a counter without stats")
		}
	}
}
