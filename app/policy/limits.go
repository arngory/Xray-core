package policy

import (
	"context"

	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// The per-user connection limits of the levels (fork: common/connlimit,
// FORK.md). The process has one registry; a level with "limits" has a
// limiter in it, a level without has none.

// newLimits makes the limiters of the levels that have limits, any of
// their numbers on; nil when none has.
func newLimits(ctx context.Context, config *Config) map[uint32]*connlimit.Limiter {
	var registry *connlimit.Registry
	var limits map[uint32]*connlimit.Limiter
	for level, p := range config.Level {
		if p.GetLimits() == nil || p.Limits.toConnLimit().Off() {
			continue
		}
		if registry == nil {
			registry = connlimit.NewRegistry()
			limits = map[uint32]*connlimit.Limiter{}
		}
		limits[level] = registry.Limiter(p.Limits.toConnLimit())
	}
	if registry != nil && core.FromContext(ctx) != nil {
		// Refusals are counted in the stats, by base name and kind, each
		// counter made at its first refusal. Without the stats app there is
		// nowhere to count them.
		_ = core.RequireFeatures(ctx, func(sm stats.Manager) {
			registry.SetCounters(func(user, kind string) connlimit.Counter {
				c, _ := sm.GetOrRegisterCounter(LimitCounterName(user, kind))
				if c == nil {
					return nil
				}
				return c
			})
		})
	}
	return limits
}

// LimitCounterName is the name of the stats counter of a user's refusals
// of a kind: "user>>>u5>>>limit>>>tcp". The user is the base name the
// limits go by; the kinds are tcp, rate, failed, udp, evicted, dest, live
// and lookup.
func LimitCounterName(user, kind string) string {
	return "user>>>" + user + ">>>limit>>>" + kind
}

func (l *Policy_Limits) toConnLimit() connlimit.Config {
	return connlimit.Config{
		Connections:  int(l.Connections),
		Rate:         float64(l.Rate),
		Burst:        float64(l.Burst),
		FailedRate:   float64(l.FailedRate),
		FailedBurst:  float64(l.FailedBurst),
		UDPSessions:  int(l.UdpSessions),
		UDPRate:      float64(l.UdpRate),
		UDPBurst:     float64(l.UdpBurst),
		UDPLive:      int(l.UdpLive),
		LookupRate:   float64(l.LookupRate),
		LookupBurst:  float64(l.LookupBurst),
		FoldAt:       l.FoldAt,
		FoldSuffixes: l.FoldSuffixes,
	}
}

// ConnLimits implements connlimit.Provider: the limiter of a level, nil
// when the level has no limits.
func (m *Instance) ConnLimits(level uint32) *connlimit.Limiter {
	return m.limits[level]
}
