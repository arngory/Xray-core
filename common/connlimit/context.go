package connlimit

import (
	"context"

	"github.com/xtls/xray-core/common/session"
)

// Provider gives the limiter of a policy level, nil for none. The policy
// manager of app/policy is one.
type Provider interface {
	ConnLimits(level uint32) *Limiter
}

// FromContext is the limiter of the user a connection came in as, and the
// base name it is limited by. nil when there is none: no user, a user
// without an email (nothing to key its limits by, as with its traffic
// counters), a policy manager without limits, or none for the user's level.
func FromContext(ctx context.Context, policyManager any) (*Limiter, string) {
	p, ok := policyManager.(Provider)
	if !ok {
		return nil, ""
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return nil, ""
	}
	l := p.ConnLimits(inbound.User.Level)
	if l == nil {
		return nil, ""
	}
	return l, l.Name(inbound.User.Email)
}

type paidKey struct{}

// ContextWithPaid marks that the dispatcher took what a new connection
// pays before routing (Limiter.Admit): the outbound does not take it again.
func ContextWithPaid(ctx context.Context) context.Context {
	return context.WithValue(ctx, paidKey{}, true)
}

// PaidFromContext reports the mark of ContextWithPaid.
func PaidFromContext(ctx context.Context) bool {
	return ctx.Value(paidKey{}) != nil
}
