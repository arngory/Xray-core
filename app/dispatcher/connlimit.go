package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// admit takes what a new connection of a user with connection limits pays
// before it is routed (fork: common/connlimit, FORK.md): TCP a token for
// its first dial, a UDP session one for its first destination. Routing may
// look the destination's name up (IPOnDemand), so the token also bounds
// the user's lookups.
//
// A connection refused is interrupted at both ends, as when its dial
// fails, and false is returned: a VLESS connection closes, a mux
// subconnection ends with the error bit and its mux lives on. Otherwise
// the context returned says the token is paid.
func (d *DefaultDispatcher) admit(ctx context.Context, link *transport.Link, network net.Network) (context.Context, bool) {
	if network != net.Network_TCP && network != net.Network_UDP {
		return ctx, true
	}
	lim, name := connlimit.FromContext(ctx, d.policy)
	if lim == nil {
		return ctx, true
	}
	if err := lim.Admit(ctx, name, network == net.Network_UDP); err != nil {
		// Neither who nor where: the level is debug, the limit is the user's.
		errors.LogDebug(ctx, err.Error())
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return ctx, false
	}
	return connlimit.ContextWithPaid(ctx), true
}
