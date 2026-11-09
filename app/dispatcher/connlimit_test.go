package dispatcher

import (
	"context"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/connlimit"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type limitPolicy struct {
	policy.DefaultManager
	lim *connlimit.Limiter
}

func (p *limitPolicy) ConnLimits(uint32) *connlimit.Limiter { return p.lim }

// admit takes a user's token before routing, TCP's or UDP's; a connection
// refused is interrupted at both ends, which is no clean end for the
// inbound that reads the link: a mux subconnection ends with the error bit.
func TestAdmit(t *testing.T) {
	refused := map[string]int{}
	r := connlimit.NewRegistry()
	r.SetCounters(func(user, kind string) connlimit.Counter { return counter{refused, user + "/" + kind} })
	d := &DefaultDispatcher{policy: &limitPolicy{lim: r.Limiter(connlimit.Config{Rate: 1, Burst: 2, UDPRate: 1, UDPBurst: 1, FoldAt: "-"})}}

	user := func(email string) context.Context {
		return session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: email}})
	}
	// try is whether a connection is admitted, and what the inbound then
	// reads from its end of the link when it is not.
	try := func(ctx context.Context, network net.Network) (bool, error) {
		t.Helper()
		// The dispatcher's ends of the link are the uplink's reader and
		// the downlink's writer; the inbound holds the other two.
		upR, upW := pipe.New(pipe.WithoutSizeLimit())
		downR, downW := pipe.New(pipe.WithoutSizeLimit())
		out, ok := d.admit(ctx, &transport.Link{Reader: upR, Writer: downW}, network)
		if ok != connlimit.PaidFromContext(out) {
			t.Fatal("admitted ", ok, ", marked paid ", connlimit.PaidFromContext(out))
		}
		if ok {
			return true, nil
		}
		b := buf.New()
		b.WriteString("data")
		if err := upW.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil {
			t.Error("the uplink of a refused connection still takes data")
		}
		_, err := downR.ReadMultiBuffer()
		return false, err
	}

	for i, email := range []string{"u5-0123456789abcdef", "u5-fedcba9876543210"} {
		if ok, _ := try(user(email), net.Network_TCP); !ok {
			t.Fatal("connection ", i, " within the burst refused")
		}
	}
	ok, err := try(user("u5-0123456789abcdef"), net.Network_TCP)
	if ok {
		t.Fatal("a third connection of u5 admitted without a token")
	}
	if err == nil || err == io.EOF {
		t.Fatal("the downlink of a refused connection ends cleanly: ", err)
	}
	// UDP has its own bucket, and another user its own.
	if ok, _ := try(user("u5-0123456789abcdef"), net.Network_UDP); !ok {
		t.Fatal("the first UDP session refused")
	}
	if ok, err := try(user("u5-0123456789abcdef"), net.Network_UDP); ok || err == nil || err == io.EOF {
		t.Fatal("a second UDP session without a token: ", ok, err)
	}
	if ok, _ := try(user("u6-0123456789abcdef"), net.Network_TCP); !ok {
		t.Fatal("u6 refused")
	}
	// Not limited: no user, a user without an email, a policy without
	// limits. Nothing is paid, so nothing is marked.
	for range 5 {
		for _, ctx := range []context.Context{context.Background(), user("")} {
			if out, ok := d.admit(ctx, &transport.Link{}, net.Network_TCP); !ok || connlimit.PaidFromContext(out) {
				t.Fatal("a connection without a user to limit: admitted ", ok)
			}
		}
	}
	plain := &DefaultDispatcher{policy: policy.DefaultManager{}}
	for range 5 {
		if out, ok := plain.admit(user("u5-n"), &transport.Link{}, net.Network_TCP); !ok || connlimit.PaidFromContext(out) {
			t.Fatal("a policy without limits: admitted ", ok)
		}
	}
	// A network without limits of its own is not limited: nothing paid,
	// and freedom takes it upstream's way.
	udpOnly := &DefaultDispatcher{policy: &limitPolicy{lim: r.Limiter(connlimit.Config{UDPSessions: 1})}}
	tcpOnly := &DefaultDispatcher{policy: &limitPolicy{lim: r.Limiter(connlimit.Config{Connections: 1})}}
	for _, c := range []struct {
		d       *DefaultDispatcher
		network net.Network
	}{{udpOnly, net.Network_TCP}, {tcpOnly, net.Network_UDP}} {
		if out, ok := c.d.admit(user("u5"), &transport.Link{}, c.network); !ok || connlimit.PaidFromContext(out) {
			t.Fatal(c.network, " without limits of its own: admitted ", ok, ", paid ", connlimit.PaidFromContext(out))
		}
	}
	if out, ok := udpOnly.admit(user("u5"), &transport.Link{}, net.Network_UDP); !ok || !connlimit.PaidFromContext(out) {
		t.Fatal("UDP with limits of its own: not paid")
	}
	if len(refused) != 2 || refused["u5/rate"] != 1 || refused["u5/dest"] != 1 {
		t.Fatal("refused: ", refused)
	}
}

type counter struct {
	m   map[string]int
	key string
}

func (c counter) Add(n int64) int64 {
	c.m[c.key] += int(n)
	return 0
}
