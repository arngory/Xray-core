package inbound

import (
	"context"
	stderrors "errors"
	"io"
	gonet "net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/transport"
)

// testDispatcher stands in for the router and the outbound.
// By default it echoes the client's data until reading from the client fails;
// it never looks at the context, so only closing the connection ends it.
// With hold set it ignores the client and waits for the context, like a
// downlink splice waiting on an idle remote; only cancelling the context
// ends it.
// With stall set it writes to the client until a write blocks because the
// client does not read, then makes that write fail with a write deadline,
// closes stalled and waits for the context: the client's send buffer is full
// and no write is in flight, as after a burst from a remote that then went
// idle.
type testDispatcher struct {
	hold       bool
	stall      bool
	stalled    chan struct{}
	dispatched atomic.Int32
}

func (*testDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*testDispatcher) Start() error      { return nil }
func (*testDispatcher) Close() error      { return nil }

func (*testDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errors.New("not implemented")
}

func (d *testDispatcher) DispatchLink(ctx context.Context, _ net.Destination, link *transport.Link) error {
	d.dispatched.Add(1)
	if d.stall {
		var written atomic.Int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				b := buf.New()
				b.Extend(buf.Size)
				if link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
					return
				}
				written.Add(1)
			}
		}()
		for last := int64(-1); last != written.Load(); time.Sleep(100 * time.Millisecond) {
			last = written.Load()
		}
		session.InboundFromContext(ctx).Conn.SetWriteDeadline(time.Now())
		<-done
		close(d.stalled)
	}
	if d.hold || d.stall {
		<-ctx.Done()
		return ctx.Err()
	}
	return buf.Copy(link.Reader, link.Writer)
}

// removingValidator calls remove right after the first lookup that finds a
// user: after DecodeRequestHeader has authenticated the connection and before
// Process tracks it, the window a concurrent RemoveUser can hit.
type removingValidator struct {
	vless.Validator
	once   sync.Once
	remove func()
}

func (v *removingValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	u := v.Validator.Get(id)
	if u != nil {
		v.once.Do(v.remove)
	}
	return u
}

func newUser(t *testing.T, email, id string) *protocol.MemoryUser {
	t.Helper()
	u, err := (&protocol.User{
		Email:   email,
		Account: serial.ToTypedMessage(&vless.Account{Id: id}),
	}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newValidator(t *testing.T, users ...*protocol.MemoryUser) *vless.MemoryValidator {
	t.Helper()
	v := new(vless.MemoryValidator)
	for _, u := range users {
		if err := v.Add(u); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func newHandler(v vless.Validator) *Handler {
	return &Handler{policyManager: policy.DefaultManager{}, validator: v}
}

// serve accepts TCP connections and handles each like the inbound worker does.
// Every finished Process call sends its error to the returned channel.
func serve(t *testing.T, h *Handler, d routing.Dispatcher) (string, <-chan error) {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln.Addr().String(), serveOn(t, h, d, ln, nil)
}

// serveOn is serve on ln. If wrap is not nil, it adds the server side of the
// transport security to each accepted connection, as the transport listener
// does.
func serveOn(t *testing.T, h *Handler, d routing.Dispatcher, ln gonet.Listener, wrap func(gonet.Conn) (gonet.Conn, error)) <-chan error {
	t.Cleanup(func() { ln.Close() })
	network := net.Network_TCP
	if ln.Addr().Network() == "unix" {
		network = net.Network_UNIX
	}
	results := make(chan error, 1024)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if wrap != nil {
					raw := conn
					if conn, err = wrap(raw); err != nil {
						raw.Close()
						results <- err
						return
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "test", Conn: conn})
				err := h.Process(ctx, network, conn, d)
				cancel()
				conn.Close()
				results <- err
			}()
		}
	}()
	return results
}

func request(u *protocol.MemoryUser) *protocol.RequestHeader {
	return &protocol.RequestHeader{
		Version: encoding.Version,
		User:    u,
		Command: protocol.RequestCommandTCP,
		Address: net.LocalHostIP,
		Port:    443,
	}
}

// dialFunc opens a client connection ready for the VLESS request header.
type dialFunc func() (gonet.Conn, error)

func tcpDialer(addr string) dialFunc {
	return func() (gonet.Conn, error) { return gonet.Dial("tcp", addr) }
}

// dial opens a TCP connection and sends the request header of user u.
func dial(addr string, u *protocol.MemoryUser) (gonet.Conn, error) {
	return dialWith(tcpDialer(addr), u)
}

func dialWith(dial dialFunc, u *protocol.MemoryUser) (gonet.Conn, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	if err := encoding.EncodeRequestHeader(conn, request(u), &encoding.Addons{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// connect opens a TCP connection as user u and completes one echo round trip.
func connect(addr string, u *protocol.MemoryUser) (gonet.Conn, error) {
	return connectWith(tcpDialer(addr), u)
}

func connectWith(dial dialFunc, u *protocol.MemoryUser) (gonet.Conn, error) {
	conn, err := dialWith(dial, u)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := encoding.DecodeResponseHeader(conn, request(u)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := readPing(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func mustConnect(t *testing.T, addr string, u *protocol.MemoryUser) gonet.Conn {
	t.Helper()
	return mustConnectWith(t, tcpDialer(addr), u)
}

func mustConnectWith(t *testing.T, dial dialFunc, u *protocol.MemoryUser) gonet.Conn {
	t.Helper()
	conn, err := connectWith(dial, u)
	if err != nil {
		t.Fatal("connect as ", u.Email, ": ", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readPing(conn gonet.Conn) error {
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return err
	}
	if string(b) != "ping" {
		return errors.New("unexpected echo ", string(b))
	}
	return nil
}

// ping completes one echo round trip on an established connection.
func ping(conn gonet.Conn) error {
	conn.SetDeadline(time.Now().Add(time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	return readPing(conn)
}

// waitClosed fails unless the server closes conn within d.
func waitClosed(t *testing.T, conn gonet.Conn, d time.Duration) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(d))
	n, err := conn.Read(make([]byte, 64))
	var ne gonet.Error
	switch {
	case err == nil:
		t.Fatal("read ", n, " bytes from a connection that should be closed")
	case stderrors.As(err, &ne) && ne.Timeout():
		t.Fatal("connection still open after ", d)
	}
}

// waitResults waits for n Process calls to return within d and returns their errors.
func waitResults(t *testing.T, results <-chan error, n int, d time.Duration) []error {
	t.Helper()
	timeout := time.After(d)
	errs := make([]error, 0, n)
	for len(errs) < n {
		select {
		case err := <-results:
			errs = append(errs, err)
		case <-timeout:
			t.Fatal(len(errs), " of ", n, " connections ended within ", d)
		}
	}
	return errs
}

// tracked returns the number of users and connections in the tracker.
func tracked(h *Handler) (users, conns int) {
	h.conns.mu.Lock()
	defer h.conns.mu.Unlock()
	for _, s := range h.conns.m {
		conns += len(s)
	}
	return len(h.conns.m), conns
}

func checkTracked(t *testing.T, h *Handler, users, conns int) {
	t.Helper()
	if u, c := tracked(h); u != users || c != conns {
		t.Fatal("tracker holds ", u, " users and ", c, " connections, want ", users, " and ", conns)
	}
}

func TestRemoveUserClosesItsConnections(t *testing.T) {
	p := newUser(t, "u5-p", "a06fe789-5ab1-480b-8124-ae4599801ff3")
	n := newUser(t, "u5-n", "b06fe789-5ab1-480b-8124-ae4599801ff3")
	h := newHandler(newValidator(t, p, n))
	addr, results := serve(t, h, &testDispatcher{})

	p1 := mustConnect(t, addr, p)
	p2 := mustConnect(t, addr, p)
	n1 := mustConnect(t, addr, n)
	checkTracked(t, h, 2, 3)

	start := time.Now()
	if err := h.RemoveUser(context.Background(), "u5-p"); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, p1, time.Second)
	waitClosed(t, p2, time.Second)
	waitResults(t, results, 2, time.Second)
	t.Log("connections of u5-p ended ", time.Since(start), " after RemoveUser")

	// The other user's connection is untouched.
	if err := ping(n1); err != nil {
		t.Fatal("connection of u5-n broken: ", err)
	}
	checkTracked(t, h, 1, 1)

	// The removed user can no longer connect.
	if conn, err := connect(addr, p); err == nil {
		conn.Close()
		t.Fatal("removed user connected")
	}
	waitResults(t, results, 1, time.Second)

	n1.Close()
	waitResults(t, results, 1, time.Second)
	checkTracked(t, h, 0, 0)
}

func TestRemoveUserCancelsContext(t *testing.T) {
	u := newUser(t, "u5", "a06fe789-5ab1-480b-8124-ae4599801ff3")
	h := newHandler(newValidator(t, u))
	d := &testDispatcher{hold: true}
	addr, results := serve(t, h, d)

	conn, err := dial(addr, u)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for deadline := time.Now().Add(time.Second); d.dispatched.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("connection not dispatched")
		}
	}
	checkTracked(t, h, 1, 1)

	if err := h.RemoveUser(context.Background(), "u5"); err != nil {
		t.Fatal(err)
	}
	// The dispatcher only returns when the context is cancelled.
	waitResults(t, results, 1, time.Second)
	waitClosed(t, conn, time.Second)
	checkTracked(t, h, 0, 0)
}

func TestRemoveUserWithoutConnectionsAndReAdd(t *testing.T) {
	const id = "a06fe789-5ab1-480b-8124-ae4599801ff3"
	u := newUser(t, "u5", id)
	h := newHandler(newValidator(t, u))
	addr, results := serve(t, h, &testDispatcher{})

	if err := h.RemoveUser(context.Background(), "u5"); err != nil {
		t.Fatal(err)
	}
	checkTracked(t, h, 0, 0)
	if err := h.RemoveUser(context.Background(), "u5"); err == nil {
		t.Fatal("removing a missing user succeeded")
	}
	if conn, err := connect(addr, u); err == nil {
		conn.Close()
		t.Fatal("removed user connected")
	}
	waitResults(t, results, 1, time.Second)

	// Re-add the same email and UUID, as the API does: a new MemoryUser.
	u2 := newUser(t, "u5", id)
	if err := h.AddUser(context.Background(), u2); err != nil {
		t.Fatal(err)
	}
	conn := mustConnect(t, addr, u2)
	checkTracked(t, h, 1, 1)
	if err := h.RemoveUser(context.Background(), "u5"); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, conn, time.Second)
	waitResults(t, results, 1, time.Second)
	checkTracked(t, h, 0, 0)
}

func TestNormalCloseLeavesTrackerEmpty(t *testing.T) {
	u := newUser(t, "u5", "a06fe789-5ab1-480b-8124-ae4599801ff3")
	vision := newUser(t, "u6", "b06fe789-5ab1-480b-8124-ae4599801ff3")
	vision.Account.(*vless.MemoryAccount).Flow = vless.XRV
	h := newHandler(newValidator(t, u, vision))
	addr, results := serve(t, h, &testDispatcher{})

	conns := make([]gonet.Conn, 0, 8)
	for range 8 {
		conns = append(conns, mustConnect(t, addr, u))
	}
	checkTracked(t, h, 1, 8)
	for _, conn := range conns {
		if err := ping(conn); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	waitResults(t, results, 8, time.Second)
	checkTracked(t, h, 0, 0)

	// A connection that Process rejects after tracking it (a Vision user
	// without flow) is forgotten too.
	if conn, err := connect(addr, vision); err == nil {
		conn.Close()
		t.Fatal("Vision user connected without flow")
	}
	if errs := waitResults(t, results, 1, time.Second); !strings.Contains(errs[0].Error(), "flow is empty") {
		t.Fatal("unexpected error: ", errs[0])
	}
	checkTracked(t, h, 0, 0)
}

func TestRemoveUserWhileAuthenticating(t *testing.T) {
	u := newUser(t, "u5", "a06fe789-5ab1-480b-8124-ae4599801ff3")
	v := &removingValidator{Validator: newValidator(t, u)}
	h := newHandler(v)
	v.remove = func() {
		if err := h.RemoveUser(context.Background(), "u5"); err != nil {
			t.Error(err)
		}
	}
	d := &testDispatcher{}
	addr, results := serve(t, h, d)

	if conn, err := connect(addr, u); err == nil {
		conn.Close()
		t.Fatal("connection survived a removal during authentication")
	}
	errs := waitResults(t, results, 1, time.Second)
	if errs[0] == nil || !strings.Contains(errs[0].Error(), "removed while connecting") {
		t.Fatal("unexpected error: ", errs[0])
	}
	if d.dispatched.Load() != 0 {
		t.Fatal("connection was dispatched")
	}
	checkTracked(t, h, 0, 0)
}

func TestRemoveUserRacesWithConnects(t *testing.T) {
	const id = "a06fe789-5ab1-480b-8124-ae4599801ff3"
	h := newHandler(new(vless.MemoryValidator))
	addr, results := serve(t, h, &testDispatcher{})

	for round := range 10 {
		u := newUser(t, "u5", id)
		if err := h.AddUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var dialed, established atomic.Int32
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := gonet.Dial("tcp", addr)
				if err != nil {
					return
				}
				defer conn.Close()
				dialed.Add(1) // the server runs Process for it
				conn.SetDeadline(time.Now().Add(time.Second))
				if err := encoding.EncodeRequestHeader(conn, request(u), &encoding.Addons{}); err != nil {
					return
				}
				if _, err := conn.Write([]byte("ping")); err != nil {
					return
				}
				if _, err := encoding.DecodeResponseHeader(conn, request(u)); err != nil {
					return
				}
				if readPing(conn) != nil {
					return
				}
				established.Add(1)
				for ping(conn) == nil { // keep the stream alive until it is cut
				}
			}()
		}
		time.Sleep(time.Duration(round) * time.Millisecond)
		if err := h.RemoveUser(context.Background(), "u5"); err != nil {
			t.Fatal(err)
		}

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("round ", round, ": a connection survived RemoveUser")
		}
		waitResults(t, results, int(dialed.Load()), time.Second)
		checkTracked(t, h, 0, 0)
		t.Log("round ", round, ": ", established.Load(), " of ", dialed.Load(), " connections were established before the removal")
	}
}
