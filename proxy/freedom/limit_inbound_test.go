package freedom_test

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/app/stats"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The tests here run a whole Xray in the test's process, as raycontrol
// configures its exits: a VLESS inbound, the dispatcher, routing, freedom
// outbounds, the policy of level 0 with or without "limits", and the stats.
// The client is the test: it speaks VLESS, and mux and XUDP in it, itself,
// to see exactly what a client is sent at a limit.

// The users: two credentials of u5 and one of u6, named as raycontrol names
// them.
const (
	u5a = "u5-0123456789abcdef"
	u5b = "u5-fedcba9876543210"
	u6  = "u6-0123456789abcdef"
)

type node struct {
	t     *testing.T
	inst  *core.Instance
	port  net.Port
	api   net.Port
	log   string
	users map[string]*protocol.MemoryUser
	names *nameServer
	// The UUIDs of u5a, u5b and u6, and with reality the client's stream.
	ids    []string
	stream *internet.StreamConfig
}

type nodeConfig struct {
	limits *policy.Policy_Limits
	// level is the level of the error log, kept in a file; none when zero.
	level clog.Severity
	// names: routing resolves the names of destinations, IPOnDemand, at a
	// name server of the test that counts what it is asked.
	names bool
	// api: the StatsService, as rayd reads it.
	api bool
	// reality: the inbound is raycontrol's REALITY one, with the flow
	// xtls-rprx-vision; the test reaches it through an Xray client.
	reality bool
}

func startNode(t *testing.T, c nodeConfig) *node {
	n := &node{t: t, port: tcp.PickPort(), users: map[string]*protocol.MemoryUser{}}
	var users []*protocol.User
	var flow string
	var stream *internet.StreamConfig
	if c.reality {
		flow = vless.XRV
		stream, n.stream = realityStreams(t)
	}
	for _, email := range []string{u5a, u5b, u6} {
		id := protocol.NewID(uuid.New()).String()
		n.ids = append(n.ids, id)
		u := &protocol.User{Email: email, Account: serial.ToTypedMessage(&vless.Account{Id: id, Flow: flow})}
		users = append(users, u)
		mu, err := u.ToMemoryUser()
		if err != nil {
			t.Fatal(err)
		}
		n.users[email] = mu
	}
	logConfig := &log.Config{ErrorLogType: log.LogType_None, AccessLogType: log.LogType_None}
	if c.level != clog.Severity_Unknown {
		n.log = filepath.Join(t.TempDir(), "error.log")
		logConfig = &log.Config{ErrorLogType: log.LogType_File, ErrorLogPath: n.log, ErrorLogLevel: c.level, AccessLogType: log.LogType_None}
	}
	routing := &router.Config{}
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(logConfig),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{Level: map[uint32]*policy.Policy{0: {
				Stats:  &policy.Policy_Stats{UserUplink: true, UserDownlink: true},
				Limits: c.limits,
			}}}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "inner",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(n.port)}},
				Listen:         net.NewIPOrDomain(net.LocalHostIP),
				StreamSettings: stream,
			}),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{Users: users}),
		}},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "direct",
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: &internet.StreamConfig{
					SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP},
				}}),
				// The test's destinations are on loopback, which freedom
				// refuses a VLESS user without a rule.
				ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
			},
			{Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})},
		},
	}
	if c.names {
		n.names = startNameServer(t)
		config.App = append(config.App, serial.ToTypedMessage(&appdns.Config{
			NameServer: []*appdns.NameServer{{Address: &net.Endpoint{
				Network: net.Network_UDP, Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(n.names.port),
			}}},
		}))
		routing.DomainStrategy = router.Config_IpOnDemand
		routing.Rule = append(routing.Rule, &router.RoutingRule{
			Ip: []*geodata.IPRule{{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{
				Cidr: &geodata.CIDR{Ip: []byte{10, 0, 0, 0}, Prefix: 8},
			}}}},
			TargetTag: &router.RoutingRule_Tag{Tag: "block"},
		})
	}
	if c.api {
		n.api = tcp.PickPort()
		config.App = append(config.App, serial.ToTypedMessage(&commander.Config{
			Tag:     "api",
			Service: []*serial.TypedMessage{serial.ToTypedMessage(&statscmd.Config{})},
		}))
		routing.Rule = append(routing.Rule, &router.RoutingRule{
			InboundTag: []string{"api"},
			TargetTag:  &router.RoutingRule_Tag{Tag: "api"},
		})
		config.Inbound = append(config.Inbound, &core.InboundHandlerConfig{
			Tag: "api",
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(n.api)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
				RewritePort:     uint32(n.api),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		})
	}
	config.App = append(config.App, serial.ToTypedMessage(routing))
	inst, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	n.inst = inst
	return n
}

// refused are the refusals of the limits the node's stats count, by
// "user/kind".
func (n *node) refused() map[string]int64 {
	out := map[string]int64{}
	sm := n.inst.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	sm.VisitCounters(func(name string, c featurestats.Counter) bool {
		if user, kind, ok := strings.Cut(strings.TrimPrefix(name, "user>>>"), ">>>limit>>>"); ok {
			out[user+"/"+kind] = c.Value()
		}
		return true
	})
	return out
}

// wantRefused waits for the refusals counted to be these.
func (n *node) wantRefused(want map[string]int64) {
	n.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := fmt.Sprint(n.refused())
		if got == fmt.Sprint(want) {
			return
		}
		if time.Now().After(deadline) {
			n.t.Fatalf("refused %v, want %v", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// request opens a connection to the inbound and sends the VLESS request of
// the user: a command, and its destination.
func (n *node) request(email string, command protocol.RequestCommand, dest net.Destination) (gonet.Conn, *protocol.RequestHeader) {
	n.t.Helper()
	conn, err := gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", n.port))
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { conn.Close() })
	req := &protocol.RequestHeader{Version: encoding.Version, User: n.users[email], Command: command, Address: dest.Address, Port: dest.Port}
	if err := encoding.EncodeRequestHeader(conn, req, &encoding.Addons{}); err != nil {
		n.t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, req
}

// tcpConn is a proxied TCP connection of a user, with what came of it: nil
// when it reached the destination and echoed, or what the client saw.
func (n *node) tcpConn(email string, dest net.Destination) (gonet.Conn, error) {
	n.t.Helper()
	conn, req := n.request(email, protocol.RequestCommandTCP, dest)
	if _, err := conn.Write([]byte("ping")); err != nil {
		return conn, fmt.Errorf("write: %w", err)
	}
	// The response header comes with the first data, or when the server
	// ends the connection.
	if _, err := encoding.DecodeResponseHeader(conn, req); err != nil {
		return conn, fmt.Errorf("closed before the response header: %w", err)
	}
	echo := make([]byte, 4)
	if got, err := io.ReadFull(conn, echo); err != nil {
		return conn, fmt.Errorf("closed after the response header and %d bytes of data: %w", got, err)
	}
	if string(echo) != "ping" {
		n.t.Fatalf("echo %q", echo)
	}
	return conn, nil
}

func (n *node) mustTCP(email string, dest net.Destination) gonet.Conn {
	n.t.Helper()
	conn, err := n.tcpConn(email, dest)
	if err != nil {
		n.t.Fatal(email, ": ", err)
	}
	return conn
}

// mustRefuseTCP is what the client of a refused TCP connection sees, at a
// limit as when the dial fails: the VLESS connection closed with no data.
// (The two bytes of the response header may come first: the server flushes
// them when it closes. The close is a reset when the server had not read
// all the client sent.)
func (n *node) mustRefuseTCP(email string, dest net.Destination) {
	n.t.Helper()
	conn, err := n.tcpConn(email, dest)
	if err == nil {
		n.t.Fatal(email, ": a refused connection reached its destination")
	}
	if !closedWithoutData(err) {
		n.t.Fatal(email, ": refused otherwise than by a close without data: ", err)
	}
	conn.Close()
}

func closedWithoutData(err error) bool {
	if err == nil || strings.Contains(err.Error(), "bytes of data") && !strings.Contains(err.Error(), " 0 bytes of data") {
		return false
	}
	return strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection reset")
}

// udpConn is a proxied UDP session of a user (the VLESS UDP command), with
// what came of it, as tcpConn.
func (n *node) udpConn(email string, dest net.Destination) (gonet.Conn, error) {
	n.t.Helper()
	conn, req := n.request(email, protocol.RequestCommandUDP, dest)
	if _, err := conn.Write([]byte{0, 4, 'p', 'i', 'n', 'g'}); err != nil {
		return conn, fmt.Errorf("write: %w", err)
	}
	if _, err := encoding.DecodeResponseHeader(conn, req); err != nil {
		return conn, fmt.Errorf("closed before the response header: %w", err)
	}
	echo := make([]byte, 6)
	if got, err := io.ReadFull(conn, echo); err != nil {
		return conn, fmt.Errorf("closed after the response header and %d bytes of data: %w", got, err)
	}
	if string(echo[2:]) != "ping" {
		n.t.Fatalf("echo %q", echo)
	}
	return conn, nil
}

// echoTCP is a TCP server that echoes.
func echoTCP(t *testing.T) net.Destination {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return net.DestinationFromAddr(ln.Addr())
}

// echoUDP is a UDP server that echoes.
func echoUDP(t *testing.T) net.Destination {
	conn, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			conn.WriteTo(b[:n], from)
		}
	}()
	return net.DestinationFromAddr(conn.LocalAddr())
}

// nameServer answers every name with 127.0.0.1 and remembers what it was
// asked.
type nameServer struct {
	port  int
	mu    sync.Mutex
	asked map[string]int
}

func startNameServer(t *testing.T) *nameServer {
	conn, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &nameServer{port: conn.LocalAddr().(*gonet.UDPAddr).Port, asked: map[string]int{}}
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			s.mu.Lock()
			s.asked[strings.TrimSuffix(q.Name, ".")]++
			s.mu.Unlock()
			if q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(q.Name + " 600 IN A 127.0.0.1")
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return s
}

func (s *nameServer) askedFor(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked[name] > 0
}

// A user's TCP connections at once, across its credentials; what the
// client of the one past them sees; and the counter, as rayd reads it.
func TestInboundTCPAtOnce(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{Connections: 2, FoldAt: "-"}, api: true})
	dest := echoTCP(t)
	first := n.mustTCP(u5a, dest)
	n.mustTCP(u5b, dest)
	n.mustRefuseTCP(u5a, dest)
	n.mustRefuseTCP(u5b, dest)
	// Another user is not held by it.
	n.mustTCP(u6, dest)
	n.mustTCP(u6, dest)
	n.wantRefused(map[string]int64{"u5/tcp": 2})

	// rayd's poll: QueryStats "user>>>", no reset.
	client, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", n.api), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for range 2 { // reading resets nothing
		resp, err := statscmd.NewStatsServiceClient(client).QueryStats(context.Background(), &statscmd.QueryStatsRequest{Pattern: "user>>>"})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int64{}
		for _, s := range resp.Stat {
			got[s.Name] = s.Value
		}
		if got["user>>>u5>>>limit>>>tcp"] != 2 {
			t.Fatal("StatsService: ", got)
		}
		// The bytes are by credential, as before; the refusals by user.
		if got["user>>>"+u5a+">>>traffic>>>uplink"] == 0 || got["user>>>"+u6+">>>traffic>>>downlink"] == 0 {
			t.Fatal("StatsService: no traffic counters: ", got)
		}
		for name := range got {
			if strings.Contains(name, ">>>limit>>>") && name != "user>>>u5>>>limit>>>tcp" {
				t.Fatal("StatsService: a counter of no refusal: ", name)
			}
		}
	}

	// A connection that ends gives its place back.
	first.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := n.tcpConn(u5a, dest); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the place of a closed connection did not come back")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The token of a new connection is taken before it is routed: one refused
// for want of a token asks the name server nothing, though routing resolves
// names (IPOnDemand).
func TestInboundTokenBeforeRouting(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{Rate: 1, Burst: 2, FoldAt: "-"}, names: true})
	dest := echoTCP(t)
	to := func(name string) net.Destination { return net.TCPDestination(net.DomainAddress(name), dest.Port) }
	n.mustTCP(u5a, to("one.test"))
	n.mustTCP(u5b, to("two.test"))
	if !n.names.askedFor("one.test") || !n.names.askedFor("two.test") {
		t.Fatal("routing did not resolve the names: the test tests nothing")
	}
	// The third within the second has no token, and none comes within the
	// half second it may wait.
	start := time.Now()
	n.mustRefuseTCP(u5a, to("three.test"))
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Error("refused after ", took, ": a token a second away is not waited for")
	}
	n.mustTCP(u6, to("four.test"))
	if n.names.askedFor("three.test") {
		t.Fatal("the name of a connection refused for want of a token was looked up")
	}
	if !n.names.askedFor("four.test") {
		t.Fatal("u6: not looked up")
	}
	n.wantRefused(map[string]int64{"u5/rate": 1})
}

// A connection that waits for its token gets it within half a second.
func TestInboundWaitsForToken(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{Rate: 4, Burst: 1}})
	dest := echoTCP(t)
	n.mustTCP(u5a, dest)
	start := time.Now()
	n.mustTCP(u5a, dest) // a quarter of a second away
	if took := time.Since(start); took < 150*time.Millisecond || took > 2*time.Second {
		t.Error("the second connection took ", took, ", want about 250 ms")
	}
	n.wantRefused(map[string]int64{})
}

// muxClient is a mux connection of a user, spoken by the test.
type muxClient struct {
	t      *testing.T
	conn   gonet.Conn
	req    *protocol.RequestHeader
	r      *bufio.Reader
	header bool
}

func (n *node) mux(email string) *muxClient {
	conn, req := n.request(email, protocol.RequestCommandMux, net.Destination{})
	return &muxClient{t: n.t, conn: conn, req: req, r: bufio.NewReader(conn)}
}

// send writes a frame: a new subconnection to dest when it is valid (XUDP
// with a global ID), data on one otherwise; each UDP frame names its
// destination.
func (m *muxClient) send(id uint16, status mux.SessionStatus, dest net.Destination, globalID [8]byte, data string) {
	m.t.Helper()
	b := buf.New()
	defer b.Release()
	meta := mux.FrameMetadata{SessionID: id, SessionStatus: status, Target: dest, GlobalID: globalID}
	if dest.Network == net.Network_UDP {
		b.UDP = &dest
	}
	if data != "" {
		meta.Option.Set(mux.OptionData)
	}
	if err := meta.WriteTo(b); err != nil {
		m.t.Fatal(err)
	}
	if data != "" {
		b.Write(binary.BigEndian.AppendUint16(nil, uint16(len(data))))
		b.WriteString(data)
	}
	if _, err := m.conn.Write(b.Bytes()); err != nil {
		m.t.Fatal(err)
	}
}

// frame is the next frame of the server's, keep-alives passed over.
func (m *muxClient) frame() (mux.FrameMetadata, string) {
	m.t.Helper()
	if !m.header {
		if _, err := encoding.DecodeResponseHeader(m.r, m.req); err != nil {
			m.t.Fatal("the mux connection: ", err)
		}
		m.header = true
	}
	for {
		var meta mux.FrameMetadata
		if err := meta.Unmarshal(m.r, false); err != nil {
			m.t.Fatal("the mux connection: ", err)
		}
		var data []byte
		if meta.Option.Has(mux.OptionData) {
			var size [2]byte
			if _, err := io.ReadFull(m.r, size[:]); err != nil {
				m.t.Fatal(err)
			}
			data = make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(m.r, data); err != nil {
				m.t.Fatal(err)
			}
		}
		if meta.SessionStatus != mux.SessionStatusKeepAlive {
			return meta, string(data)
		}
	}
}

// echoes: the next frame is data on the subconnection.
func (m *muxClient) echoes(id uint16, want string) {
	m.t.Helper()
	meta, data := m.frame()
	if meta.SessionID != id || meta.SessionStatus != mux.SessionStatusKeep || data != want {
		m.t.Fatalf("subconnection %d: frame of %d, status %d, option %#x, %q; want %q echoed", id, meta.SessionID, meta.SessionStatus, meta.Option, data, want)
	}
}

// endsWithError: the next frame ends the subconnection, with the error bit.
func (m *muxClient) endsWithError(id uint16) {
	m.t.Helper()
	meta, data := m.frame()
	if meta.SessionID != id || meta.SessionStatus != mux.SessionStatusEnd || !meta.Option.Has(mux.OptionError) {
		m.t.Fatalf("subconnection %d: frame of %d, status %d, option %#x, %q; want End with the error bit", id, meta.SessionID, meta.SessionStatus, meta.Option, data)
	}
}

// globalID is the global ID of an XUDP session. The process keeps the
// sessions by it, across the nodes of the tests.
func globalID() (id [8]byte) {
	rand.Read(id[:])
	return id
}

// A mux subconnection past the user's limit ends with End and the error
// bit; the mux and its other subconnections live on.
func TestInboundMuxSubconnectionRefused(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{Connections: 2, FoldAt: "-"}})
	dest := echoTCP(t)
	m := n.mux(u5a)
	none := [8]byte{}
	m.send(1, mux.SessionStatusNew, dest, none, "one")
	m.echoes(1, "one")
	m.send(2, mux.SessionStatusNew, dest, none, "two")
	m.echoes(2, "two")
	m.send(3, mux.SessionStatusNew, dest, none, "three")
	m.endsWithError(3)
	// The others, and the mux, go on.
	m.send(1, mux.SessionStatusKeep, net.Destination{}, none, "more")
	m.echoes(1, "more")
	m.send(2, mux.SessionStatusKeep, net.Destination{}, none, "more")
	m.echoes(2, "more")
	// The limit is the user's, not the connection's: another mux of u5, and
	// a plain connection, have no place either; u6 has.
	o := n.mux(u5b)
	o.send(1, mux.SessionStatusNew, dest, none, "one")
	o.endsWithError(1)
	n.mustRefuseTCP(u5b, dest)
	n.mustTCP(u6, dest)
	n.wantRefused(map[string]int64{"u5/tcp": 3})
}

// UDP sessions: plain ones (the VLESS UDP command) and XUDP ones in a mux
// share the user's limit; a session's packets to more destinations than the
// user may have pairs are dropped, and the session lives.
func TestInboundUDP(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{UdpSessions: 2, UdpLive: 3, FoldAt: "-"}})
	one, two, three, four := echoUDP(t), echoUDP(t), echoUDP(t), echoUDP(t)
	if _, err := n.udpConn(u5a, one); err != nil {
		t.Fatal("the first session: ", err)
	}
	// An XUDP session: each packet names its destination.
	m := n.mux(u5b)
	id := globalID()
	m.send(1, mux.SessionStatusNew, two, id, "to two")
	m.echoes(1, "to two")
	m.send(1, mux.SessionStatusKeep, three, id, "to three")
	m.echoes(1, "to three")
	// The user's fourth pair: dropped, with no answer and no end.
	m.send(1, mux.SessionStatusKeep, four, id, "to four")
	m.send(1, mux.SessionStatusKeep, two, id, "two again")
	m.echoes(1, "two again")
	n.wantRefused(map[string]int64{"u5/live": 1})

	// A third session: none of the two has been quiet for 10 s to give way.
	m.send(2, mux.SessionStatusNew, one, globalID(), "another")
	m.endsWithError(2)
	conn, err := n.udpConn(u5a, one)
	if !closedWithoutData(err) {
		t.Fatal("a third session of u5: ", err)
	}
	conn.Close()
	// The XUDP session lives on, and u6 has its own.
	m.send(1, mux.SessionStatusKeep, three, id, "three again")
	m.echoes(1, "three again")
	if _, err := n.udpConn(u6, one); err != nil {
		t.Fatal("u6: ", err)
	}
	n.wantRefused(map[string]int64{"u5/live": 1, "u5/udp": 2})
}

// ends: the next frame ends the subconnection, without the error bit.
func (m *muxClient) ends(id uint16) {
	m.t.Helper()
	meta, data := m.frame()
	if meta.SessionID != id || meta.SessionStatus != mux.SessionStatusEnd || meta.Option.Has(mux.OptionError) {
		m.t.Fatalf("subconnection %d: frame of %d, status %d, option %#x, %q; want End without the error bit", id, meta.SessionID, meta.SessionStatus, meta.Option, data)
	}
}

// An XUDP session lives detached from its connection, until its idle timer.
// At the user's limit the one quiet for 10 s gives way to a new session: it
// ends with End, as when the timer runs out, and the client's next packet
// opens it anew. (The 10 s are real: the node's clock is not the test's.)
func TestInboundXUDPGivesWay(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 10 s")
	}
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{UdpSessions: 2}})
	dest := echoUDP(t)
	m := n.mux(u5a)
	m.conn.SetDeadline(time.Now().Add(30 * time.Second))
	a, b := globalID(), globalID()
	m.send(1, mux.SessionStatusNew, dest, a, "a")
	m.echoes(1, "a")
	time.Sleep(100 * time.Millisecond) // a is the quieter of the two
	m.send(2, mux.SessionStatusNew, dest, b, "b")
	m.echoes(2, "b")
	// Neither has been quiet for 10 s.
	m.send(3, mux.SessionStatusNew, dest, globalID(), "c")
	m.endsWithError(3)
	n.wantRefused(map[string]int64{"u5-0123456789abcdef/udp": 1})

	time.Sleep(10*time.Second + 200*time.Millisecond)
	m.send(4, mux.SessionStatusNew, dest, globalID(), "d")
	// a gives way, and d has its place; the two frames come in either order.
	ended, echoed := false, false
	for range 2 {
		meta, data := m.frame()
		switch {
		case meta.SessionID == 1 && meta.SessionStatus == mux.SessionStatusEnd && !meta.Option.Has(mux.OptionError):
			ended = true
		case meta.SessionID == 4 && meta.SessionStatus == mux.SessionStatusKeep && data == "d":
			echoed = true
		default:
			t.Fatalf("frame of %d, status %d, option %#x, %q", meta.SessionID, meta.SessionStatus, meta.Option, data)
		}
	}
	if !ended || !echoed {
		t.Fatal("the quiet session ended: ", ended, "; the new one echoed: ", echoed)
	}
	n.wantRefused(map[string]int64{"u5-0123456789abcdef/udp": 1, "u5-0123456789abcdef/evicted": 1})
	// The client's next packet from the socket of a opens its session anew:
	// b, quiet as long, gives way to it.
	m.send(5, mux.SessionStatusNew, dest, a, "a again")
	ended, echoed = false, false
	for range 2 {
		meta, data := m.frame()
		switch {
		case meta.SessionID == 2 && meta.SessionStatus == mux.SessionStatusEnd && !meta.Option.Has(mux.OptionError):
			ended = true
		case meta.SessionID == 5 && meta.SessionStatus == mux.SessionStatusKeep && data == "a again":
			echoed = true
		default:
			t.Fatalf("frame of %d, status %d, option %#x, %q", meta.SessionID, meta.SessionStatus, meta.Option, data)
		}
	}
	if !ended || !echoed {
		t.Fatal("the second quiet session ended: ", ended, "; the session opened anew echoed: ", echoed)
	}
	n.wantRefused(map[string]int64{"u5-0123456789abcdef/udp": 1, "u5-0123456789abcdef/evicted": 2})
}

// A route into the blackhole outbound holds no place: the connections of a
// user that all go there do not keep its others out.
func TestInboundBlockedRouteHoldsNoPlace(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{Connections: 1, UdpSessions: 1}, names: true})
	for range 3 {
		// 10.0.0.0/8 is routed to "block", which holds a UDP session 30 to
		// 90 s and closes a TCP connection.
		udp, _ := n.request(u5a, protocol.RequestCommandUDP, net.UDPDestination(net.ParseAddress("10.1.2.3"), 53))
		udp.Write([]byte{0, 1, 'x'})
		tcp, _ := n.request(u5a, protocol.RequestCommandTCP, net.TCPDestination(net.ParseAddress("10.1.2.3"), 80))
		tcp.Write([]byte("x"))
	}
	time.Sleep(100 * time.Millisecond)
	n.mustTCP(u5a, echoTCP(t))
	if _, err := n.udpConn(u5a, echoUDP(t)); err != nil {
		t.Fatal("a UDP session beside the blackholed ones: ", err)
	}
	n.wantRefused(map[string]int64{})
}

// Without "limits" nothing is limited and nothing is counted.
func TestInboundNoLimits(t *testing.T) {
	for _, c := range []nodeConfig{{}, {limits: &policy.Policy_Limits{}}} {
		n := startNode(t, c)
		tcpDest, udpDest := echoTCP(t), echoUDP(t)
		for range 40 {
			n.mustTCP(u5a, tcpDest)
			if _, err := n.udpConn(u5a, udpDest); err != nil {
				t.Fatal(err)
			}
		}
		m := n.mux(u5b)
		for i := uint16(1); i <= 40; i++ {
			m.send(i, mux.SessionStatusNew, tcpDest, [8]byte{}, "data")
			m.echoes(i, "data")
		}
		n.wantRefused(map[string]int64{})
	}
}

// refusingDialer is the system dialer with a kernel that refuses: TCP
// dials to refuseTCP fail with the errno, and the first packets of every
// UDP socket fail with EPERM.
type refusingDialer struct {
	internet.SystemDialer
	refuseTCP net.Port
	errno     syscall.Errno
	mu        sync.Mutex
	dials     int // of refuseTCP
	refuseUDP int // packets of each socket
}

func (d *refusingDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *internet.SocketConfig) (gonet.Conn, error) {
	if dest.Network == net.Network_TCP && dest.Port == d.refuseTCP {
		d.mu.Lock()
		d.dials++
		d.mu.Unlock()
		return nil, &gonet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", d.errno)}
	}
	conn, err := d.SystemDialer.Dial(ctx, src, dest, sockopt)
	if p, ok := conn.(*net.PacketConnWrapper); ok && err == nil {
		p.PacketConn = &refusingPacketConn{PacketConn: p.PacketConn, left: d.refuseUDP}
	}
	return conn, err
}

type refusingPacketConn struct {
	gonet.PacketConn
	mu   sync.Mutex
	left int
}

func (c *refusingPacketConn) WriteTo(p []byte, addr gonet.Addr) (int, error) {
	c.mu.Lock()
	refuse := c.left > 0
	c.left--
	c.mu.Unlock()
	if refuse {
		return 0, &gonet.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EPERM)}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// What the node's conntrack guard and egress policy do to a socket: a UDP
// packet refused with EPERM is dropped and its session lives, with limits
// and without; a TCP dial refused with ENETUNREACH or EPERM is not dialed
// again, and is not charged to the user's failed dials.
func TestInboundKernelRefusals(t *testing.T) {
	refusing := &refusingDialer{SystemDialer: &internet.DefaultSystemDialer{}, refuseUDP: 2}
	internet.UseAlternativeSystemDialer(refusing)
	defer internet.UseAlternativeSystemDialer(nil)

	for _, limits := range []*policy.Policy_Limits{nil, {UdpSessions: 4, UdpLive: 4, UdpRate: 1, UdpBurst: 4}} {
		n := startNode(t, nodeConfig{limits: limits})
		conn, req := n.request(u5a, protocol.RequestCommandUDP, echoUDP(t))
		for _, packet := range []string{"one", "two", "three"} { // the first two are refused
			conn.Write(append([]byte{0, byte(len(packet))}, packet...))
		}
		if _, err := encoding.DecodeResponseHeader(conn, req); err != nil {
			t.Fatal("limits ", limits != nil, ": the session ended at a packet the kernel refused: ", err)
		}
		echo := make([]byte, 7)
		if _, err := io.ReadFull(conn, echo); err != nil || string(echo[2:]) != "three" {
			t.Fatalf("limits %v: the packet after the refused ones: %q, %v", limits != nil, echo, err)
		}
		n.wantRefused(map[string]int64{})
	}

	refusing.refuseUDP = 0
	refusing.refuseTCP = tcp.PickPort()
	closed := net.TCPDestination(net.LocalHostIP, refusing.refuseTCP)
	for _, c := range []struct {
		errno   syscall.Errno
		limits  bool
		dials   int
		charged bool
	}{
		{syscall.ENETUNREACH, true, 1, false},
		{syscall.EPERM, true, 1, false},
		{syscall.ECONNREFUSED, true, 1, true},
		{syscall.EPERM, false, 5, false}, // upstream: five dials
	} {
		var limits *policy.Policy_Limits
		if c.limits {
			limits = &policy.Policy_Limits{Connections: 16, FailedRate: 1, FailedBurst: 1}
		}
		n := startNode(t, nodeConfig{limits: limits})
		refusing.errno, refusing.dials = c.errno, 0
		for range 2 {
			n.mustRefuseTCP(u5a, closed) // as an unreachable destination: closed, no data
		}
		if refusing.dials != 2*c.dials {
			t.Errorf("%v, limits %v: %d dials of 2 connections, want %d each", c.errno, c.limits, refusing.dials, c.dials)
		}
		// Two failures with a burst of one: in debt, if they were charged.
		dest := echoTCP(t)
		if c.charged {
			n.mustRefuseTCP(u5a, dest)
			n.wantRefused(map[string]int64{"u5-0123456789abcdef/failed": 1})
		} else {
			n.mustTCP(u5a, dest)
			n.wantRefused(map[string]int64{})
		}
	}
}

// realityStreams are the stream settings of a REALITY inbound and of its
// clients. REALITY borrows the handshake of a TLS 1.3 server: a local one.
func realityStreams(t *testing.T) (server, client *internet.StreamConfig) {
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	keyPair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{keyPair}, MinVersion: gotls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	server = &internet.StreamConfig{
		ProtocolName: "tcp",
		SecurityType: serial.GetMessageType(&reality.Config{}),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&reality.Config{
			Dest:        ln.Addr().String(),
			Type:        "tcp",
			ServerNames: []string{"localhost"},
			PrivateKey:  privateKey.Bytes(),
			ShortIds:    [][]byte{shortID},
		})},
	}
	client = &internet.StreamConfig{
		ProtocolName: "tcp",
		SecurityType: serial.GetMessageType(&reality.Config{}),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&reality.Config{
			Fingerprint: "chrome",
			ServerName:  "localhost",
			PublicKey:   privateKey.PublicKey().Bytes(),
			ShortId:     shortID,
			SpiderX:     "/",
		})},
	}
	return server, client
}

// startClient runs an Xray client of the node: a local port for each of
// u5a, u5b and u6 that leads to dest through the node, as that user.
func (n *node) startClient(dest net.Destination) (ports []net.Port) {
	config := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&log.Config{ErrorLogType: log.LogType_None, AccessLogType: log.LogType_None}),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}}
	routing := &router.Config{}
	for i, id := range n.ids {
		tag := fmt.Sprint("user", i)
		port := tcp.PickPort()
		ports = append(ports, port)
		config.Inbound = append(config.Inbound, &core.InboundHandlerConfig{
			Tag: tag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(dest.Address),
				RewritePort:     uint32(dest.Port),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		})
		config.Outbound = append(config.Outbound, &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&outbound.Config{Vnext: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.LocalHostIP),
				Port:    uint32(n.port),
				User:    &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Flow: vless.XRV})},
			}}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: n.stream}),
		})
		routing.Rule = append(routing.Rule, &router.RoutingRule{InboundTag: []string{tag}, TargetTag: &router.RoutingRule_Tag{Tag: tag}})
	}
	config.App = append(config.App, serial.ToTypedMessage(routing))
	inst, err := core.New(config)
	if err != nil {
		n.t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { inst.Close() })
	return ports
}

// What an application behind an Xray client sees on raycontrol's REALITY
// profile (VLESS, xtls-rprx-vision, no mux: a VLESS connection for each of
// the application's): the connection past the user's limit is accepted by
// the client and closed with no data, as one whose destination is
// unreachable.
func TestInboundRealityVision(t *testing.T) {
	n := startNode(t, nodeConfig{limits: &policy.Policy_Limits{Connections: 2, FoldAt: "-"}, reality: true})
	ports := n.startClient(echoTCP(t))
	// app is an application's connection through the client as a user, and
	// what came of it: the echo, or the close.
	app := func(user int) (gonet.Conn, error) {
		conn, err := gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ports[user]))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte("ping")); err != nil {
			return conn, err
		}
		echo := make([]byte, 4)
		if got, err := io.ReadFull(conn, echo); err != nil {
			return conn, fmt.Errorf("closed after %d bytes of data: %w", got, err)
		}
		return conn, nil
	}
	const a, b, other = 0, 1, 2
	for _, user := range []int{a, b} {
		if _, err := app(user); err != nil {
			t.Fatal("connection of u5 within the limit: ", err)
		}
	}
	start := time.Now()
	if _, err := app(a); !closedWithoutData(err) {
		t.Fatal("a third connection of u5: ", err)
	}
	t.Log("the application's connection past the limit was closed after ", time.Since(start))
	if _, err := app(other); err != nil {
		t.Fatal("u6: ", err)
	}
	n.wantRefused(map[string]int64{"u5/tcp": 1})
}

// The log says nothing of the limits at the level raycontrol runs Xray at
// (warning), and at debug neither whose connection was refused nor where
// it went.
func TestInboundLogs(t *testing.T) {
	refuse := func(n *node) {
		dest := echoTCP(t)
		n.mustTCP(u5a, dest)
		n.mustRefuseTCP(u5a, dest) // refused by the dispatcher
		udp := echoUDP(t)
		if _, err := n.udpConn(u5a, udp); err != nil {
			t.Fatal(err)
		}
		if _, err := n.udpConn(u5a, udp); err == nil { // refused in freedom
			t.Fatal("a second UDP session")
		}
		n.wantRefused(map[string]int64{"u5/tcp": 1, "u5/udp": 1})
	}
	// said waits for the log to have so many lines of the refusals.
	said := func(n *node, lines int) []string {
		deadline := time.Now().Add(2 * time.Second)
		for {
			var got []string
			b, _ := os.ReadFile(n.log)
			for _, line := range strings.Split(string(b), "\n") {
				if s := strings.ToLower(line); strings.Contains(s, "too many") || strings.Contains(s, "limit") {
					got = append(got, line)
				}
			}
			if len(got) >= lines || time.Now().After(deadline) {
				return got
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	limits := &policy.Policy_Limits{Connections: 1, UdpSessions: 1, FoldAt: "-"}

	n := startNode(t, nodeConfig{limits: limits, level: clog.Severity_Warning})
	refuse(n)
	if got := said(n, 1); len(got) != 0 {
		t.Fatalf("the log at warning: %q", got)
	}

	n = startNode(t, nodeConfig{limits: limits, level: clog.Severity_Debug})
	refuse(n)
	// The dispatcher's line at debug, and the outbound handler's at info.
	got := said(n, 2)
	if len(got) < 2 {
		t.Fatalf("the log at debug says nothing of the refusals: %q", got)
	}
	for _, line := range got {
		if strings.Contains(line, "u5") != strings.Contains(line, "create new counter") || strings.Contains(line, "127.0.0.1") {
			t.Error("the log says who or where: ", line)
		}
	}
}
