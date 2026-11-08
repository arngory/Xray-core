package scenarios

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The tests below remove a user through HandlerService while it has a
// long-lived stream. The stream must end at the client and at the destination;
// another user's stream must go on.

// TestVlessRemoveUserEndsVisionSplice: VLESS TLS + Vision with a TLS 1.3
// stream inside, which the server forwards with splice.
func TestVlessRemoveUserEndsVisionSplice(t *testing.T) {
	testVlessRemoveUser(t, removeUserCase{security: "tls", vision: true})
}

// TestVlessRemoveUserEndsMux: mux, no flow or security.
func TestVlessRemoveUserEndsMux(t *testing.T) {
	testVlessRemoveUser(t, removeUserCase{mux: true})
}

// TestVlessRemoveUserEndsEncryptedVision: VLESS TLS + Vision with native
// VLESS encryption.
func TestVlessRemoveUserEndsEncryptedVision(t *testing.T) {
	testVlessRemoveUser(t, removeUserCase{security: "tls", vision: true, encryption: true})
}

// TestVlessRemoveUserEndsEncryptedVisionReality: REALITY + Vision with native
// VLESS encryption, the REALITY inbound of raycontrol. REALITY borrows the
// handshake of a local TLS server.
func TestVlessRemoveUserEndsEncryptedVisionReality(t *testing.T) {
	testVlessRemoveUser(t, removeUserCase{security: "reality", vision: true, encryption: true})
}

// TestVlessRemoveUserEndsEncryptedUnix: native VLESS encryption on a unix
// socket behind a TCP forwarder, no flow or security: the inner inbound of
// raycontrol behind its front.
func TestVlessRemoveUserEndsEncryptedUnix(t *testing.T) {
	testVlessRemoveUser(t, removeUserCase{unix: true, encryption: true})
}

type removeUserCase struct {
	security   string // "", "tls" or "reality"
	vision     bool   // flow xtls-rprx-vision, with a TLS 1.3 stream inside
	encryption bool   // VLESS encryption, mlkem768x25519plus.native
	mux        bool
	unix       bool // the server listens on a unix socket
}

func testVlessRemoveUser(t *testing.T, c removeUserCase) {
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	keyPair, err := gotls.X509KeyPair(certPEM, keyPEM)
	common.Must(err)
	tlsConfig := &gotls.Config{Certificates: []gotls.Certificate{keyPair}, MinVersion: gotls.VersionTLS13}

	var destTLS *gotls.Config
	if c.vision { // Vision only takes over TLS 1.3
		destTLS = tlsConfig
	}
	destP := startStreamServer(t, destTLS)
	destN := startStreamServer(t, destTLS)

	var flow string
	if c.vision {
		flow = vless.XRV
	}
	var mux *proxyman.MultiplexingConfig
	if c.mux {
		mux = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 8}
	}

	var serverStream, clientStream *internet.StreamConfig
	switch c.security {
	case "tls":
		serverStream = &internet.StreamConfig{
			ProtocolName: "tcp",
			SecurityType: serial.GetMessageType(&tls.Config{}),
			SecuritySettings: []*serial.TypedMessage{
				serial.ToTypedMessage(&tls.Config{
					Certificate: []*tls.Certificate{tls.ParseCertificate(ct)},
				}),
			},
		}
		clientStream = &internet.StreamConfig{
			ProtocolName: "tcp",
			TransportSettings: []*internet.TransportConfig{
				{
					ProtocolName: "tcp",
					Settings:     serial.ToTypedMessage(&transtcp.Config{}),
				},
			},
			SecurityType: serial.GetMessageType(&tls.Config{}),
			SecuritySettings: []*serial.TypedMessage{
				serial.ToTypedMessage(&tls.Config{
					PinnedPeerCertSha256: [][]byte{ctHash[:]},
				}),
			},
		}
	case "reality":
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		common.Must(err)
		shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		serverStream = &internet.StreamConfig{
			ProtocolName: "tcp",
			SecurityType: serial.GetMessageType(&reality.Config{}),
			SecuritySettings: []*serial.TypedMessage{
				serial.ToTypedMessage(&reality.Config{
					Dest:        startTLSServer(t, tlsConfig),
					Type:        "tcp",
					ServerNames: []string{"localhost"},
					PrivateKey:  privateKey.Bytes(),
					ShortIds:    [][]byte{shortID},
				}),
			},
		}
		clientStream = &internet.StreamConfig{
			ProtocolName: "tcp",
			TransportSettings: []*internet.TransportConfig{
				{
					ProtocolName: "tcp",
					Settings:     serial.ToTypedMessage(&transtcp.Config{}),
				},
			},
			SecurityType: serial.GetMessageType(&reality.Config{}),
			SecuritySettings: []*serial.TypedMessage{
				serial.ToTypedMessage(&reality.Config{
					Fingerprint: "chrome",
					ServerName:  "localhost",
					PublicKey:   privateKey.PublicKey().Bytes(),
					ShortId:     shortID,
					SpiderX:     "/",
				}),
			},
		}
	}

	// "mlkem768x25519plus.native.600s.<seed>" on the server and
	// "mlkem768x25519plus.native.0rtt.<public key>" on the client, as
	// infra/conf parses them.
	var decryption, encryption string
	var secondsFrom int64
	var seconds uint32
	if c.encryption {
		seed := make([]byte, mlkem.SeedSize)
		common.Must2(rand.Read(seed))
		key, err := mlkem.NewDecapsulationKey768(seed)
		common.Must(err)
		decryption = base64.RawURLEncoding.EncodeToString(seed)
		encryption = base64.RawURLEncoding.EncodeToString(key.EncapsulationKey().Bytes())
		secondsFrom, seconds = 600, 1
	}

	idP := protocol.NewID(uuid.New()).String()
	idN := protocol.NewID(uuid.New()).String()
	logPath := filepath.Join(t.TempDir(), "server.log")

	cmdPort := tcp.PickPort()
	serverPort := tcp.PickPort()
	receiver := &proxyman.ReceiverConfig{
		PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
		Listen:         net.NewIPOrDomain(net.LocalHostIP),
		StreamSettings: serverStream,
	}
	if c.unix {
		socket := filepath.Join(t.TempDir(), "inner.sock")
		receiver = &proxyman.ReceiverConfig{Listen: net.NewIPOrDomain(net.DomainAddress(socket))}
		serverPort = startForwarder(t, socket)
	}
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_File,
				ErrorLogPath:  logPath,
			}),
			serial.ToTypedMessage(&commander.Config{
				Tag: "api",
				Service: []*serial.TypedMessage{
					serial.ToTypedMessage(&command.Config{}),
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						InboundTag: []string{"api"},
						TargetTag:  &router.RoutingRule_Tag{Tag: "api"},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag:              "vless",
				ReceiverSettings: serial.ToTypedMessage(receiver),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Decryption:  decryption,
					SecondsFrom: secondsFrom,
					Users: []*protocol.User{
						{
							Email:   "u5-p",
							Account: serial.ToTypedMessage(&vless.Account{Id: idP, Flow: flow}),
						},
						{
							Email:   "u5-n",
							Account: serial.ToTypedMessage(&vless.Account{Id: idN, Flow: flow}),
						},
					},
				}),
			},
			{
				Tag: "api",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(cmdPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
					RewritePort:     uint32(cmdPort),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	clientPortP := tcp.PickPort()
	clientPortN := tcp.PickPort()
	clientInbound := func(tag string, port, dest net.Port) *core.InboundHandlerConfig {
		return &core.InboundHandlerConfig{
			Tag: tag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(net.LocalHostIP),
				RewritePort:     uint32(dest),
				AllowedNetworks: []net.Network{net.Network_TCP},
			}),
		}
	}
	clientOutbound := func(tag, id string) *core.OutboundHandlerConfig {
		return &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(serverPort),
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         id,
							Flow:       flow,
							Encryption: encryption,
							Seconds:    seconds,
						}),
					},
				},
			}),
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings:    clientStream,
				MultiplexSettings: mux,
			}),
		}
	}
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			// Without this the client waits up to UplinkOnly (1 s by default)
			// after the server's FIN before it closes the stream, which would
			// hide how fast the server cut it.
			serial.ToTypedMessage(&policy.Config{
				Level: map[uint32]*policy.Policy{
					0: {
						Timeout: &policy.Policy_Timeout{
							UplinkOnly:   &policy.Second{Value: 0},
							DownlinkOnly: &policy.Second{Value: 0},
						},
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{InboundTag: []string{"p"}, TargetTag: &router.RoutingRule_Tag{Tag: "p"}},
					{InboundTag: []string{"n"}, TargetTag: &router.RoutingRule_Tag{Tag: "n"}},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			clientInbound("p", clientPortP, destP.port),
			clientInbound("n", clientPortN, destN.port),
		},
		Outbound: []*core.OutboundHandlerConfig{
			clientOutbound("p", idP),
			clientOutbound("n", idN),
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	streamP := openStream(t, clientPortP, c.vision)
	streamN := openStream(t, clientPortN, c.vision)
	for _, s := range []gonet.Conn{streamP, streamN} {
		if err := readAtLeast(s, 1<<20); err != nil {
			t.Fatal("stream does not flow: ", err)
		}
	}
	if c.vision {
		waitLog(t, logPath, "XtlsFilterTls found tls 1.3")
	}
	if c.vision && !c.encryption { // VLESS encryption disables splice
		waitLog(t, logPath, "CopyRawConn splice")
	}

	cmdConn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", cmdPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	common.Must(err)
	defer cmdConn.Close()
	start := time.Now()
	_, err = command.NewHandlerServiceClient(cmdConn).AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag:       "vless",
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: "u5-p"}),
	})
	common.Must(err)

	// The stream of u5-p ends at the client...
	if err := readUntilClosed(streamP, 5*time.Second); err != nil {
		t.Fatal("u5-p: ", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Error("u5-p: stream ended ", d, " after RemoveUser")
	} else {
		t.Log("u5-p: stream ended ", d, " after RemoveUser")
	}
	// ...and at the destination: the server dropped its outbound connection.
	select {
	case end := <-destP.ended:
		if d := end.Sub(start); d > time.Second {
			t.Error("u5-p: destination connection closed ", d, " after RemoveUser")
		} else {
			t.Log("u5-p: destination connection closed ", d, " after RemoveUser")
		}
	case <-time.After(time.Second):
		t.Fatal("u5-p: destination connection still open")
	}
	waitLog(t, logPath, "closed 1 connection(s) of removed user u5-p")

	// The stream of u5-n goes on.
	if err := readAtLeast(streamN, 1<<20); err != nil {
		t.Fatal("u5-n: stream broken: ", err)
	}
	select {
	case <-destN.ended:
		t.Fatal("u5-n: destination connection closed")
	default:
	}
}

// streamServer streams data to every connection, over TLS if configured, until
// the connection is closed. ended receives the time each connection closed.
type streamServer struct {
	port  net.Port
	ended chan time.Time
}

func startStreamServer(t *testing.T, config *gotls.Config) *streamServer {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	t.Cleanup(func() { ln.Close() })
	s := &streamServer{
		port:  net.Port(ln.Addr().(*gonet.TCPAddr).Port),
		ended: make(chan time.Time, 16),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if config != nil {
				conn = gotls.Server(conn, config)
			}
			go func() {
				defer conn.Close()
				go func() {
					chunk := make([]byte, 16*1024)
					for {
						if _, err := conn.Write(chunk); err != nil {
							return
						}
						time.Sleep(time.Millisecond)
					}
				}()
				io.Copy(io.Discard, conn) // returns once the proxy closes the connection
				s.ended <- time.Now()
			}()
		}
	}()
	return s
}

// startTLSServer runs a TLS server that completes handshakes and reads until
// the peer closes, and returns its address.
func startTLSServer(t *testing.T, config *gotls.Config) string {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if c := gotls.Server(conn, config); c.Handshake() == nil {
					io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startForwarder forwards a local TCP port to the unix socket at path, closing
// both sides when either side ends, and returns the port.
func startForwarder(t *testing.T, path string) net.Port {
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				unix, err := gonet.Dial("unix", path)
				if err != nil {
					return
				}
				defer unix.Close()
				done := make(chan struct{}, 2)
				go func() { io.Copy(unix, conn); done <- struct{}{} }()
				go func() { io.Copy(conn, unix); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return net.Port(ln.Addr().(*gonet.TCPAddr).Port)
}

func openStream(t *testing.T, port net.Port, useTLS bool) gonet.Conn {
	conn, err := gonet.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	common.Must(err)
	if useTLS {
		conn = gotls.Client(conn, &gotls.Config{InsecureSkipVerify: true, MinVersion: gotls.VersionTLS13})
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readAtLeast(conn gonet.Conn, n int64) error {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	_, err := io.CopyN(io.Discard, conn, n)
	return err
}

// readUntilClosed reads until the connection is closed or timeout passes.
func readUntilClosed(conn gonet.Conn, timeout time.Duration) error {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, err := io.Copy(io.Discard, conn)
	if ne, ok := err.(gonet.Error); ok && ne.Timeout() {
		return fmt.Errorf("still open after %v", timeout)
	}
	return nil
}

// waitLog waits until the log file at path contains s.
func waitLog(t *testing.T, path, s string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), s) {
			return
		}
	}
	t.Fatal("server log has no ", fmt.Sprintf("%q", s))
}
