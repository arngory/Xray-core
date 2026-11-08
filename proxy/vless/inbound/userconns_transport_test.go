package inbound

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	gotls "crypto/tls"
	"fmt"
	"io"
	gonet "net"
	"path/filepath"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// testTransport is how a VLESS connection reaches the inbound.
type testTransport struct {
	name   string
	listen func(t *testing.T) gonet.Listener
	server func(gonet.Conn) (gonet.Conn, error) // server side of the security, nil for none
	client func(gonet.Conn) (gonet.Conn, error) // client side of the security, nil for none
	raw    string                               // type of the connection RemoveUser must close
}

func testTransports(t *testing.T) []testTransport {
	listenTCP := func(t *testing.T) gonet.Listener {
		ln, err := gonet.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	// The inbound worker gets unix connections through this wrapper.
	listenUnix := func(t *testing.T) gonet.Listener {
		ln, err := gonet.Listen("unix", filepath.Join(t.TempDir(), "inner.sock"))
		if err != nil {
			t.Fatal(err)
		}
		return &internet.UnixListenerWrapper{UnixListener: ln.(*gonet.UnixListener)}
	}

	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	keyPair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &gotls.Config{Certificates: []gotls.Certificate{keyPair}, MinVersion: gotls.VersionTLS13}

	// REALITY borrows the handshake of a real TLS 1.3 server: a local one.
	dest := startTLSServer(t, tlsConfig)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	realityServer := (&reality.Config{
		Dest:        dest,
		Type:        "tcp",
		ServerNames: []string{"localhost"},
		PrivateKey:  privateKey.Bytes(),
		ShortIds:    [][]byte{shortID},
	}).GetREALITYConfig()
	goreality.DetectPostHandshakeRecordsLens(realityServer) // as the listener does
	realityClient := &reality.Config{
		ServerName:  "localhost",
		Fingerprint: "chrome",
		PublicKey:   privateKey.PublicKey().Bytes(),
		ShortId:     shortID,
	}

	return []testTransport{
		{name: "tcp", listen: listenTCP, raw: "*net.TCPConn"},
		{name: "unix", listen: listenUnix, raw: "*net.UnixConn"},
		{
			name:   "tls",
			listen: listenTCP,
			server: func(c gonet.Conn) (gonet.Conn, error) { return tls.Server(c, tlsConfig), nil },
			client: func(c gonet.Conn) (gonet.Conn, error) {
				return gotls.Client(c, &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true}), nil
			},
			raw: "*net.TCPConn",
		},
		{
			name:   "reality",
			listen: listenTCP,
			server: func(c gonet.Conn) (gonet.Conn, error) { return reality.Server(c, realityServer) },
			client: func(c gonet.Conn) (gonet.Conn, error) {
				addr := c.RemoteAddr().(*gonet.TCPAddr)
				return reality.UClient(c, realityClient, context.Background(), net.TCPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)))
			},
			raw: "*net.TCPConn",
		},
	}
}

// startTLSServer runs a TLS server that completes handshakes and reads until
// the peer closes, and returns its address.
func startTLSServer(t *testing.T, config *gotls.Config) string {
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
				if c := gotls.Server(conn, config); c.Handshake() == nil {
					io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// encryptionModes are the VLESS encryption modes; raycontrol uses native.
var encryptionModes = []struct {
	name    string
	xorMode uint32
}{{"native", 0}, {"xorpub", 1}, {"random", 2}}

// newEncryption returns both sides of VLESS encryption, as configured by the
// strings `xray vlessenc` prints: the server's
// "mlkem768x25519plus.<mode>.600s.<seed>" and the client's
// "mlkem768x25519plus.<mode>.0rtt.<public key>".
func newEncryption(t *testing.T, xorMode uint32) (*encryption.ServerInstance, *encryption.ClientInstance) {
	seed := make([]byte, mlkem.SeedSize)
	rand.Read(seed)
	key, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatal(err)
	}
	server := &encryption.ServerInstance{}
	if err := server.Init([][]byte{seed}, xorMode, 600, 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	client := &encryption.ClientInstance{}
	if err := client.Init([][]byte{key.EncapsulationKey().Bytes()}, xorMode, 1, ""); err != nil {
		t.Fatal(err)
	}
	return server, client
}

// dialer dials ln through the client side of tr and of the encryption.
// A positive readBuffer sets the client's socket receive buffer.
func (tr testTransport) dialer(ln gonet.Listener, enc *encryption.ClientInstance, readBuffer int) dialFunc {
	return func() (gonet.Conn, error) {
		raw, err := gonet.Dial(ln.Addr().Network(), ln.Addr().String())
		if err != nil {
			return nil, err
		}
		if readBuffer > 0 {
			raw.(interface{ SetReadBuffer(int) error }).SetReadBuffer(readBuffer)
		}
		conn := raw
		if tr.client != nil {
			if conn, err = tr.client(raw); err != nil {
				raw.Close()
				return nil, err
			}
		}
		if enc != nil {
			if conn, err = enc.Handshake(conn); err != nil {
				raw.Close()
				return nil, err
			}
		}
		return conn, nil
	}
}

func checkTrackedRaw(t *testing.T, h *Handler, want string) {
	t.Helper()
	h.conns.mu.Lock()
	defer h.conns.mu.Unlock()
	for _, s := range h.conns.m {
		for uc := range s {
			if got := fmt.Sprintf("%T", uc.conn); got != want {
				t.Fatal("tracked connection is a ", got, ", want ", want)
			}
		}
	}
}

func TestRemoveUserClosesEncryptedConnections(t *testing.T) {
	for _, tr := range testTransports(t) {
		for _, mode := range encryptionModes {
			t.Run(tr.name+"/"+mode.name, func(t *testing.T) {
				p := newUser(t, "u5-p", "a06fe789-5ab1-480b-8124-ae4599801ff3")
				n := newUser(t, "u5-n", "b06fe789-5ab1-480b-8124-ae4599801ff3")
				h := newHandler(newValidator(t, p, n))
				var client *encryption.ClientInstance
				h.decryption, client = newEncryption(t, mode.xorMode)
				ln := tr.listen(t)
				results := serveOn(t, h, &testDispatcher{}, ln, tr.server)
				dial := tr.dialer(ln, client, 0)

				p1 := mustConnectWith(t, dial, p) // 1-RTT
				p2 := mustConnectWith(t, dial, p) // 0-RTT
				n1 := mustConnectWith(t, dial, n)
				checkTracked(t, h, 2, 3)
				checkTrackedRaw(t, h, tr.raw)

				start := time.Now()
				if err := h.RemoveUser(context.Background(), "u5-p"); err != nil {
					t.Fatal(err)
				}
				waitClosed(t, p1, time.Second)
				waitClosed(t, p2, time.Second)
				waitResults(t, results, 2, time.Second)
				t.Log("connections of u5-p ended ", time.Since(start), " after RemoveUser")

				if err := ping(n1); err != nil {
					t.Fatal("connection of u5-n broken: ", err)
				}
				n1.Close()
				waitResults(t, results, 1, time.Second)
				checkTracked(t, h, 0, 0)
			})
		}
	}
}

// TestRemoveUserDoesNotWaitForStalledClient removes a user whose client stopped
// reading, so the server's send buffer is full. Closing the TLS or REALITY
// connection would try to send close_notify into that buffer, for up to 5 s
// over REALITY; RemoveUser must not wait for that.
func TestRemoveUserDoesNotWaitForStalledClient(t *testing.T) {
	for _, tr := range testTransports(t) {
		t.Run(tr.name+"/native", func(t *testing.T) {
			u := newUser(t, "u5", "a06fe789-5ab1-480b-8124-ae4599801ff3")
			h := newHandler(newValidator(t, u))
			var client *encryption.ClientInstance
			h.decryption, client = newEncryption(t, 0)
			d := &testDispatcher{stall: true, stalled: make(chan struct{})}
			ln := tr.listen(t)
			results := serveOn(t, h, d, ln, func(c gonet.Conn) (gonet.Conn, error) {
				c.(interface{ SetWriteBuffer(int) error }).SetWriteBuffer(64 << 10)
				if tr.server == nil {
					return c, nil
				}
				return tr.server(c)
			})

			conn, err := dialWith(tr.dialer(ln, client, 64<<10), u) // never reads
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			select {
			case <-d.stalled:
			case <-time.After(10 * time.Second):
				t.Fatal("the send buffer did not fill up")
			}

			start := time.Now()
			if err := h.RemoveUser(context.Background(), "u5"); err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 100*time.Millisecond {
				t.Fatal("RemoveUser took ", took)
			} else {
				t.Log("RemoveUser took ", took)
			}
			waitResults(t, results, 1, time.Second)
			checkTracked(t, h, 0, 0)
		})
	}
}
