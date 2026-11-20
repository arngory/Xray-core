package reality

// fork: REALITY borrows the handshake of a target whatever extensions the target sends in its EncryptedExtensions,
// none included (FORK.md, 4).

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/binary"
	"io"
	gonet "net"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestTargetExtensions(t *testing.T) {
	for _, tc := range []struct {
		name string
		// hideName: the target does not see the client's server_name, and acks none
		hideName bool
		alpn     []string
	}{
		{name: "server_name ack", alpn: nil},
		{name: "ALPN", hideName: true, alpn: []string{"h2", "http/1.1"}},
		// as openssl s_server's by default: REALITY's own server_name ack made its extensions 4 bytes longer than
		// the target's, and conn.go failed with "padding: -4"
		{name: "none", hideName: true, alpn: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target := tlsTarget(t, tc.alpn, tc.hideName)

			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			server := (&Config{
				Dest:        target,
				Type:        "tcp",
				ServerNames: []string{"localhost"},
				PrivateKey:  privateKey.Bytes(),
				ShortIds:    [][]byte{shortID},
			}).GetREALITYConfig()
			waitDetected(t, server, "localhost 2") // the client's ALPN begins with h2
			client := &Config{
				Fingerprint: "chrome",
				ServerName:  "localhost",
				PublicKey:   privateKey.PublicKey().Bytes(),
				ShortId:     shortID,
				SpiderX:     "/",
			}

			ln := listen(t)
			serverErr := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				conn, err := Server(c, server)
				serverErr <- err
				if err == nil {
					io.Copy(conn, conn)
				}
			}()

			c, err := gonet.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			conn, err := UClient(c, client, context.Background(), net.TCPDestination(net.LocalHostIP, 443))
			if err != nil {
				select {
				case sErr := <-serverErr:
					t.Fatalf("client: %v; server: %v", err, sErr)
				case <-time.After(5 * time.Second):
					t.Fatalf("client: %v; the server did not finish", err)
				}
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server: %v", err)
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
				t.Fatalf("echo: %q, %v", got, err)
			}
		})
	}
}

func listen(t *testing.T) gonet.Listener {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// waitDetected starts what Xray's listener starts with a REALITY inbound, the probe of the target's records after
// the handshake, and waits until it has measured those of key ("SNI ALPN"): until then Server holds an
// authenticated client.
func waitDetected(t *testing.T, config *goreality.Config, key string) {
	t.Helper()
	goreality.DetectPostHandshakeRecordsLens(config)
	key = config.Dest + " " + key
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if val, ok := goreality.GlobalPostHandshakeRecordsLens.Load(key); ok {
			if _, ok := val.([]int); ok {
				return
			}
		}
	}
	t.Fatal("the probe of the target did not finish")
}

// tlsTarget is a TLS 1.3 server of Go's for REALITY to borrow, with alpn. Go acks the client's server_name; with
// hideName the target is behind a proxy that renames the server_name extension of the ClientHello, so that it acks
// none (the proxy closes a connection whose ClientHello has none to rename).
func tlsTarget(t *testing.T, alpn []string, hideName bool) (addr string) {
	t.Helper()
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	keyPair, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := gotls.NewListener(listen(t), &gotls.Config{
		Certificates: []gotls.Certificate{keyPair},
		MinVersion:   gotls.VersionTLS13,
		NextProtos:   alpn,
	})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	if !hideName {
		return tlsLn.Addr().String()
	}

	proxy := listen(t)
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				header := make([]byte, 5)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(header[3:]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				record := append(header, body...)
				if !renameServerName(record) {
					return
				}
				d, err := gonet.Dial("tcp", tlsLn.Addr().String())
				if err != nil {
					return
				}
				defer d.Close()
				if _, err := d.Write(record); err != nil {
					return
				}
				go io.Copy(d, c)
				io.Copy(c, d)
			}()
		}
	}()
	return proxy.Addr().String()
}

// renameServerName gives the server_name extension of the ClientHello in record (one TLS record) a type nobody
// knows, so that the server ignores it; the lengths stay as they are. False when record has no such extension.
func renameServerName(record []byte) bool {
	p := 5 + 4 + 2 + 32 // record header, handshake header, legacy_version, random
	if len(record) < p || record[0] != 22 || record[5] != 1 {
		return false
	}
	skip := func(lenBytes int) bool { // a vector with a length of lenBytes bytes
		if p+lenBytes > len(record) {
			return false
		}
		n := 0
		for _, b := range record[p : p+lenBytes] {
			n = n<<8 | int(b)
		}
		p += lenBytes + n
		return p <= len(record)
	}
	if !skip(1) || !skip(2) || !skip(1) { // legacy_session_id, cipher_suites, legacy_compression_methods
		return false
	}
	p += 2 // the extensions' length
	for p+4 <= len(record) {
		if record[p] == 0 && record[p+1] == 0 {
			record[p], record[p+1] = 0xde, 0xad
			return true
		}
		p += 2
		if !skip(2) {
			return false
		}
	}
	return false
}
