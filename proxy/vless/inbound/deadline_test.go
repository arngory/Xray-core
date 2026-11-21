package inbound

// fork: the handshake's deadline covers VLESS Encryption's handshake (FORK.md, 5).

import (
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/policy"
)

// shortHandshake is the default policy with a short handshake timeout.
type shortHandshake struct {
	policy.DefaultManager
	timeout time.Duration
}

func (m shortHandshake) ForLevel(level uint32) policy.Session {
	s := m.DefaultManager.ForLevel(level)
	s.Timeouts.Handshake = m.timeout
	return s
}

// TestEncryptionHandshakeDeadline: a client that gets through the transport's
// security and then sends nothing, not even VLESS Encryption's handshake, is
// dropped at the handshake's deadline.
func TestEncryptionHandshakeDeadline(t *testing.T) {
	const timeout = 300 * time.Millisecond
	for _, tr := range testTransports(t) {
		t.Run(tr.name, func(t *testing.T) {
			h := newHandler(newValidator(t, newUser(t, "u5", "a06fe789-5ab1-480b-8124-ae4599801ff3")))
			h.policyManager = shortHandshake{timeout: timeout}
			h.decryption, _ = newEncryption(t, 0)
			ln := tr.listen(t)
			results := serveOn(t, h, &testDispatcher{}, ln, tr.server)

			raw, err := gonet.Dial(ln.Addr().Network(), ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			conn := raw
			if tr.client != nil {
				if conn, err = tr.client(raw); err != nil {
					t.Fatal(err)
				}
			}
			defer conn.Close()
			start := time.Now()
			errs := waitResults(t, results, 1, 10*timeout+5*time.Second)
			if errs[0] == nil {
				t.Fatal("Process returned no error")
			}
			t.Log("dropped after ", time.Since(start), ": ", errs[0])
		})
	}
}
