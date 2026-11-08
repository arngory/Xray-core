package inbound

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// userConn is a live connection of an authenticated user.
type userConn struct {
	conn   net.Conn           // raw transport connection, see proxy.UnwrapRawConn
	cancel context.CancelFunc // cancels the context the connection is processed with
}

// userConns tracks the live connections of each authenticated user, so that
// RemoveUser can close them. It is keyed by the *protocol.MemoryUser the
// validator returned, so a user re-added under the same email is a new key.
// It is touched once when a connection is authenticated and once when it ends,
// never on the data path.
type userConns struct {
	mu sync.Mutex
	m  map[*protocol.MemoryUser]map[*userConn]struct{}
}

func (t *userConns) add(u *protocol.MemoryUser, c *userConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = make(map[*protocol.MemoryUser]map[*userConn]struct{})
	}
	s := t.m[u]
	if s == nil {
		s = make(map[*userConn]struct{}, 1)
		t.m[u] = s
	}
	s[c] = struct{}{}
}

func (t *userConns) remove(u *protocol.MemoryUser, c *userConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.m[u]; s != nil {
		delete(s, c)
		if len(s) == 0 {
			delete(t.m, u)
		}
	}
}

// closeAll closes every tracked connection of u, forgets them and returns how
// many there were. Closing the raw connection fails every read and write on
// it, including a Vision splice that writes to it; cancelling the context ends
// the dispatch (outbound task.Run, mux worker), which closes the outbound
// connection and so also ends a splice that is waiting to read from it.
func (t *userConns) closeAll(u *protocol.MemoryUser) int {
	t.mu.Lock()
	s := t.m[u]
	delete(t.m, u)
	t.mu.Unlock()
	for c := range s {
		c.cancel()
		c.conn.Close()
	}
	return len(s)
}
