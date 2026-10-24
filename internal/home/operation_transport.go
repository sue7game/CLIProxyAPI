package home

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
)

// Cancel the socket directly: Redis pool shutdown can wait on an active read
// while checking connection health, before it reaches the underlying Close.
func contextBoundRedisDialer(ctx context.Context, dialer func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(dialCtx context.Context, network, address string) (net.Conn, error) {
		conn, errDial := dialer(dialCtx, network, address)
		if errDial != nil {
			return nil, errDial
		}
		return newContextBoundConn(ctx, conn), nil
	}
}

type contextBoundConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func newContextBoundConn(ctx context.Context, conn net.Conn) net.Conn {
	wrapped := &contextBoundConn{Conn: conn, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = closeUnderlyingTransport(conn)
		case <-wrapped.done:
		}
	}()
	return wrapped
}

func (c *contextBoundConn) Close() error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func closeUnderlyingTransport(conn net.Conn) error {
	if conn == nil {
		return net.ErrClosed
	}
	current := conn
	for {
		if dispatchConn, ok := current.(*homeDispatchConn); ok {
			dispatchConn.untrack()
			if next := dispatchConn.NetConn(); next != nil && next != current {
				current = next
				continue
			}
		}
		if tlsConn, ok := current.(*tls.Conn); ok {
			if netConn := tlsConn.NetConn(); netConn != nil && netConn != current {
				current = netConn
				continue
			}
		}
		type unwrapper interface {
			NetConn() net.Conn
		}
		if u, ok := current.(unwrapper); ok {
			if next := u.NetConn(); next != nil && next != current {
				current = next
				continue
			}
		}
		break
	}
	return current.Close()
}
