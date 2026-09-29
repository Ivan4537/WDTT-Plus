package main

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Pion owns allocation transactions, but Client.Close does not close the
// caller-supplied network socket. Keep the two lifetimes together, including
// TCP/TLS and MASQUE streams, so retrying a worker cannot leak a reader/socket.
type ownedTURNAllocation struct {
	net.PacketConn
	transport   net.PacketConn
	closeClient func()
	deletion    *turnDeletionTransport
	once        sync.Once
	err         error
}

func (c *ownedTURNAllocation) Close() error {
	c.once.Do(func() {
		// Send allocation deletion while its transport is still available.
		if c.deletion != nil {
			c.deletion.closing.Store(true)
		}
		c.err = c.PacketConn.Close()
		if c.deletion != nil && c.err == nil {
			c.deletion.wait(750 * time.Millisecond)
		}
		c.closeClient()
		if err := c.transport.Close(); c.err == nil {
			c.err = err
		}
	})
	return c.err
}

// Keep the socket and Pion retransmission timer alive for the zero-lifetime
// Refresh response. Closing them immediately after sending one UDP datagram
// can leave the remote allocation occupied until its ordinary expiry.
// Only teardown inspects STUN; normal traffic takes a single atomic branch.
type turnDeletionTransport struct {
	net.PacketConn
	closing     atomic.Bool
	mu          sync.Mutex
	transaction [12]byte
	pending     bool
	ack         chan struct{}
	once        sync.Once
}

func deletionTransaction(p []byte, kind uint16) ([12]byte, bool) {
	var id [12]byte
	if len(p) < 20 || binary.BigEndian.Uint16(p[:2]) != kind || binary.BigEndian.Uint32(p[4:8]) != 0x2112a442 {
		return id, false
	}
	n := 20 + int(binary.BigEndian.Uint16(p[2:4]))
	if n != len(p) {
		return id, false
	}
	for at := 20; at+4 <= n; {
		attr, size := binary.BigEndian.Uint16(p[at:at+2]), int(binary.BigEndian.Uint16(p[at+2:at+4]))
		at += 4
		if at+size > n {
			return id, false
		}
		if attr == 0x000d && size == 4 && binary.BigEndian.Uint32(p[at:at+4]) == 0 {
			copy(id[:], p[8:20])
			return id, true
		}
		at += (size + 3) &^ 3
	}
	return id, false
}

func (c *turnDeletionTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closing.Load() {
		if id, ok := deletionTransaction(p, 0x0004); ok {
			c.mu.Lock()
			c.transaction = id
			c.pending = true
			c.mu.Unlock()
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}
func (c *turnDeletionTransport) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if c.closing.Load() && n > 0 {
		if id, ok := deletionTransaction(p[:n], 0x0104); ok {
			c.mu.Lock()
			match := c.pending && c.transaction == id
			c.mu.Unlock()
			if match {
				c.once.Do(func() { close(c.ack) })
			}
		}
	}
	return n, addr, err
}
func (c *turnDeletionTransport) wait(timeout time.Duration) {
	c.mu.Lock()
	pending := c.pending
	c.mu.Unlock()
	if !pending {
		return
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-c.ack:
	case <-t.C:
	}
}
