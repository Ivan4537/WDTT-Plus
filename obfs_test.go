package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- helpers -----------------------------------------------------------------

func testKey(t testing.TB, password string) []byte {
	t.Helper()
	k, err := deriveWrapKey(password)
	if err != nil {
		t.Fatalf("deriveWrapKey: %v", err)
	}
	return k
}

func randPayload(t testing.TB, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	if _, err := rand.Read(p); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return p
}

// --- nonce -------------------------------------------------------------------

// The stack-based nonce builder must produce bytes identical to the legacy
// allocating one — the nonce is part of the AEAD contract, any drift breaks
// Poly1305 auth against the iOS WRAP-A client.
func TestObfsBuildNonceEquiv(t *testing.T) {
	cases := []struct {
		ssrc uint32
		seq  uint16
		ts   uint32
	}{
		{0, 0, 0},
		{0xDEADBEEF, 0x1234, 0xCAFEBABE},
		{1, 65535, 0xFFFFFFFF},
	}
	for _, c := range cases {
		want := obfsBuildNonce(c.ssrc, c.seq, c.ts)
		var got [12]byte
		obfsBuildNonceInto(&got, c.ssrc, c.seq, c.ts)
		if !bytes.Equal(want, got[:]) {
			t.Errorf("nonce mismatch ssrc=%x seq=%x ts=%x: want %x got %x",
				c.ssrc, c.seq, c.ts, want, got[:])
		}
		// Bytes [6:8] must be zero (part of the wire format).
		if got[6] != 0 || got[7] != 0 {
			t.Errorf("nonce [6:8] not zero: %x", got[:])
		}
	}
}

// --- wire format -------------------------------------------------------------

// Wrapping then unwrapping with the alloc-free path must recover the payload
// exactly, across a range of sizes including odd lengths.
func TestObfsRoundTrip(t *testing.T) {
	key := testKey(t, "round-trip-pass")
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	cfg := NewObfsConfig()
	state := NewObfsState()

	for _, n := range []int{1, 13, 64, 100, 1000, 1280, 1400} {
		payload := randPayload(t, n)
		dst := make([]byte, obfsWrapWireLen(n, cfg))
		wn, err := obfsWrapPacketInto(dst, aead, payload, cfg, state)
		if err != nil {
			t.Fatalf("wrap n=%d: %v", n, err)
		}
		wire := dst[:wn]

		// Wire sanity: RTP v2, P bit set, PT 111 → looks like a VK media packet.
		if wire[0] != 0xA0 {
			t.Errorf("n=%d byte0=%#x, want 0xA0 (V=2,P=1)", n, wire[0])
		}
		if wire[1]&0x7F != 111 {
			t.Errorf("n=%d PT=%d, want 111", n, wire[1]&0x7F)
		}
		if !obfsIsRTPPacket(wire) {
			t.Errorf("n=%d: obfsIsRTPPacket=false", n)
		}

		out := make([]byte, n+64)
		m, err := obfsUnwrapPacketAEAD(aead, wire, out)
		if err != nil {
			t.Fatalf("unwrap n=%d: %v", n, err)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Errorf("n=%d: payload mismatch after round trip", n)
		}
	}
}

// The refactor must not change the wire format: a packet produced by the OLD
// allocating path must decode with the NEW alloc-free path and vice versa.
// This is the core compatibility guarantee for the iOS WRAP-A client.
func TestObfsWireCompatOldNew(t *testing.T) {
	key := testKey(t, "compat-pass")
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	payload := randPayload(t, 512)

	// OLD wrap -> NEW unwrap
	{
		cfg := NewObfsConfig()
		state := NewObfsState()
		wire, err := obfsWrapPacket(key, payload, cfg, state)
		if err != nil {
			t.Fatalf("old wrap: %v", err)
		}
		out := make([]byte, len(payload)+64)
		m, err := obfsUnwrapPacketAEAD(aead, wire, out)
		if err != nil {
			t.Fatalf("new unwrap of old wrap: %v", err)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Fatal("old->new payload mismatch")
		}
	}

	// NEW wrap -> OLD unwrap
	{
		cfg := NewObfsConfig()
		state := NewObfsState()
		dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
		n, err := obfsWrapPacketInto(dst, aead, payload, cfg, state)
		if err != nil {
			t.Fatalf("new wrap: %v", err)
		}
		out := make([]byte, len(payload)+64)
		m, err := obfsUnwrapPacket(key, dst[:n], out)
		if err != nil {
			t.Fatalf("old unwrap of new wrap: %v", err)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Fatal("new->old payload mismatch")
		}
	}
}

// A packet authenticated under one password must NOT decrypt under another.
func TestObfsWrongKeyFails(t *testing.T) {
	aeadA, _ := getAEAD(testKey(t, "alice"))
	aeadB, _ := getAEAD(testKey(t, "bob"))
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(t, 200)

	dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
	n, err := obfsWrapPacketInto(dst, aeadA, payload, cfg, state)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	out := make([]byte, len(payload)+64)
	if _, err := obfsUnwrapPacketAEAD(aeadB, dst[:n], out); err == nil {
		t.Fatal("expected auth failure with wrong key, got nil")
	}
}

// dst smaller than the wrapped size must be rejected, not overflow.
func TestObfsWrapDstTooSmall(t *testing.T) {
	aead, _ := getAEAD(testKey(t, "small"))
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(t, 500)
	tiny := make([]byte, 50)
	if _, err := obfsWrapPacketInto(tiny, aead, payload, cfg, state); err == nil {
		t.Fatal("expected error for too-small dst")
	}
}

// --- key store ---------------------------------------------------------------

// A packet wrapped with a derived key must be recognised by the key store
// (the first-packet key-selection probe the server runs per connection).
func TestWrapKeyStoreUnwrapSelectsKey(t *testing.T) {
	ks := newWrapKeyStore()
	if err := ks.SetPasswords("main-pw", []string{"gen-pw-1", "gen-pw-2"}); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}

	for _, pw := range []string{"main-pw", "gen-pw-1", "gen-pw-2"} {
		key := testKey(t, pw)
		aead, _ := getAEAD(key)
		cfg := NewObfsConfig()
		state := NewObfsState()
		payload := randPayload(t, 128)
		dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
		n, _ := obfsWrapPacketInto(dst, aead, payload, cfg, state)

		out := make([]byte, len(payload)+64)
		gotKey, m, err := ks.Unwrap(dst[:n], out)
		if err != nil {
			t.Fatalf("pw=%s Unwrap: %v", pw, err)
		}
		if !bytes.Equal(gotKey, key) {
			t.Errorf("pw=%s: store selected wrong key", pw)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Errorf("pw=%s: payload mismatch", pw)
		}
	}

	// Unknown password must not authenticate against any stored key.
	badKey := testKey(t, "not-registered")
	badAead, _ := getAEAD(badKey)
	cfg := NewObfsConfig()
	state := NewObfsState()
	dst := make([]byte, obfsWrapWireLen(16, cfg))
	n, _ := obfsWrapPacketInto(dst, badAead, randPayload(t, 16), cfg, state)
	out := make([]byte, 128)
	if _, _, err := ks.Unwrap(dst[:n], out); err == nil {
		t.Fatal("expected Unwrap failure for unregistered password")
	}
}

// --- end-to-end wrapPacketConn ----------------------------------------------

type fakeAddr string

func (fakeAddr) Network() string  { return "fake" }
func (a fakeAddr) String() string { return string(a) }

// fakePacketConn is an in-memory net.PacketConn. Two are wired together by
// crossing their rx/tx channels, modelling the UDP/TURN path under the wrap.
type fakePacketConn struct {
	rx     chan []byte
	tx     chan []byte
	local  fakeAddr
	remote fakeAddr
	once   sync.Once
}

func newFakePair() (*fakePacketConn, *fakePacketConn) {
	a2b := make(chan []byte, 32)
	b2a := make(chan []byte, 32)
	a := &fakePacketConn{rx: b2a, tx: a2b, local: "A", remote: "B"}
	b := &fakePacketConn{rx: a2b, tx: b2a, local: "B", remote: "A"}
	return a, b
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-c.rx
	if !ok {
		return 0, c.remote, io.EOF
	}
	return copy(p, pkt), c.remote, nil
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	c.tx <- b
	return len(p), nil
}

func (c *fakePacketConn) Close() error                     { c.once.Do(func() { close(c.tx) }); return nil }
func (c *fakePacketConn) LocalAddr() net.Addr              { return c.local }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// Full path: a client (raw obfs over a fake conn) drives the server-side
// wrapPacketConn through key selection, server->client wrapped writes, and
// repeated client->server wrapped reads — all over the reused buffers.
func TestWrapPacketConnEndToEnd(t *testing.T) {
	const pw = "e2e-main"
	ks := newWrapKeyStore()
	if err := ks.SetPasswords(pw, nil); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}
	clientRaw, serverRaw := newFakePair()
	server := &wrapPacketConn{inner: serverRaw, keys: ks}

	key := testKey(t, pw)
	clientAead, _ := getAEAD(key)
	clientCfg := NewObfsConfig()
	clientState := NewObfsState()

	clientSend := func(payload []byte) {
		dst := make([]byte, obfsWrapWireLen(len(payload), clientCfg))
		n, err := obfsWrapPacketInto(dst, clientAead, payload, clientCfg, clientState)
		if err != nil {
			t.Fatalf("client wrap: %v", err)
		}
		if _, err := clientRaw.WriteTo(dst[:n], clientRaw.remote); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}

	// 1) First packet triggers key selection on the server.
	first := []byte("GETCONF:51820|deadbeef|" + pw)
	clientSend(first)
	rbuf := make([]byte, 2048)
	n, _, err := server.ReadFrom(rbuf)
	if err != nil {
		t.Fatalf("server ReadFrom (select): %v", err)
	}
	if !bytes.Equal(rbuf[:n], first) {
		t.Fatalf("first payload mismatch: got %q", rbuf[:n])
	}

	// 2) Server -> client: the client must decode using the SSRC carried on
	//    the wire (server picked its own ObfsConfig at selection time).
	resp := randPayload(t, 800)
	if _, err := server.WriteTo(resp, serverRaw.remote); err != nil {
		t.Fatalf("server WriteTo: %v", err)
	}
	wire := make([]byte, 2048)
	wn, _, err := clientRaw.ReadFrom(wire)
	if err != nil {
		t.Fatalf("client ReadFrom: %v", err)
	}
	cout := make([]byte, 2048)
	cm, err := obfsUnwrapPacketAEAD(clientAead, wire[:wn], cout)
	if err != nil {
		t.Fatalf("client unwrap server resp: %v", err)
	}
	if !bytes.Equal(cout[:cm], resp) {
		t.Fatal("server->client payload mismatch")
	}

	// 3) Many client -> server packets over the reused server rxBuf.
	for i := 0; i < 50; i++ {
		msg := randPayload(t, 200+i)
		clientSend(msg)
		rn, _, err := server.ReadFrom(rbuf)
		if err != nil {
			t.Fatalf("server ReadFrom #%d: %v", i, err)
		}
		if !bytes.Equal(rbuf[:rn], msg) {
			t.Fatalf("client->server payload mismatch #%d", i)
		}
	}
}

// --- allocations -------------------------------------------------------------

// The hot paths must not allocate the per-packet output/key buffers anymore.
// A single residual 16-byte allocation per call is unavoidable: the [12]byte
// nonce escapes to the heap when sliced into the cipher.AEAD interface method
// (the compiler can't prove Seal/Open don't retain it). That is a tiny fixed
// cost independent of payload size — the churn that mattered (the full output
// buffer + key string + nonce slice, ~1.3 KB / 3 allocs per packet) is gone.
const obfsHotPathMaxAllocs = 1.0

func TestObfsHotPathAllocsBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation distorts allocation counts")
	}
	key := testKey(t, "alloc-pass")
	aead, _ := getAEAD(key)
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(t, 1200)
	dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
	out := make([]byte, len(payload)+64)

	wrapAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsWrapPacketInto(dst, aead, payload, cfg, state); err != nil {
			t.Fatal(err)
		}
	})
	if wrapAllocs > obfsHotPathMaxAllocs {
		t.Errorf("obfsWrapPacketInto: %.1f allocs/op, want <= %.0f", wrapAllocs, obfsHotPathMaxAllocs)
	}

	// Build one valid packet to repeatedly unwrap.
	wn, _ := obfsWrapPacketInto(dst, aead, payload, cfg, state)
	wire := append([]byte(nil), dst[:wn]...)
	unwrapAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsUnwrapPacketAEAD(aead, wire, out); err != nil {
			t.Fatal(err)
		}
	})
	if unwrapAllocs > obfsHotPathMaxAllocs {
		t.Errorf("obfsUnwrapPacketAEAD: %.1f allocs/op, want <= %.0f", unwrapAllocs, obfsHotPathMaxAllocs)
	}

	// Regression guard: the new path must allocate strictly less than the old
	// allocating wrapper (which mallocs the whole output buffer every packet).
	oldAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsWrapPacket(key, payload, cfg, state); err != nil {
			t.Fatal(err)
		}
	})
	if wrapAllocs >= oldAllocs {
		t.Errorf("new wrap (%.1f allocs) not better than old (%.1f allocs)", wrapAllocs, oldAllocs)
	}
}

func BenchmarkObfsWrapInto(b *testing.B) {
	key := testKey(b, "bench")
	aead, _ := getAEAD(key)
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(b, 1200)
	dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := obfsWrapPacketInto(dst, aead, payload, cfg, state); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkObfsWrapOldAllocating(b *testing.B) {
	key := testKey(b, "bench")
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(b, 1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := obfsWrapPacket(key, payload, cfg, state); err != nil {
			b.Fatal(err)
		}
	}
}
