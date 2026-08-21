package main

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type singlePacketConn struct {
	packet []byte
	remote net.Addr
}

type generationLeaseConn struct {
	deadlineSet atomic.Bool
}

func (c *generationLeaseConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *generationLeaseConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *generationLeaseConn) Close() error                     { return nil }
func (c *generationLeaseConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *generationLeaseConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *generationLeaseConn) SetDeadline(time.Time) error      { c.deadlineSet.Store(true); return nil }
func (c *generationLeaseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *generationLeaseConn) SetWriteDeadline(time.Time) error { return nil }

func (c *singlePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.packet), c.remote, nil
}

func (c *singlePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *singlePacketConn) Close() error                              { return nil }
func (c *singlePacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *singlePacketConn) SetDeadline(time.Time) error               { return nil }
func (c *singlePacketConn) SetReadDeadline(time.Time) error           { return nil }
func (c *singlePacketConn) SetWriteDeadline(time.Time) error          { return nil }

func TestDeviceLogRefIsStableAndDoesNotExposeIdentifier(t *testing.T) {
	deviceID := "android-private-device-identifier"
	first := deviceLogRef(deviceID)
	second := deviceLogRef(deviceID)
	if first != second {
		t.Fatalf("device log reference is unstable: %q != %q", first, second)
	}
	if first == "" || strings.Contains(first, deviceID) || len(first) != 12 {
		t.Fatalf("device log reference exposes its source: %q", first)
	}
}

func TestWrapKeyStoreReturnsAuthenticatedAccessIdentity(t *testing.T) {
	store := newWrapKeyStore()
	if err := store.SetPasswords("owner-secret", []string{"client-secret"}); err != nil {
		t.Fatal(err)
	}
	key, err := deriveWrapKey("client-secret")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("dtls handshake packet")
	wire, err := obfsWrapPacket(key, payload, NewObfsConfig(), NewObfsState())
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 256)
	selectedKey, identity, n, err := store.Unwrap(wire, dst)
	if err != nil {
		t.Fatal(err)
	}
	if identity.password != "client-secret" || identity.isMain || !strings.HasPrefix(identity.id, "pass:") {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if string(dst[:n]) != string(payload) {
		t.Fatalf("unexpected payload: %q", dst[:n])
	}
	if string(selectedKey) != string(key) {
		t.Fatal("selected key differs from authenticated key")
	}
}

func TestWrapIdentityBecomesAvailableAfterFirstRead(t *testing.T) {
	store := newWrapKeyStore()
	if err := store.SetPasswords("owner-secret", []string{"client-secret"}); err != nil {
		t.Fatal(err)
	}
	key, err := deriveWrapKey("client-secret")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := obfsWrapPacket(key, []byte("client hello"), NewObfsConfig(), NewObfsState())
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 42000}
	conn := &wrapPacketConn{
		inner: &singlePacketConn{packet: wire, remote: remote},
		keys:  store,
	}
	if _, ok := wrappedIdentity(remote); ok {
		t.Fatal("identity unexpectedly existed before the first WRAP read")
	}
	plain := make([]byte, 256)
	if _, _, err := conn.ReadFrom(plain); err != nil {
		t.Fatal(err)
	}
	identity, ok := wrappedIdentity(remote)
	if !ok || identity.password != "client-secret" {
		t.Fatalf("identity was not registered by the first WRAP read: %#v", identity)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := wrappedIdentity(remote); ok {
		t.Fatal("identity remained registered after closing the connection")
	}
}

func TestAccessWorkerLimitIsSharedByAllWorkers(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(2, 0)
	if limit := configuredAccessWorkerLimit(); limit != 2 {
		t.Fatalf("configured limit = %d, want 2", limit)
	}
	identity := accessIdentity{id: "pass:test", password: "secret"}

	_, releaseFirst, ok := acquireAccessWorker(identity)
	if !ok {
		t.Fatal("first worker rejected")
	}
	_, releaseSecond, ok := acquireAccessWorker(identity)
	if !ok {
		t.Fatal("second worker rejected")
	}
	if _, _, ok := acquireAccessWorker(identity); ok {
		t.Fatal("worker over the per-access limit was accepted")
	}
	releaseFirst()
	if _, releaseThird, ok := acquireAccessWorker(identity); !ok {
		t.Fatal("worker was not accepted after capacity release")
	} else {
		releaseThird()
	}
	releaseSecond()
}

func TestOwnerWorkersAreNotRestrictedByClientAccessLimit(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(2, 0)
	identity := accessIdentity{id: "main", password: "owner-secret", isMain: true}

	releases := make([]func(), 0, 5)
	for worker := 0; worker < 5; worker++ {
		_, release, ok := acquireAccessWorker(identity)
		if !ok {
			t.Fatalf("owner worker %d was restricted by the client access limit", worker)
		}
		releases = append(releases, release)
	}
	for _, release := range releases {
		release()
	}
}

func TestNewTransportSessionReplacesStaleWorkersWithoutRaisingLimit(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(3, 0)
	identity := accessIdentity{id: "pass:replace", password: "secret"}

	oldFirstConn := &generationLeaseConn{}
	_, oldFirst, releaseOldFirst, ok := acquireAccessWorkerSession(identity, oldFirstConn)
	if !ok {
		t.Fatal("first old worker rejected")
	}
	oldSecondConn := &generationLeaseConn{}
	_, _, releaseOldSecond, ok := acquireAccessWorkerSession(identity, oldSecondConn)
	if !ok {
		t.Fatal("second old worker rejected")
	}
	if !activateAccessSession(oldFirst, "device-one", "session-old-0001") {
		t.Fatal("initial transport session was not activated")
	}

	newConfigConn := &generationLeaseConn{}
	_, newConfig, releaseNewConfig, ok := acquireAccessWorkerSession(identity, newConfigConn)
	if !ok {
		t.Fatal("new config worker must fit the configured transition headroom")
	}
	if !activateAccessSession(newConfig, "device-one", "session-new-0002") {
		t.Fatal("new transport session was not activated")
	}
	if !oldFirstConn.deadlineSet.Load() || !oldSecondConn.deadlineSet.Load() {
		t.Fatal("stale transport workers were not closed")
	}

	newReleases := []func(){releaseNewConfig}
	for worker := 0; worker < 2; worker++ {
		_, _, release, accepted := acquireAccessWorkerSession(identity, &generationLeaseConn{})
		if !accepted {
			t.Fatalf("new generation worker %d was blocked by stale workers", worker)
		}
		newReleases = append(newReleases, release)
	}
	if _, _, _, accepted := acquireAccessWorkerSession(identity, &generationLeaseConn{}); accepted {
		t.Fatal("current generation exceeded the unchanged worker limit")
	}

	releaseOldFirst()
	releaseOldSecond()
	for _, release := range newReleases {
		release()
	}
}

func TestAuthenticatedConfigConnectionReplacesAFullStaleGeneration(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(3, 0)
	identity := accessIdentity{id: "pass:full-replace", password: "secret"}

	oldConnections := make([]*generationLeaseConn, 0, 3)
	oldReleases := make([]func(), 0, 3)
	for worker := 0; worker < 3; worker++ {
		connection := &generationLeaseConn{}
		_, lease, release, ok := acquireAccessWorkerSession(identity, connection)
		if !ok {
			t.Fatalf("old worker %d was rejected", worker)
		}
		if worker == 0 && !activateAccessSession(lease, "device-one", "session-old-0001") {
			t.Fatal("old generation was not activated")
		}
		oldConnections = append(oldConnections, connection)
		oldReleases = append(oldReleases, release)
	}

	newConnection := &generationLeaseConn{}
	_, newLease, releaseNew, ok := acquireAccessWorkerForSession(
		identity,
		newConnection,
		"device-one",
		"session-new-0002",
	)
	if !ok || newLease == nil {
		t.Fatal("authenticated GETCONF was blocked by a full stale generation")
	}
	for index, connection := range oldConnections {
		if !connection.deadlineSet.Load() {
			t.Fatalf("stale worker %d was not closed", index)
		}
	}

	newReleases := []func(){releaseNew}
	for worker := 0; worker < 2; worker++ {
		_, _, release, accepted := acquireAccessWorkerSession(identity, &generationLeaseConn{})
		if !accepted {
			t.Fatalf("new worker %d was rejected after generation replacement", worker)
		}
		newReleases = append(newReleases, release)
	}
	if _, _, _, accepted := acquireAccessWorkerSession(identity, &generationLeaseConn{}); accepted {
		t.Fatal("new generation exceeded the unchanged worker limit")
	}

	for _, release := range oldReleases {
		release()
	}
	for _, release := range newReleases {
		release()
	}
}

func TestSameTransportSessionCannotBeClaimedByAnotherDevice(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(3, 0)
	identity := accessIdentity{id: "pass:device", password: "secret"}
	oldConn := &generationLeaseConn{}
	_, first, releaseFirst, ok := acquireAccessWorkerSession(identity, oldConn)
	if !ok || !activateAccessSession(first, "device-one", "session-old-0001") {
		t.Fatal("initial session failed")
	}
	_, second, releaseSecond, ok := acquireAccessWorkerSession(identity, &generationLeaseConn{})
	if !ok {
		t.Fatal("second worker rejected")
	}
	if activateAccessSession(second, "device-two", "session-old-0001") {
		t.Fatal("another device claimed the same transport session")
	}
	if !activateAccessSession(second, "device-two", "session-new-0002") {
		t.Fatal("an authorized new generation did not replace the explicitly rebound device")
	}
	if !oldConn.deadlineSet.Load() {
		t.Fatal("the explicitly rebound device left its old transport alive")
	}
	releaseFirst()
	releaseSecond()
}

func TestGeneralServerRuntimeDefaultsAreUnrestricted(t *testing.T) {
	registry := newAccessRuntimeRegistry()
	if registry.maxWorkers != 0 {
		t.Fatalf("default worker limit = %d, want disabled", registry.maxWorkers)
	}
	if registry.clientMbps != 0 {
		t.Fatalf("default client speed limit = %v, want disabled", registry.clientMbps)
	}
}

func TestFiftyClientEighteenWorkerAcceptanceProfile(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(24, 50)

	releases := make([]func(), 0, 50*18)
	for client := 0; client < 50; client++ {
		identity := accessIdentity{
			id:       "pass:client-" + strconv.Itoa(client),
			password: "secret-" + strconv.Itoa(client),
		}
		for worker := 0; worker < 18; worker++ {
			_, release, ok := acquireAccessWorker(identity)
			if !ok {
				t.Fatalf("client %d worker %d was rejected", client, worker)
			}
			releases = append(releases, release)
		}
	}
	if len(releases) != 900 {
		t.Fatalf("expected 900 workers, got %d", len(releases))
	}
	for _, release := range releases {
		release()
	}
}

func TestLegacyNineWorkerClientRemainsAcceptedByExpandedServerLimit(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(24, 50)
	identity := accessIdentity{id: "pass:legacy-client", password: "secret"}

	releases := make([]func(), 0, 9)
	for worker := 0; worker < 9; worker++ {
		_, release, ok := acquireAccessWorker(identity)
		if !ok {
			t.Fatalf("legacy worker %d was rejected", worker)
		}
		releases = append(releases, release)
	}
	for _, release := range releases {
		release()
	}
}

func TestUnlimitedWorkerPolicyDoesNotRestrictGeneralServer(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(0, 50)

	identity := accessIdentity{id: "pass:general", password: "secret-general"}
	releases := make([]func(), 0, 256)
	for worker := 0; worker < 256; worker++ {
		_, release, ok := acquireAccessWorker(identity)
		if !ok {
			t.Fatalf("general server rejected worker %d with disabled limit", worker)
		}
		releases = append(releases, release)
	}
	for _, release := range releases {
		release()
	}
}

func TestTokenBucketWaitHonorsContext(t *testing.T) {
	bucket := newTokenBucket(1, 1)
	if !bucket.allow(1) {
		t.Fatal("initial burst was unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := bucket.wait(ctx, 1); err == nil {
		t.Fatal("expected context cancellation while waiting for bandwidth")
	}
}

func TestWireGuardHexToBase64(t *testing.T) {
	hexKey := strings.Repeat("01", 32)
	got, err := wireGuardHexToBase64(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 || raw[0] != 1 || raw[31] != 1 {
		t.Fatalf("unexpected key conversion: %x", raw)
	}
}

func TestLinuxRuntimeReaders(t *testing.T) {
	cpu, err := readProcCPU()
	if err != nil || cpu.total == 0 {
		t.Fatalf("readProcCPU: %#v, %v", cpu, err)
	}
	memory, err := readProcMemoryPercent()
	if err != nil || memory < 0 || memory > 100 {
		t.Fatalf("readProcMemoryPercent: %.2f, %v", memory, err)
	}
	if _, err := readProcUDPDrops(); err != nil {
		t.Fatalf("readProcUDPDrops: %v", err)
	}
}
