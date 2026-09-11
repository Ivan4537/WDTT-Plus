package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type updateRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn updateRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

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

func TestParseUpdateMetadataRequest(t *testing.T) {
	requestID, ok := parseUpdateMetadataRequest([]byte("WDTT_UPDATE1|request-1234"))
	if !ok || requestID != "request-1234" {
		t.Fatalf("request = %q, %t", requestID, ok)
	}
	for _, invalid := range []string{
		"ordinary WireGuard packet",
		"WDTT_UPDATE1|short",
		"WDTT_UPDATE1|request/with/slash",
	} {
		if _, accepted := parseUpdateMetadataRequest([]byte(invalid)); accepted {
			t.Fatalf("accepted invalid request %q", invalid)
		}
	}
}

func TestEncodeUpdateMetadataResponseChunksRoundTrip(t *testing.T) {
	payload := []byte(strings.Repeat("metadata", 300))
	frames := encodeUpdateMetadataResponse("request-1234", payload, nil)
	if len(frames) < 2 {
		t.Fatalf("frames = %d, want fragmentation", len(frames))
	}
	var restored []byte
	for _, frame := range frames {
		parts := strings.Split(string(frame), "|")
		if len(parts) != 6 || parts[0] != "WDTT_UPDATE1_RESULT" || parts[1] != "request-1234" || parts[2] != "OK" {
			t.Fatalf("unexpected frame %q", frame)
		}
		chunk, err := base64.RawURLEncoding.DecodeString(parts[5])
		if err != nil {
			t.Fatal(err)
		}
		restored = append(restored, chunk...)
	}
	if string(restored) != string(payload) {
		t.Fatal("fragmented response did not round-trip")
	}
}

func TestEncodeUpdateAPKChunkResponsePreservesBinaryPayload(t *testing.T) {
	payload := make([]byte, updateAPKFrameBytes*2+17)
	for index := range payload {
		payload[index] = byte(index % 256)
	}
	frames := encodeUpdateAPKChunkResponse("request-1234", payload, nil)
	if len(frames) != 3 {
		t.Fatalf("frames = %d, want 3", len(frames))
	}
	restored := make([]byte, 0, len(payload))
	for _, frame := range frames {
		parts := bytes.SplitN(frame, []byte("|"), 6)
		if len(parts) != 6 || string(parts[0]) != "WDTT_UPDATE_APK1_RESULT" || string(parts[2]) != "OK" {
			t.Fatalf("unexpected APK frame header %q", frame[:min(len(frame), 100)])
		}
		restored = append(restored, parts[5]...)
	}
	if !bytes.Equal(restored, payload) {
		t.Fatal("binary APK response did not round-trip")
	}
}

func TestParseUpdateAPKChunkRequest(t *testing.T) {
	assetURL := "https://github.com/Ivan4537/WDTT-Plus/releases/download/v18/app.apk"
	encodedAssetURL := base64.RawURLEncoding.EncodeToString([]byte(assetURL))
	digest := strings.Repeat("a", 64)
	packet := "WDTT_UPDATE_APK1|request-1234|32768|1024|65536|" + digest + "|" +
		encodedAssetURL
	request, ok := parseUpdateAPKChunkRequest([]byte(packet))
	if !ok || request.offset != 32768 || request.length != 1024 || request.size != 65536 || request.downloadURL != assetURL {
		t.Fatalf("unexpected request: %#v, %t", request, ok)
	}
	for _, invalid := range []string{
		strings.Replace(packet, "|1024|", "|65537|", 1),
		strings.Replace(packet, encodedAssetURL, base64.RawURLEncoding.EncodeToString([]byte("https://example.com/app.apk")), 1),
		strings.Replace(packet, digest, "bad", 1),
	} {
		if _, accepted := parseUpdateAPKChunkRequest([]byte(invalid)); accepted {
			t.Fatalf("accepted invalid APK request %q", invalid)
		}
	}
}

func TestDownloadOfficialUpdateAPKVerifiesContent(t *testing.T) {
	payload := []byte(strings.Repeat("apk-data", 512))
	digest := sha256.Sum256(payload)
	request := updateAPKChunkRequest{
		requestID:   "request-1234",
		offset:      0,
		length:      len(payload),
		size:        int64(len(payload)),
		sha256:      hex.EncodeToString(digest[:]),
		downloadURL: "https://github.com/Ivan4537/WDTT-Plus/releases/download/v18/app.apk",
	}
	client := &http.Client{Transport: updateRoundTripFunc(func(httpRequest *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: int64(len(payload)),
			Body:          io.NopCloser(strings.NewReader(string(payload))),
			Header:        make(http.Header),
			Request:       httpRequest,
		}, nil
	})}
	path, err := downloadOfficialUpdateAPK(context.Background(), client, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(payload) {
		t.Fatal("cached APK content changed")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cached APK mode = %v, %v", info, err)
	}
}

func TestConvertGitHubReleaseKeepsOnlyOfficialAPKs(t *testing.T) {
	release := githubUpdateRelease{TagName: "17", HTMLURL: "https://github.com/Ivan4537/WDTT-Plus/releases/tag/v17"}
	release.Assets = append(release.Assets,
		struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			Digest             string `json:"digest"`
		}{"WDTT-Plus-v17-arm64-v8a-release.apk", "https://github.com/Ivan4537/WDTT-Plus/releases/download/v17/app.apk", 123, "sha256:abc"},
		struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			Digest             string `json:"digest"`
		}{"server.tar.gz", "https://github.com/Ivan4537/WDTT-Plus/releases/download/v17/server.tar.gz", 456, "sha256:def"},
		struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			Digest             string `json:"digest"`
		}{"evil.apk", "https://example.com/evil.apk", 789, "sha256:bad"},
	)
	metadata := convertGitHubRelease(release)
	if metadata.VersionTag != "v17" || len(metadata.Assets) != 1 {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestParseDeploySafeStartRequestChecksDigest(t *testing.T) {
	payload := []byte(`{"main_password":"secret","args":["list"]}`)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	packet := []byte(deploySafeRequestPrefix + "request-1234|" + digest + "|" + base64.RawURLEncoding.EncodeToString(payload))
	request, ok := parseDeploySafeStartRequest(packet)
	if !ok || request.requestID != "request-1234" || string(request.payload) != string(payload) {
		t.Fatalf("valid request rejected: %#v, ok=%v", request, ok)
	}
	packet[len(packet)-1] ^= 1
	if _, ok := parseDeploySafeStartRequest(packet); ok {
		t.Fatal("corrupted request accepted")
	}
}

func TestRelayedDeployAdminAllowlist(t *testing.T) {
	allowed := [][]string{
		{"list"},
		{"details", "--password", "client-secret"},
		{"backup-status"},
		{"backup-verify", "--id", "20260909T010203Z-012345abcdef"},
		{"backup-export", "--id", "20260909T010203Z-012345abcdef"},
		{"backup-create", "--reason", "manual"},
		{"safe-inspect", "outbound-status"},
		{"safe-inspect", "server-diagnostics", "56000", "56001", "9000"},
		{"safe-inspect", "check-tun", "tun0"},
		{"safe-inspect", "check-local-proxy", "1080", "login", "password"},
		{"safe-inspect", "check-external-proxy", "Socks5", "proxy.example", "1080", "", ""},
		{"safe-inspect", "database-snapshot"},
		{"safe-inspect", "config-export", "true"},
	}
	for _, args := range allowed {
		if !isRelayedDeployAdminCommandAllowed(args) {
			t.Fatalf("safe command rejected: %#v", args)
		}
	}
	blocked := [][]string{
		{"restart"},
		{"delete", "--password", "client-secret"},
		{"backup-delete", "--id", "20260909T010203Z-012345abcdef"},
		{"backup-create", "--reason", "pre_restore"},
		{"backup-verify", "--id", "../../etc/shadow"},
		{"safe-inspect", "run", "rm", "-rf", "/"},
		{"safe-inspect", "check-tun", "tun0;reboot"},
		{"safe-inspect", "check-external-proxy", "Socks5", "https://proxy.example", "1080", "", ""},
		{"safe-inspect", "config-export", "yes"},
	}
	for _, args := range blocked {
		if isRelayedDeployAdminCommandAllowed(args) {
			t.Fatalf("unsafe command accepted: %#v", args)
		}
	}
}

func TestRelayedDeployReadOnlyCardsReturnCurrentServerState(t *testing.T) {
	configDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(configDir, "passwords.json"),
		[]byte(`{"main_password":"owner-secret","passwords":{},"devices":{}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"list"},
		{"backup-status"},
		{"safe-inspect", "database-snapshot"},
		{"safe-inspect", "config-export", "false"},
	} {
		request, err := json.Marshal(adminRequest{MainPassword: "owner-secret", Args: args})
		if err != nil {
			t.Fatal(err)
		}
		response, err := executeDeploySafeAdminRequest(configDir, nil, request)
		if err != nil {
			t.Fatalf("args=%v: %v", args, err)
		}
		var decoded adminResponse
		if err := json.Unmarshal(response, &decoded); err != nil {
			t.Fatalf("args=%v response=%q: %v", args, response, err)
		}
		if !decoded.OK {
			t.Fatalf("args=%v response=%+v", args, decoded)
		}
	}
}

func TestParseOpaqueHTTPSRequest(t *testing.T) {
	packet := strings.Join([]string{
		"WDTT_HTTPS_POST1",
		"request-1234",
		base64.RawURLEncoding.EncodeToString([]byte("https://example.org/status")),
		base64.RawURLEncoding.EncodeToString([]byte(`{"operation":"status"}`)),
	}, "|")
	request, ok := parseOpaqueHTTPSRequest([]byte(packet))
	if !ok || request.requestID != "request-1234" || request.url != "https://example.org/status" {
		t.Fatalf("request rejected: %#v, ok=%v", request, ok)
	}
}

func TestParseOpaqueHTTPSRequestRejectsOversizedPacket(t *testing.T) {
	if _, ok := parseOpaqueHTTPSRequest([]byte("WDTT_HTTPS_POST1|request-1234|" + strings.Repeat("a", 1500))); ok {
		t.Fatal("oversized request accepted")
	}
}

func TestOpaqueHTTPSAddressPolicyRejectsLocalNetworks(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"100.64.0.1",
		"169.254.1.1",
		"192.168.1.1",
		"198.18.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"2001:db8::1",
	} {
		if isPublicOpaqueHTTPSAddress(netip.MustParseAddr(value)) {
			t.Fatalf("local or reserved address accepted: %s", value)
		}
	}
	if !isPublicOpaqueHTTPSAddress(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
}

func TestParseDeploySafeChunkRequestRejectsBounds(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	valid := []byte(deploySafeChunkRequestPrefix + "chunk-1234|request-1234|0|16384|" + digest)
	if request, ok := parseDeploySafeChunkRequest(valid); !ok || request.length != 16384 {
		t.Fatalf("valid chunk request rejected: %#v, ok=%v", request, ok)
	}
	tooLarge := []byte(deploySafeChunkRequestPrefix + "chunk-1234|request-1234|0|32769|" + digest)
	if _, ok := parseDeploySafeChunkRequest(tooLarge); ok {
		t.Fatal("oversized chunk request accepted")
	}
}

func TestDeploySafeConfigExportReadsOnlyBoundedRegularFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "passwords.json"), []byte(`{"main_password":"secret","passwords":{},"devices":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wg-keys.dat"), []byte("private\npublic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := deploySafeConfigExport(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]string
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	if document["passwords_b64"] == "" || document["wg_keys_b64"] == "" || document["backup_policy_b64"] == "" {
		t.Fatalf("incomplete export: %#v", document)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"main_password":"leak"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "passwords.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "passwords.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := deploySafeConfigExport(dir, false); err == nil {
		t.Fatal("symbolic-link database was accepted")
	}
}
