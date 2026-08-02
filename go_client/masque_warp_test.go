package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testWarpMasqueConfig(t *testing.T) *warpMasqueConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &warpMasqueConfig{
		Version:        warpConfigVersion,
		PrivateKey:     base64.StdEncoding.EncodeToString(privateDER),
		EndpointV4:     "162.159.197.1",
		EndpointH2V4:   warpDefaultH2Endpoint,
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		DeviceID:       "device",
		AccessToken:    "token",
		IPv4:           "172.16.0.2",
		IPv6:           "2606:4700:110:8f1b::2",
	}
}

func TestWarpMasqueProtocolOrder(t *testing.T) {
	if got, want := warpMasqueProtocolOrder(""), []warpMasqueProtocol{warpMasqueHTTP2, warpMasqueHTTP3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default order = %v, want %v", got, want)
	}
	if got, want := warpMasqueProtocolOrder(warpMasqueHTTP3), []warpMasqueProtocol{warpMasqueHTTP3, warpMasqueHTTP2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remembered order = %v, want %v", got, want)
	}
}

func TestEndpointHost(t *testing.T) {
	for input, want := range map[string]string{
		"162.159.197.1:0":  "162.159.197.1",
		"[2606:4700::1]:0": "2606:4700::1",
		"162.159.197.1":    "162.159.197.1",
	} {
		got, err := endpointHost(input)
		if err != nil || got != want {
			t.Fatalf("endpointHost(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := endpointHost("warp.invalid:0"); err == nil {
		t.Fatal("hostname endpoint must be rejected")
	}
}

func TestWarpMasqueConfigRoundTripIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "warp.json")
	want := testWarpMasqueConfig(t)
	if err := saveWarpMasqueConfig(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
	got, err := loadWarpMasqueConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestWarpMasqueRequiresExplicitSNIAndConfigPath(t *testing.T) {
	if _, err := newWarpMasqueManager(context.Background(), "", "ya.ru", true); err == nil {
		t.Fatal("empty config path must be rejected")
	}
	if _, err := newWarpMasqueManager(context.Background(), "warp.json", "", true); err == nil {
		t.Fatal("empty outer SNI must be rejected")
	}
}

func TestWarpAPIErrorMessageKeepsSafeStatusAndBackendCode(t *testing.T) {
	got := warpAPIErrorMessage(429, []byte(`{"errors":[{"code":1042,"message":"  rate   limited  "}]}`))
	want := "WARP API HTTP 429: code=1042 rate limited"
	if got != want {
		t.Fatalf("warpAPIErrorMessage = %q, want %q", got, want)
	}
}

func TestWarpAPINetworkErrorRemovesDeviceURL(t *testing.T) {
	got := warpAPINetworkError(&url.Error{
		Op:  "Patch",
		URL: "https://api.cloudflareclient.com/v0a4471/reg/secret-device-id",
		Err: context.DeadlineExceeded,
	}, warpAPIPhaseResponse).Error()
	if strings.Contains(got, "secret-device-id") || strings.Contains(got, "https://") {
		t.Fatalf("network error leaked request URL: %q", got)
	}
	if !strings.Contains(got, "HTTP-запрос отправлен") {
		t.Fatalf("network error lacks Russian diagnosis: %q", got)
	}
}

func TestWarpAPINetworkErrorNamesExactHTTPSPhase(t *testing.T) {
	tlsError := warpAPINetworkError(
		errors.New("net/http: TLS handshake timeout"),
		warpAPIPhaseTLS,
	).Error()
	if !strings.Contains(tlsError, "тайм-аут TLS-рукопожатия") ||
		!strings.Contains(tlsError, "после успешного TCP/443") {
		t.Fatalf("TLS diagnosis = %q", tlsError)
	}

	headerError := warpAPINetworkError(
		errors.New("net/http: timeout awaiting response headers"),
		warpAPIPhaseResponse,
	).Error()
	if !strings.Contains(headerError, "HTTP-запрос отправлен") ||
		!strings.Contains(headerError, "не прислал заголовки ответа") {
		t.Fatalf("response diagnosis = %q", headerError)
	}
}

func TestWarpAPIRelayErrorKeepsRussianPhaseWithoutEndpoint(t *testing.T) {
	got := warpAPIRelayNetworkError(
		&url.Error{
			Op:  "Post",
			URL: "https://api.cloudflareclient.com/private-device-path",
			Err: errors.New("net/http: TLS handshake timeout"),
		},
		warpAPIPhaseTLS,
	).Error()
	if !strings.Contains(got, "через сервер профиля") ||
		!strings.Contains(got, "TLS-рукопожатие") {
		t.Fatalf("relay diagnosis = %q", got)
	}
	if strings.Contains(got, "private-device-path") || strings.Contains(got, "https://") {
		t.Fatalf("relay diagnosis leaked request URL: %q", got)
	}
}

func TestWarpAPITraceDistinguishesSafePreWriteFailure(t *testing.T) {
	requestTrace := newWarpAPIRequestTrace()
	clientTrace := requestTrace.clientTrace()
	clientTrace.TLSHandshakeStart()
	phase, written := requestTrace.snapshot()
	if phase != warpAPIPhaseTLS || written {
		t.Fatalf("before write: phase=%q written=%v", phase, written)
	}
	if !warpAPICanRetryBeforeWrite(&net.DNSError{Err: "timeout", IsTimeout: true}) {
		t.Fatal("pre-write network timeout must allow one safe retry")
	}

	clientTrace.WroteRequest(httptrace.WroteRequestInfo{})
	phase, written = requestTrace.snapshot()
	if phase != warpAPIPhaseResponse || !written {
		t.Fatalf("after write: phase=%q written=%v", phase, written)
	}
}

func TestWarpAPIFragmentConnOnlyFragmentsFirstTLSClientHello(t *testing.T) {
	underlying := &recordingConn{}
	connection := &warpAPIFragmentConn{
		Conn:      underlying,
		chunkSize: 8,
	}

	proxyConnect := []byte("CONNECT api.cloudflareclient.com:443 HTTP/1.1\r\n\r\n")
	if written, err := connection.Write(proxyConnect); err != nil || written != len(proxyConnect) {
		t.Fatalf("proxy CONNECT write = %d, %v", written, err)
	}
	if len(underlying.writes) != 1 {
		t.Fatalf("plain proxy request writes = %d, want 1", len(underlying.writes))
	}

	clientHello := append([]byte{0x16, 0x03, 0x01, 0x00, 0x18, 0x01, 0x00, 0x00, 0x14}, make([]byte, 20)...)
	if written, err := connection.Write(clientHello); err != nil || written != len(clientHello) {
		t.Fatalf("ClientHello write = %d, %v", written, err)
	}
	if got := len(underlying.writes); got != 1+4 {
		t.Fatalf("writes after fragmented ClientHello = %d, want 5", got)
	}
	if reconstructed := bytes.Join(underlying.writes[1:], nil); !bytes.Equal(reconstructed, clientHello) {
		t.Fatalf("fragmented ClientHello changed: %x", reconstructed)
	}

	applicationData := []byte{0x17, 0x03, 0x03, 0x00, 0x03, 1, 2, 3}
	if _, err := connection.Write(applicationData); err != nil {
		t.Fatal(err)
	}
	if got := len(underlying.writes); got != 6 {
		t.Fatalf("later TLS record was fragmented: writes=%d, want 6", got)
	}
}

func TestWarpHTTPClientsKeepCertificateVerificationAndIsolateFallback(t *testing.T) {
	normalTransport, ok := newWarpHTTPClient(false).Transport.(*http.Transport)
	if !ok {
		t.Fatal("normal WARP client does not use net/http transport")
	}
	if !normalTransport.ForceAttemptHTTP2 || normalTransport.TLSClientConfig != nil {
		t.Fatalf("normal WARP client changed: HTTP/2=%v TLS=%#v", normalTransport.ForceAttemptHTTP2, normalTransport.TLSClientConfig)
	}

	fallbackTransport, ok := newWarpHTTPClient(true).Transport.(*http.Transport)
	if !ok {
		t.Fatal("fallback WARP client does not use net/http transport")
	}
	tlsConfig := fallbackTransport.TLSClientConfig
	if tlsConfig == nil {
		t.Fatal("fallback TLS configuration is missing")
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 || tlsConfig.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("fallback TLS range = %x..%x, want TLS 1.2 only", tlsConfig.MinVersion, tlsConfig.MaxVersion)
	}
	if fallbackTransport.ForceAttemptHTTP2 || !reflect.DeepEqual(tlsConfig.NextProtos, []string{"http/1.1"}) {
		t.Fatalf("fallback HTTP protocol = HTTP/2:%v ALPN:%v", fallbackTransport.ForceAttemptHTTP2, tlsConfig.NextProtos)
	}
	if tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs != nil {
		t.Fatal("fallback must retain system roots and full certificate verification")
	}
}

func TestWarpAPIRelayAcceptsOnlyLoopbackAndKeepsEndToEndTLS(t *testing.T) {
	if _, err := normalizeWarpAPIRelayAddress("192.0.2.1:443"); err == nil {
		t.Fatal("non-loopback relay must be rejected")
	}
	address, err := normalizeWarpAPIRelayAddress("127.0.0.1:19443")
	if err != nil || address != "127.0.0.1:19443" {
		t.Fatalf("loopback relay = %q, %v", address, err)
	}
	client, err := newWarpRelayHTTPClient(address)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("relay client does not use net/http transport")
	}
	if transport.Proxy != nil || transport.TLSClientConfig != nil || !transport.ForceAttemptHTTP2 {
		t.Fatalf(
			"relay changed HTTPS security: proxySet=%v TLS=%#v HTTP/2=%v",
			transport.Proxy != nil,
			transport.TLSClientConfig,
			transport.ForceAttemptHTTP2,
		)
	}
}

func TestWarpAPIRecognizesOnlyTLSPhaseTimeoutForFragmentedRetry(t *testing.T) {
	tlsTimeout := errors.New("net/http: TLS handshake timeout")
	if !warpAPIIsTLSHandshakeTimeout(tlsTimeout, warpAPIPhaseTLS) {
		t.Fatal("TLS handshake timeout must select the fragmented fallback")
	}
	if warpAPIIsTLSHandshakeTimeout(tlsTimeout, warpAPIPhaseTCP) {
		t.Fatal("TCP-phase timeout must not select the TLS fallback")
	}
	if warpAPIIsTLSHandshakeTimeout(&net.DNSError{Err: "timeout", IsTimeout: true}, warpAPIPhaseDNS) {
		t.Fatal("DNS timeout must not select the TLS fallback")
	}
}

func TestWarpAPIRequestDiagnosesUnexpectedSuccessfulResponse(t *testing.T) {
	for name, body := range map[string]string{
		"empty": "",
		"html":  "<html>challenge</html>",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			var out warpAccountData
			err := warpAPIRequest(context.Background(), http.MethodPost, server.URL, "", struct{}{}, &out)
			if err == nil {
				t.Fatal("unexpected response must fail")
			}
			message := err.Error()
			if !strings.Contains(message, "HTTP 200") || !strings.Contains(message, "Content-Type=text/html") {
				t.Fatalf("diagnosis lacks status or content type: %q", message)
			}
			if strings.Contains(message, body) && body != "" {
				t.Fatalf("diagnosis leaked response body: %q", message)
			}
		})
	}
}

func TestTurnCandidateStagesAreIsolatedBehindMasque(t *testing.T) {
	candidates := []turnEndpoint{
		{Host: "turns.example", Port: "443", Transport: turnTransportTLS},
		{Host: "turn.example", Port: "443", Transport: turnTransportTCP},
		{Host: "turn.example", Port: "3478", Transport: turnTransportUDP},
	}

	direct, masque, finalUDP := turnCandidateStages(candidates, false)
	if !reflect.DeepEqual(direct, candidates) || masque != nil || finalUDP != nil {
		t.Fatalf("ordinary stages changed: direct=%v masque=%v udp=%v", direct, masque, finalUDP)
	}

	direct, masque, finalUDP = turnCandidateStages(candidates, true)
	wantStream := candidates[:2]
	wantUDP := candidates[2:]
	if !reflect.DeepEqual(direct, wantStream) || !reflect.DeepEqual(masque, wantStream) || !reflect.DeepEqual(finalUDP, wantUDP) {
		t.Fatalf("MASQUE stages = direct=%v masque=%v udp=%v", direct, masque, finalUDP)
	}
}
