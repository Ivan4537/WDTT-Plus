package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestChooseDNSRouteFallsBackToSystemAfterDirectTimeouts(t *testing.T) {
	directAttempts := make([]string, 0, 4)
	systemAttempts := 0

	route, probes := chooseDNSRouteWithProbes(
		context.Background(),
		&net.Resolver{},
		func(_ context.Context, route dnsRoute, _ time.Duration) error {
			directAttempts = append(directAttempts, route.Label)
			return context.DeadlineExceeded
		},
		func(_ context.Context, _ *net.Resolver, _ time.Duration) error {
			systemAttempts++
			return nil
		},
	)

	wantAttempts := []string{
		"77.88.8.8 UDP",
		"77.88.8.1 UDP",
		"77.88.8.8 TCP",
		"77.88.8.1 TCP",
	}
	if len(directAttempts) != len(wantAttempts) {
		t.Fatalf("direct attempts = %v, want %v", directAttempts, wantAttempts)
	}
	for i := range wantAttempts {
		if directAttempts[i] != wantAttempts[i] {
			t.Fatalf("direct attempts = %v, want %v", directAttempts, wantAttempts)
		}
	}
	if !route.System || route.Label != "системный DNS устройства" {
		t.Fatalf("route = %+v, want system resolver", route)
	}
	if systemAttempts != 1 {
		t.Fatalf("system attempts = %d, want 1", systemAttempts)
	}
	if len(probes) != len(wantAttempts)+1 {
		t.Fatalf("probes = %d, want %d", len(probes), len(wantAttempts)+1)
	}
}

func TestLookupHostRequiresDNSResponseFromConnectedSocket(t *testing.T) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = io.Copy(io.Discard, server)
			}()
			return client, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	if err := lookupHostWithResolver(ctx, resolver, dnsProbeHost); err == nil {
		t.Fatal("connected DNS socket without a response was treated as working")
	}
}

func TestSummarizeDNSFailuresSkipsSystemWhenRequested(t *testing.T) {
	probes := []dnsRouteProbe{
		{Route: dnsRoute{Label: "77.88.8.8 UDP"}, Err: errors.New("timeout")},
		{Route: dnsRoute{Label: "системный DNS устройства", System: true}, Err: nil},
	}
	got := summarizeDNSFailures(probes, false)
	if got != "77.88.8.8 UDP: timeout" {
		t.Fatalf("summary = %q", got)
	}
}

func TestShortDNSErrorLimitsLongText(t *testing.T) {
	long := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
	got := shortDNSError(errors.New(long))
	if len(got) > 123 {
		t.Fatalf("short error too long: %d", len(got))
	}
}

func TestParsePeerEndpointAcceptsIPv4AndHostname(t *testing.T) {
	literal, err := parsePeerEndpoint("192.0.2.7:443")
	if err != nil || literal.Literal == nil || literal.Port != 443 {
		t.Fatalf("literal = %+v, err = %v", literal, err)
	}
	hostname, err := parsePeerEndpoint("example.com:51820")
	if err != nil || hostname.Literal != nil || hostname.Host != "example.com" || hostname.Port != 51820 {
		t.Fatalf("hostname = %+v, err = %v", hostname, err)
	}
}

func TestParsePeerEndpointRejectsPermanentConfigurationErrors(t *testing.T) {
	for _, value := range []string{"example.com", "example.com:0", "[2001:db8::1]:443", ":443"} {
		if _, err := parsePeerEndpoint(value); err == nil {
			t.Fatalf("parsePeerEndpoint(%q) succeeded", value)
		}
	}
}

func TestResolvePeerUDPAddrFallsBackToAnotherResolverAndRequiresIPv4(t *testing.T) {
	endpoint, err := parsePeerEndpoint("example.com:51820")
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	peer, err := resolvePeerUDPAddrOnceWithLookups(
		context.Background(),
		endpoint,
		[]peerIPLookup{
			func(context.Context, string) ([]net.IPAddr, error) {
				attempts++
				return nil, context.DeadlineExceeded
			},
			func(context.Context, string) ([]net.IPAddr, error) {
				attempts++
				return []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, nil
			},
			func(context.Context, string) ([]net.IPAddr, error) {
				attempts++
				return []net.IPAddr{{IP: net.ParseIP("192.0.2.9")}}, nil
			},
		},
	)
	if err != nil || peer.String() != "192.0.2.9:51820" || attempts != 3 {
		t.Fatalf("peer = %v, attempts = %d, err = %v", peer, attempts, err)
	}
}

func TestWaitForPeerUDPAddrSurvivesTransientDNSFailure(t *testing.T) {
	endpoint, err := parsePeerEndpoint("example.com:51820")
	if err != nil {
		t.Fatal(err)
	}
	resolveAttempts := 0
	waits := 0
	warnings := 0
	peer, failures, err := waitForPeerUDPAddrWith(
		context.Background(),
		endpoint,
		func(context.Context, peerEndpoint) (*net.UDPAddr, error) {
			resolveAttempts++
			if resolveAttempts < 3 {
				return nil, errors.New("temporary DNS outage")
			}
			return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820}, nil
		},
		func(context.Context, time.Duration) error {
			waits++
			return nil
		},
		func(int, error) { warnings++ },
	)
	if err != nil || peer.String() != "192.0.2.10:51820" || failures != 2 {
		t.Fatalf("peer = %v, failures = %d, err = %v", peer, failures, err)
	}
	if resolveAttempts != 3 || waits != 2 || warnings != 2 {
		t.Fatalf("resolve=%d waits=%d warnings=%d", resolveAttempts, waits, warnings)
	}
}

func TestWaitForPeerUDPAddrStopsWhenContextIsCancelled(t *testing.T) {
	endpoint, err := parsePeerEndpoint("example.com:51820")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	resolveAttempts := 0
	_, _, err = waitForPeerUDPAddrWith(
		ctx,
		endpoint,
		func(context.Context, peerEndpoint) (*net.UDPAddr, error) {
			resolveAttempts++
			return nil, errors.New("temporary DNS outage")
		},
		func(context.Context, time.Duration) error {
			cancel()
			return context.Canceled
		},
		nil,
	)
	if !errors.Is(err, context.Canceled) || resolveAttempts != 1 {
		t.Fatalf("attempts = %d, err = %v", resolveAttempts, err)
	}
}
