package main

import "testing"

func TestParseTURNEndpointPreservesTransport(t *testing.T) {
	tests := []struct {
		raw       string
		host      string
		port      string
		transport turnTransport
	}{
		{"turn:1.2.3.4:3478?transport=udp", "1.2.3.4", "3478", turnTransportUDP},
		{"turn:turn.example:443?transport=tcp", "turn.example", "443", turnTransportTCP},
		{"turns:turn.example:443?transport=tcp", "turn.example", "443", turnTransportTLS},
		{"turn.example:3478", "turn.example", "3478", turnTransportUDP},
	}
	for _, tt := range tests {
		got, err := parseTURNEndpoint(tt.raw)
		if err != nil {
			t.Fatalf("parseTURNEndpoint(%q) error: %v", tt.raw, err)
		}
		if got.Host != tt.host || got.Port != tt.port || got.Transport != tt.transport {
			t.Fatalf("parseTURNEndpoint(%q) = host=%q port=%q transport=%q", tt.raw, got.Host, got.Port, got.Transport)
		}
	}
}

func TestSessionTURNCandidatesKeepLegacyUDPFirst(t *testing.T) {
	raw := []string{
		"turns:turn.example:443?transport=tcp",
		"turn:1.2.3.4:3478?transport=udp",
		"turn:turn.example:3478?transport=tcp",
	}
	got := sessionTURNCandidates(raw, 0, nil)
	want := []struct {
		host      string
		port      string
		transport turnTransport
		legacyUDP bool
	}{
		{"turn.example", "443", turnTransportUDP, true},
		{"1.2.3.4", "3478", turnTransportUDP, true},
		{"turn.example", "3478", turnTransportUDP, true},
		{"turn.example", "443", turnTransportTLS, false},
		{"turn.example", "3478", turnTransportTCP, false},
	}
	if len(got) != len(want) {
		t.Fatalf("normal-mode candidates=%#v, want %d entries", got, len(want))
	}
	for index, expected := range want {
		actual := got[index]
		if actual.Host != expected.host || actual.Port != expected.port ||
			actual.Transport != expected.transport || actual.LegacyUDP != expected.legacyUDP {
			t.Fatalf("normal-mode candidate[%d]=%#v, want %#v", index, actual, expected)
		}
	}
}

func TestSessionTURNCandidatesPreferStreamForRtMode(t *testing.T) {
	raw := []string{
		"turn:turn.example:443?transport=tcp",
		"turn:1.2.3.4:3478?transport=udp",
		"turns:turn.example:443?transport=tcp",
	}
	got := sessionTURNCandidatesWithPreference(raw, 0, nil, true)
	if len(got) < 3 {
		t.Fatalf("not enough candidates: %#v", got)
	}
	if got[0].Transport != turnTransportTLS || got[0].LegacyUDP {
		t.Fatalf("first candidate must be the real TLS transport, got %#v", got[0])
	}
	if got[1].Transport != turnTransportTCP || got[1].LegacyUDP {
		t.Fatalf("second candidate must be the real TCP transport, got %#v", got[1])
	}
	if got[len(got)-1].Transport != turnTransportUDP || !got[len(got)-1].LegacyUDP {
		t.Fatalf("legacy UDP candidates must remain as a final fallback, got %#v", got)
	}
}

func TestSessionTURNCandidatesPreferStreamSynthesizesTCPFromUDPURL(t *testing.T) {
	got := sessionTURNCandidatesWithPreference(
		[]string{"turn:1.2.3.4:3478?transport=udp"},
		0,
		nil,
		true,
	)
	if len(got) != 2 {
		t.Fatalf("expected synthetic TCP plus UDP fallback, got %#v", got)
	}
	if got[0].Transport != turnTransportTCP || got[0].Host != "1.2.3.4" || got[0].Port != "3478" {
		t.Fatalf("first candidate must be synthetic TCP to the VK TURN address, got %#v", got[0])
	}
	if got[1].Transport != turnTransportUDP || !got[1].LegacyUDP {
		t.Fatalf("last candidate must preserve UDP fallback, got %#v", got[1])
	}
}

func TestSessionTURNCandidatesNormalModeDoesNotSynthesizeTCP(t *testing.T) {
	got := sessionTURNCandidatesWithPreference(
		[]string{"turn:1.2.3.4:3478?transport=udp"},
		0,
		nil,
		false,
	)
	if len(got) != 1 || got[0].Transport != turnTransportUDP || !got[0].LegacyUDP {
		t.Fatalf("normal mode must keep the historical UDP-only candidate, got %#v", got)
	}
}

func TestSessionTURNCandidatesApplyOverride(t *testing.T) {
	got := sessionTURNCandidates(
		[]string{"turn:old.example:3478?transport=udp", "turn:new.example:443?transport=tcp"},
		0,
		&TurnParams{Host: "override.example", Port: "5555"},
	)
	if len(got) == 0 {
		t.Fatal("no candidates")
	}
	for _, endpoint := range got {
		if endpoint.Host != "override.example" || endpoint.Port != "5555" {
			t.Fatalf("override not applied: %#v", endpoint)
		}
	}
}
