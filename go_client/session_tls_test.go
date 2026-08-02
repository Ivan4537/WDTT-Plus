package main

import (
	"net"
	"testing"
	"time"
)

type recordingConn struct {
	writes [][]byte
}

func (conn *recordingConn) Read(_ []byte) (int, error)         { return 0, nil }
func (conn *recordingConn) Close() error                       { return nil }
func (conn *recordingConn) LocalAddr() net.Addr                { return nil }
func (conn *recordingConn) RemoteAddr() net.Addr               { return nil }
func (conn *recordingConn) SetDeadline(_ time.Time) error      { return nil }
func (conn *recordingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (conn *recordingConn) SetWriteDeadline(_ time.Time) error { return nil }

func (conn *recordingConn) Write(payload []byte) (int, error) {
	copyOfPayload := append([]byte(nil), payload...)
	conn.writes = append(conn.writes, copyOfPayload)
	return len(payload), nil
}

func TestNormalizeTURNFrontSNI(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{input: " Ya.RU ", want: "ya.ru", ok: true},
		{input: "telemost.yandex.ru", want: "telemost.yandex.ru", ok: true},
		{input: "", want: "", ok: true},
		{input: "ya", ok: false},
		{input: "127.0.0.1", ok: false},
		{input: "я.рф", ok: false},
		{input: "-ya.ru", ok: false},
		{input: "ya..ru", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeTURNFrontSNI(tt.input)
			if (err == nil) != tt.ok {
				t.Fatalf("normalizeTURNFrontSNI(%q) error=%v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeTURNFrontSNI(%q)=%q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTurnTLSConfigUsesFrontSNIWithoutDisablingChainCheck(t *testing.T) {
	endpoint := turnEndpoint{Host: "turn.example", Port: "443", Transport: turnTransportTLS}
	config := turnTLSConfig(endpoint, "ya.ru")
	if config.ServerName != "ya.ru" {
		t.Fatalf("ServerName=%q, want ya.ru", config.ServerName)
	}
	if !config.InsecureSkipVerify || config.VerifyConnection == nil {
		t.Fatal("front SNI must replace hostname matching with explicit CA-chain verification")
	}

	normal := turnTLSConfig(endpoint, "")
	if normal.ServerName != "turn.example" || normal.InsecureSkipVerify || normal.VerifyConnection != nil {
		t.Fatalf("normal TLS verification changed unexpectedly: %#v", normal)
	}
}

func TestSplitFirstWriteConnOnlySplitsFirstWrite(t *testing.T) {
	underlying := &recordingConn{}
	conn := &splitFirstWriteConn{Conn: underlying, splitAt: 6}

	first := []byte("0123456789")
	if n, err := conn.Write(first); err != nil || n != len(first) {
		t.Fatalf("first Write() = (%d, %v), want (%d, nil)", n, err, len(first))
	}
	second := []byte("abcdef")
	if n, err := conn.Write(second); err != nil || n != len(second) {
		t.Fatalf("second Write() = (%d, %v), want (%d, nil)", n, err, len(second))
	}

	if len(underlying.writes) != 3 {
		t.Fatalf("underlying writes=%q, want three writes", underlying.writes)
	}
	if got := string(underlying.writes[0]); got != "012345" {
		t.Fatalf("first fragment=%q, want %q", got, "012345")
	}
	if got := string(underlying.writes[1]); got != "6789" {
		t.Fatalf("second fragment=%q, want %q", got, "6789")
	}
	if got := string(underlying.writes[2]); got != "abcdef" {
		t.Fatalf("subsequent write=%q, want %q", got, "abcdef")
	}
}
