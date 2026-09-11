package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestValidateProxyListenAddressRequiresScopedAuthenticatedLAN(t *testing.T) {
	address, policy, err := validateProxyListenAddress(
		"192.168.50.1:1080",
		"192.168.50.0/24",
		true,
	)
	if err != nil || address != "192.168.50.1:1080" || !policy.allowedPrefix.IsValid() {
		t.Fatalf("safe LAN binding rejected: %q, %#v, %v", address, policy, err)
	}
	for name, input := range map[string]struct {
		listen string
		cidr   string
		auth   bool
	}{
		"wildcard":       {"0.0.0.0:1080", "192.168.50.0/24", true},
		"public":         {"203.0.113.2:1080", "203.0.113.0/24", true},
		"without auth":   {"192.168.50.1:1080", "192.168.50.0/24", false},
		"outside subnet": {"192.168.51.1:1080", "192.168.50.0/24", true},
		"wide subnet":    {"10.1.2.3:1080", "10.0.0.0/8", true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validateProxyListenAddress(input.listen, input.cidr, input.auth); err == nil {
				t.Fatal("unsafe LAN binding accepted")
			}
		})
	}
}

func TestProxyAccessPolicyLimitsClientSubnet(t *testing.T) {
	_, policy, err := validateProxyListenAddress("192.168.50.1:1080", "192.168.50.0/24", true)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.allows(&net.TCPAddr{IP: net.ParseIP("192.168.50.42"), Port: 1234}) {
		t.Fatal("same-subnet client rejected")
	}
	if policy.allows(&net.TCPAddr{IP: net.ParseIP("192.168.51.42"), Port: 1234}) {
		t.Fatal("foreign-subnet client accepted")
	}
}

func TestHTTPConnectRelaysTCP(t *testing.T) {
	echo := startTCPEchoServer(t)
	defer echo.Close()
	server := &httpConnectServer{
		dialer:      systemSocksDialer{},
		authEnabled: true,
		username:    "user",
		password:    "secret",
	}
	client, proxy := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.serveClient(context.Background(), proxy) }()

	target := echo.Addr().String()
	auth := base64.StdEncoding.EncodeToString([]byte("user:secret"))
	if _, err := fmt.Fprintf(
		client,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		target,
		target,
		auth,
	); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %#v, %v", response, err)
	}
	_ = response.Body.Close()
	if _, err := client.Write([]byte("tcp-through-http-connect")); err != nil {
		t.Fatal(err)
	}
	assertReadBytes(t, client, []byte("tcp-through-http-connect"))
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP CONNECT relay did not stop")
	}
}

func TestHTTPConnectAuthenticationAndMethodChecks(t *testing.T) {
	server := &httpConnectServer{
		dialer:      systemSocksDialer{},
		authEnabled: true,
		username:    "user",
		password:    "secret",
	}
	for name, testCase := range map[string]struct {
		request string
		status  int
	}{
		"missing auth": {"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n", http.StatusProxyAuthRequired},
		"wrong method": {"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", http.StatusMethodNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			client, proxy := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- server.serveClient(context.Background(), proxy) }()
			_, _ = io.WriteString(client, testCase.request)
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{})
			if err != nil || response.StatusCode != testCase.status {
				t.Fatalf("status = %#v, %v; want %d", response, err, testCase.status)
			}
			_ = response.Body.Close()
			_ = client.Close()
			<-done
		})
	}
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	invalid := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:bad"))
	if !server.validAuthorization(valid) || server.validAuthorization(invalid) {
		t.Fatal("Basic proxy authentication validation failed")
	}
}

func TestHTTPConnectHeaderLimit(t *testing.T) {
	reader := &boundedHeaderReader{
		reader:    strings.NewReader(strings.Repeat("a", httpConnectMaxHeaderBytes+1)),
		remaining: httpConnectMaxHeaderBytes,
	}
	data, err := io.ReadAll(reader)
	if err == nil || len(data) != httpConnectMaxHeaderBytes {
		t.Fatalf("bounded read = %d bytes, %v", len(data), err)
	}
}
