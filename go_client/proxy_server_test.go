package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestValidateProxyListenAddressesAllowsExactLoopbackAndLAN(t *testing.T) {
	addresses, policies, err := validateProxyListenAddresses(
		[]string{"127.0.0.1:1080", "192.168.50.1:1080"},
		"192.168.50.0/24",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || len(policies) != 2 {
		t.Fatalf("addresses=%v policies=%v", addresses, policies)
	}
	if !policies[0].listenIP.IsLoopback() || !policies[1].allowedPrefix.IsValid() {
		t.Fatalf("unexpected policies: %#v", policies)
	}
}

func TestValidateProxyListenAddressesRejectsUnsafeCombinations(t *testing.T) {
	for name, testCase := range map[string]struct {
		addresses []string
		cidr      string
		auth      bool
	}{
		"duplicate": {
			[]string{"127.0.0.1:1080", "127.0.0.1:1080"}, "", false,
		},
		"wildcard": {
			[]string{"0.0.0.0:1080"}, "192.168.50.0/24", true,
		},
		"LAN without auth": {
			[]string{"127.0.0.1:1080", "192.168.50.1:1080"}, "192.168.50.0/24", false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validateProxyListenAddresses(
				testCase.addresses,
				testCase.cidr,
				testCase.auth,
			); err == nil {
				t.Fatal("unsafe listener combination accepted")
			}
		})
	}
}

func TestAutoProxyDetectsSOCKSAndHTTPWithoutWaitingForMoreData(t *testing.T) {
	for name, greeting := range map[string][]byte{
		"SOCKS5": {socksVersion5},
		"HTTP":   []byte("CONNECT example.test:443 HTTP/1.1\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			client, proxy := net.Pipe()
			defer client.Close()
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- serveUnifiedProxyClient(
					ctx, "auto", proxy, proxyAccessPolicy{}, systemSocksDialer{},
					false, "", "", true,
				)
			}()
			if _, err := client.Write(greeting); err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("auto protocol selection waited beyond its handshake")
			}
		})
	}
}

func TestAutoProxyRejectsUnknownGreeting(t *testing.T) {
	client, proxy := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serveUnifiedProxyClient(
			context.Background(), "auto", proxy, proxyAccessPolicy{}, systemSocksDialer{},
			false, "", "", true,
		)
	}()
	_, _ = client.Write([]byte{0x04})
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("unknown proxy protocol accepted")
	}
}

func TestAutoProxyServesAuthenticatedHTTPFromAllowedLAN(t *testing.T) {
	echo := startTCPEchoServer(t)
	defer echo.Close()
	_, access, err := validateProxyListenAddress(
		"192.168.50.1:1080",
		"192.168.50.0/24",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	lanProxy := &proxyTestRemoteConn{
		Conn: proxy,
		remote: &net.TCPAddr{
			IP:   net.ParseIP("192.168.50.42"),
			Port: 43210,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveUnifiedProxyClient(
			ctx,
			"auto",
			lanProxy,
			access,
			systemSocksDialer{},
			true,
			"wdtt",
			"secret",
			true,
		)
	}()
	target := echo.Addr().String()
	auth := base64.StdEncoding.EncodeToString([]byte("wdtt:secret"))
	if _, err = fmt.Fprintf(
		client,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		target,
		target,
		auth,
	); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(
		bufio.NewReader(client),
		&http.Request{Method: http.MethodConnect},
	)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %#v, %v", response, err)
	}
	_ = response.Body.Close()
	if err = echoRoundTrip(client, "auto-http-from-lan"); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case err = <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("authenticated HTTP client did not finish")
	}
}

func TestAutoProxyServesConcurrentSOCKSAndHTTPOnOnePort(t *testing.T) {
	echo := startTCPEchoServer(t)
	defer echo.Close()
	ctx, cancel := context.WithCancel(context.Background())
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := reserved.Addr().String()
	_ = reserved.Close()
	_, proxyPort, err := net.SplitHostPort(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	secondProxyAddress := net.JoinHostPort("127.0.0.2", proxyPort)
	ready := make(chan []string, 1)
	done := make(chan error, 1)
	go func() {
		done <- runUnifiedProxyServer(
			ctx,
			"auto",
			[]string{proxyAddress, secondProxyAddress},
			systemSocksDialer{},
			false,
			"",
			"",
			true,
			"",
			func(addresses []string) { ready <- addresses },
		)
	}()
	select {
	case addresses := <-ready:
		if len(addresses) != 2 {
			t.Fatalf("ready addresses=%v", addresses)
		}
	case err = <-done:
		t.Fatalf("auto proxy failed before ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("auto proxy did not become ready")
	}

	var clients sync.WaitGroup
	errorsCh := make(chan error, 16)
	for index := 0; index < 8; index++ {
		index := index
		selectedAddress := proxyAddress
		if index%2 == 1 {
			selectedAddress = secondProxyAddress
		}
		clients.Add(2)
		go func() {
			defer clients.Done()
			errorsCh <- autoHTTPRoundTrip(selectedAddress, echo.Addr().String(), fmt.Sprintf("http-%d", index))
		}()
		go func() {
			defer clients.Done()
			errorsCh <- autoSocksRoundTrip(selectedAddress, echo.Addr().String(), fmt.Sprintf("socks-%d", index))
		}()
	}
	clients.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("auto proxy did not stop")
	}
}

func autoHTTPRoundTrip(proxyAddress, target, payload string) error {
	connection, err := net.Dial("tcp4", proxyAddress)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err = fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP CONNECT status=%d", response.StatusCode)
	}
	return echoRoundTrip(connection, payload)
}

func autoSocksRoundTrip(proxyAddress, target, payload string) error {
	connection, err := net.Dial("tcp4", proxyAddress)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err = connection.Write([]byte{socksVersion5, 1, socksAuthNone}); err != nil {
		return err
	}
	var authReply [2]byte
	if _, err = io.ReadFull(connection, authReply[:]); err != nil || authReply != [2]byte{socksVersion5, socksAuthNone} {
		return fmt.Errorf("SOCKS auth reply=%v err=%v", authReply, err)
	}
	targetAddress, err := net.ResolveTCPAddr("tcp4", target)
	if err != nil {
		return err
	}
	request := []byte{socksVersion5, socksCommandConnect, 0, socksAddressIPv4}
	request = append(request, targetAddress.IP.To4()...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(targetAddress.Port))
	request = append(request, port[:]...)
	if _, err = connection.Write(request); err != nil {
		return err
	}
	var reply [10]byte
	if _, err = io.ReadFull(connection, reply[:]); err != nil || reply[1] != socksReplyOK {
		return fmt.Errorf("SOCKS CONNECT reply=%v err=%v", reply, err)
	}
	return echoRoundTrip(connection, payload)
}

func echoRoundTrip(connection net.Conn, payload string) error {
	if _, err := connection.Write([]byte(payload)); err != nil {
		return err
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		return err
	}
	if string(received) != payload {
		return fmt.Errorf("echo=%q want=%q", received, payload)
	}
	return nil
}

type proxyTestRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (connection *proxyTestRemoteConn) RemoteAddr() net.Addr {
	return connection.remote
}
