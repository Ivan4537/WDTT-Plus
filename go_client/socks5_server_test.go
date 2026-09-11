package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type deadlineRecordingConn struct {
	net.Conn
	deadlines []time.Time
}

func (connection *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	connection.deadlines = append(connection.deadlines, deadline)
	return connection.Conn.SetDeadline(deadline)
}

type systemSocksDialer struct{}

func (systemSocksDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (systemSocksDialer) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func TestValidateSocksListenAddressLoopbackOnly(t *testing.T) {
	if got, err := validateSocksListenAddress("127.0.0.1:1080"); err != nil || got != "127.0.0.1:1080" {
		t.Fatalf("loopback rejected: %q, %v", got, err)
	}
	for _, value := range []string{"0.0.0.0:1080", "192.0.2.1:1080", "[::1]:1080", "127.0.0.1:0"} {
		if _, err := validateSocksListenAddress(value); err == nil {
			t.Fatalf("unsafe listen address accepted: %s", value)
		}
	}
}

func TestSocksPasswordAuthentication(t *testing.T) {
	server := &socks5Server{authEnabled: true, username: "user", password: "secret"}
	for name, password := range map[string]string{"valid": "secret", "invalid": "wrong"} {
		t.Run(name, func(t *testing.T) {
			request := []byte{socksVersion5, 1, socksAuthPassword, 1, 4}
			request = append(request, []byte("user")...)
			request = append(request, byte(len(password)))
			request = append(request, []byte(password)...)
			reader := bytes.NewReader(request)
			var response bytes.Buffer
			err := server.negotiateAuthentication(bufio.NewReader(reader), &response)
			if name == "valid" && err != nil {
				t.Fatalf("valid credentials rejected: %v", err)
			}
			if name == "invalid" && err == nil {
				t.Fatal("invalid credentials accepted")
			}
			if got := response.Bytes(); len(got) != 4 || got[1] != socksAuthPassword || (name == "valid" && got[3] != 0) {
				t.Fatalf("unexpected auth response: %v", got)
			}
		})
	}
}

func TestSocksConnectRelaysTCP(t *testing.T) {
	echo := startTCPEchoServer(t)
	defer echo.Close()
	server := &socks5Server{dialer: systemSocksDialer{}}
	client, proxy := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.serveClient(context.Background(), proxy) }()

	client.Write([]byte{socksVersion5, 1, socksAuthNone})
	assertReadBytes(t, client, []byte{socksVersion5, socksAuthNone})
	port := uint16(echo.Addr().(*net.TCPAddr).Port)
	request := []byte{socksVersion5, socksCommandConnect, 0, socksAddressIPv4, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], port)
	client.Write(request)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != socksReplyOK {
		t.Fatalf("CONNECT reply = %v, %v", reply, err)
	}
	client.Write([]byte("tcp-through-socks"))
	assertReadBytes(t, client, []byte("tcp-through-socks"))
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP relay did not stop")
	}
}

func TestSocksClientHandshakeDeadlineIsClearedAfterRequest(t *testing.T) {
	client, rawProxy := net.Pipe()
	proxy := &deadlineRecordingConn{Conn: rawProxy}
	done := make(chan error, 1)
	go func() { done <- (&socks5Server{}).serveClient(context.Background(), proxy) }()

	if _, err := client.Write([]byte{socksVersion5, 1, socksAuthNone}); err != nil {
		t.Fatal(err)
	}
	assertReadBytes(t, client, []byte{socksVersion5, socksAuthNone})
	request := []byte{socksVersion5, 0x02, 0, socksAddressIPv4, 127, 0, 0, 1, 0, 80}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := <-done; err == nil {
		t.Fatal("unsupported request unexpectedly succeeded")
	}
	if len(proxy.deadlines) != 2 || proxy.deadlines[0].IsZero() || !proxy.deadlines[1].IsZero() {
		t.Fatalf("handshake deadlines = %v, want non-zero then cleared", proxy.deadlines)
	}
}

func TestSocksUDPAssociateRelaysDatagram(t *testing.T) {
	echo := startUDPEchoServer(t)
	defer echo.Close()
	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	server := &socks5Server{dialer: systemSocksDialer{}, udpEnabled: true}
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := proxyListener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		serverDone <- server.serveClient(context.Background(), connection)
	}()

	control, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	control.Write([]byte{socksVersion5, 1, socksAuthNone})
	assertReadBytes(t, control, []byte{socksVersion5, socksAuthNone})
	control.Write([]byte{socksVersion5, socksCommandUDP, 0, socksAddressIPv4, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil || reply[1] != socksReplyOK {
		t.Fatalf("UDP ASSOCIATE reply = %v, %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	udpClient, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	packet, err := buildSocksUDPDatagram(echo.LocalAddr().(*net.UDPAddr), []byte("udp-through-socks"))
	if err != nil {
		t.Fatal(err)
	}
	udpClient.Write(packet)
	_ = udpClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 1024)
	size, err := udpClient.Read(response)
	if err != nil {
		t.Fatalf("UDP response: %v", err)
	}
	_, payload, err := parseSocksUDPDatagram(response[:size])
	if err != nil || string(payload) != "udp-through-socks" {
		t.Fatalf("UDP payload = %q, %v", payload, err)
	}
	control.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP association did not stop with control connection")
	}
}

func TestSocksUDPRejectsFragmentation(t *testing.T) {
	packet := []byte{0, 0, 1, socksAddressIPv4, 127, 0, 0, 1, 0, 53, 1}
	if _, _, err := parseSocksUDPDatagram(packet); err == nil {
		t.Fatal("fragmented SOCKS UDP packet accepted")
	}
}

func TestPrepareSocksUDPFlowSlotRemovesStaleAndOldestFlows(t *testing.T) {
	now := time.Now()
	flows := make(map[string]*socksUDPFlow, socksMaxUDPFlows)
	peers := make([]net.Conn, 0, socksMaxUDPFlows)
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
		for _, flow := range flows {
			_ = flow.connection.Close()
		}
	}()
	for index := 0; index < socksMaxUDPFlows; index++ {
		flow, peer := net.Pipe()
		peers = append(peers, peer)
		lastUsed := now.Add(-time.Duration(index+1) * time.Second)
		if index == 0 {
			lastUsed = now.Add(-socksUDPFlowIdle)
		}
		flows[fmt.Sprintf("flow-%d", index)] = &socksUDPFlow{
			connection: flow,
			lastUsed:   lastUsed,
		}
	}

	prepareSocksUDPFlowSlot(flows, now)

	if len(flows) != socksMaxUDPFlows-1 {
		t.Fatalf("flow count = %d, want %d", len(flows), socksMaxUDPFlows-1)
	}
	if _, exists := flows["flow-0"]; exists {
		t.Fatal("stale flow was not removed")
	}

	newFlow, newPeer := net.Pipe()
	peers = append(peers, newPeer)
	flows["replacement"] = &socksUDPFlow{connection: newFlow, lastUsed: now}
	prepareSocksUDPFlowSlot(flows, now)
	if len(flows) != socksMaxUDPFlows-1 {
		t.Fatalf("full flow table was not reduced: %d", len(flows))
	}
	if _, exists := flows["flow-63"]; exists {
		t.Fatal("oldest flow was not evicted")
	}
}

func startTCPEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener
}

func startUDPEchoServer(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buffer := make([]byte, 2048)
		for {
			size, source, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = connection.WriteToUDP(buffer[:size], source)
		}
	}()
	return connection
}

func assertReadBytes(t *testing.T, reader io.Reader, expected []byte) {
	t.Helper()
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, actual); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("read %v, want %v", actual, expected)
	}
}
