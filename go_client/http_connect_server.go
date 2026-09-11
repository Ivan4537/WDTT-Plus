package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

const httpConnectMaxHeaderBytes = 16 * 1024

type httpConnectServer struct {
	dialer      socks5Dialer
	access      proxyAccessPolicy
	authEnabled bool
	username    string
	password    string
}

func runHTTPConnectServer(
	ctx context.Context,
	listenAddress string,
	tunnelNetwork *netstack.Net,
	authEnabled bool,
	username string,
	password string,
	allowedCIDR string,
	onReady func(string),
) error {
	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	validatedAddress, access, err := validateProxyListenAddress(listenAddress, allowedCIDR, authEnabled)
	if err != nil {
		return err
	}
	if authEnabled && (username == "" || password == "" || len(username) > 255 || len(password) > 255) {
		return fmt.Errorf("для HTTP-аутентификации нужны логин и пароль длиной до 255 байт")
	}
	listener, err := net.Listen("tcp4", validatedAddress)
	if err != nil {
		return fmt.Errorf("HTTP CONNECT не смог занять %s: %w", validatedAddress, err)
	}
	defer listener.Close()
	server := &httpConnectServer{
		dialer:      netstackSocksDialer{network: tunnelNetwork},
		access:      access,
		authEnabled: authEnabled,
		username:    username,
		password:    password,
	}
	go func() {
		<-serverCtx.Done()
		_ = listener.Close()
	}()
	if onReady != nil {
		onReady(listener.Addr().String())
	}

	var clients sync.WaitGroup
	clientSlots := make(chan struct{}, 64)
	defer clients.Wait()
	for {
		client, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("приём HTTP-клиента: %w", acceptErr)
		}
		select {
		case clientSlots <- struct{}{}:
		default:
			_ = client.Close()
			continue
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer func() { <-clientSlots }()
			defer client.Close()
			stopClosingClient := context.AfterFunc(serverCtx, func() { _ = client.Close() })
			defer stopClosingClient()
			_ = server.serveClient(serverCtx, client)
		}()
	}
}

func (server *httpConnectServer) serveClient(ctx context.Context, client net.Conn) error {
	if !server.access.allows(client.RemoteAddr()) {
		return fmt.Errorf("HTTP-клиент вне разрешённой подсети")
	}
	if err := client.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return err
	}
	limited := &boundedHeaderReader{reader: client, remaining: httpConnectMaxHeaderBytes}
	reader := bufio.NewReaderSize(limited, 4096)
	request, err := http.ReadRequest(reader)
	if err != nil {
		_ = writeHTTPProxyResponse(client, http.StatusBadRequest, "Некорректный запрос")
		return fmt.Errorf("некорректный HTTP-запрос: %w", err)
	}
	defer request.Body.Close()
	if request.Method != http.MethodConnect {
		_ = writeHTTPProxyResponse(client, http.StatusMethodNotAllowed, "Поддерживается только CONNECT")
		return fmt.Errorf("HTTP-метод %s не поддерживается", request.Method)
	}
	if server.authEnabled && !server.validAuthorization(request.Header.Get("Proxy-Authorization")) {
		_, _ = io.WriteString(
			client,
			"HTTP/1.1 407 Proxy Authentication Required\r\n"+
				"Proxy-Authenticate: Basic realm=\"WDTT Plus\"\r\n"+
				"Connection: close\r\nContent-Length: 0\r\n\r\n",
		)
		return fmt.Errorf("неверный логин или пароль HTTP-прокси")
	}
	target, err := server.resolveTarget(ctx, request.Host)
	if err != nil {
		_ = writeHTTPProxyResponse(client, http.StatusBadGateway, "Узел недоступен")
		return err
	}
	upstream, err := server.dialer.DialContext(ctx, "tcp4", target)
	if err != nil {
		_ = writeHTTPProxyResponse(client, http.StatusBadGateway, "Узел недоступен")
		return err
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if err := client.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	buffered, err := reader.Peek(reader.Buffered())
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
		return err
	}
	return relayHTTPConnect(client, upstream, append([]byte(nil), buffered...))
}

func (server *httpConnectServer) resolveTarget(ctx context.Context, authority string) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err != nil || host == "" {
		return "", fmt.Errorf("CONNECT требует адрес вида host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("некорректный порт CONNECT")
	}
	return (&socks5Server{dialer: server.dialer}).resolveIPv4(ctx, host, uint16(port))
}

func (server *httpConnectServer) validAuthorization(value string) bool {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(username), []byte(server.username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(server.password)) == 1
}

func writeHTTPProxyResponse(writer io.Writer, status int, message string) error {
	body := message + "\n"
	_, err := fmt.Fprintf(
		writer,
		"HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
		status,
		http.StatusText(status),
		len([]byte(body)),
		body,
	)
	return err
}

func relayHTTPConnect(client, upstream net.Conn, buffered []byte) error {
	errorsCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, io.MultiReader(bytes.NewReader(buffered), client))
		if closer, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errorsCh <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		if closer, ok := client.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errorsCh <- err
	}()
	first := <-errorsCh
	second := <-errorsCh
	if first != nil && !errors.Is(first, net.ErrClosed) {
		return first
	}
	return second
}

type boundedHeaderReader struct {
	reader    io.Reader
	remaining int
}

func (reader *boundedHeaderReader) Read(buffer []byte) (int, error) {
	if reader.remaining <= 0 {
		return 0, fmt.Errorf("HTTP-заголовок превышает %d байт", httpConnectMaxHeaderBytes)
	}
	if len(buffer) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	read, err := reader.reader.Read(buffer)
	reader.remaining -= read
	return read, err
}
