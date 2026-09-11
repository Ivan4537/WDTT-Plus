package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const proxyMaxClients = 64

type proxyListener struct {
	listener net.Listener
	access   proxyAccessPolicy
}

type bufferedProxyConn struct {
	net.Conn
	reader io.Reader
}

func (connection *bufferedProxyConn) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}

func validateProxyListenAddresses(
	values []string,
	allowedCIDR string,
	authEnabled bool,
) ([]string, []proxyAccessPolicy, error) {
	if len(values) == 0 {
		return nil, nil, fmt.Errorf("не указан адрес прокси")
	}
	addresses := make([]string, 0, len(values))
	policies := make([]proxyAccessPolicy, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		host, _, err := net.SplitHostPort(strings.TrimSpace(value))
		if err != nil {
			return nil, nil, fmt.Errorf("адрес прокси: %w", err)
		}
		parsedHost, err := netip.ParseAddr(host)
		if err != nil {
			return nil, nil, fmt.Errorf("некорректный IPv4-адрес прокси")
		}
		cidr := allowedCIDR
		if parsedHost.IsLoopback() {
			cidr = ""
		}
		address, policy, err := validateProxyListenAddress(value, cidr, authEnabled)
		if err != nil {
			return nil, nil, err
		}
		if _, duplicate := seen[address]; duplicate {
			return nil, nil, fmt.Errorf("адрес прокси указан повторно: %s", address)
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
		policies = append(policies, policy)
	}
	return addresses, policies, nil
}

// runUnifiedProxyServer owns every local listener for one WDTT userspace tunnel.
// The semaphore is intentionally shared by all addresses and protocols so the
// Auto + Both combination cannot multiply the client limit.
func runUnifiedProxyServer(
	ctx context.Context,
	mode string,
	listenAddresses []string,
	dialer socks5Dialer,
	authEnabled bool,
	username string,
	password string,
	udpEnabled bool,
	allowedCIDR string,
	onReady func([]string),
) error {
	if mode != "socks5" && mode != "http" && mode != "auto" {
		return fmt.Errorf("неподдерживаемый режим прокси: %s", mode)
	}
	if authEnabled && (username == "" || password == "" || len(username) > 255 || len(password) > 255) {
		return fmt.Errorf("для аутентификации прокси нужны логин и пароль длиной до 255 байт")
	}
	addresses, policies, err := validateProxyListenAddresses(
		listenAddresses,
		allowedCIDR,
		authEnabled,
	)
	if err != nil {
		return err
	}

	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	listeners := make([]proxyListener, 0, len(addresses))
	for index, address := range addresses {
		listener, listenErr := net.Listen("tcp4", address)
		if listenErr != nil {
			for _, opened := range listeners {
				_ = opened.listener.Close()
			}
			return fmt.Errorf("прокси не смог занять %s: %w", address, listenErr)
		}
		listeners = append(listeners, proxyListener{listener: listener, access: policies[index]})
	}
	defer func() {
		for _, opened := range listeners {
			_ = opened.listener.Close()
		}
	}()
	go func() {
		<-serverCtx.Done()
		for _, opened := range listeners {
			_ = opened.listener.Close()
		}
	}()

	readyAddresses := make([]string, 0, len(listeners))
	for _, opened := range listeners {
		readyAddresses = append(readyAddresses, opened.listener.Addr().String())
	}
	if onReady != nil {
		onReady(readyAddresses)
	}

	clientSlots := make(chan struct{}, proxyMaxClients)
	errorsCh := make(chan error, len(listeners))
	var accepts sync.WaitGroup
	var clients sync.WaitGroup
	for _, opened := range listeners {
		opened := opened
		accepts.Add(1)
		go func() {
			defer accepts.Done()
			for {
				client, acceptErr := opened.listener.Accept()
				if acceptErr != nil {
					if serverCtx.Err() == nil && !errors.Is(acceptErr, net.ErrClosed) {
						select {
						case errorsCh <- fmt.Errorf("приём клиента прокси: %w", acceptErr):
						default:
						}
					}
					return
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
					_ = serveUnifiedProxyClient(
						serverCtx,
						mode,
						client,
						opened.access,
						dialer,
						authEnabled,
						username,
						password,
						udpEnabled,
					)
				}()
			}
		}()
	}

	select {
	case <-ctx.Done():
		cancelServer()
	case err = <-errorsCh:
		cancelServer()
	}
	accepts.Wait()
	clients.Wait()
	if err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func serveUnifiedProxyClient(
	ctx context.Context,
	mode string,
	client net.Conn,
	access proxyAccessPolicy,
	dialer socks5Dialer,
	authEnabled bool,
	username string,
	password string,
	udpEnabled bool,
) error {
	selectedMode := mode
	connection := client
	if mode == "auto" {
		if err := client.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
			return err
		}
		var first [1]byte
		_, err := io.ReadFull(client, first[:])
		if err != nil {
			return err
		}
		switch first[0] {
		case socksVersion5:
			selectedMode = "socks5"
		case 'C':
			selectedMode = "http"
		default:
			return fmt.Errorf("неизвестное приветствие прокси")
		}
		connection = &bufferedProxyConn{
			Conn:   client,
			reader: io.MultiReader(bytes.NewReader(first[:]), client),
		}
	}
	if selectedMode == "http" {
		return (&httpConnectServer{
			dialer: dialer, access: access, authEnabled: authEnabled,
			username: username, password: password,
		}).serveClient(ctx, connection)
	}
	return (&socks5Server{
		dialer: dialer, access: access, authEnabled: authEnabled,
		username: username, password: password, udpEnabled: udpEnabled,
	}).serveClient(ctx, connection)
}
