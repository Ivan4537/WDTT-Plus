package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	socksVersion5         = 0x05
	socksAuthNone         = 0x00
	socksAuthPassword     = 0x02
	socksAuthUnavailable  = 0xff
	socksCommandConnect   = 0x01
	socksCommandUDP       = 0x03
	socksAddressIPv4      = 0x01
	socksAddressDomain    = 0x03
	socksAddressIPv6      = 0x04
	socksReplyOK          = 0x00
	socksReplyFailure     = 0x01
	socksReplyNotAllowed  = 0x02
	socksReplyUnreachable = 0x04
	socksReplyUnsupported = 0x07
	socksReplyAddressType = 0x08
	socksMaxUDPDatagram   = 64 * 1024
	socksMaxUDPFlows      = 64
	socksHandshakeTimeout = 15 * time.Second
	socksUDPFlowIdle      = 2 * time.Minute
	socksUDPIdleTimeout   = 5 * time.Minute
	socksUDPReadTick      = time.Second
)

type socks5Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	LookupContextHost(ctx context.Context, host string) ([]string, error)
}

type netstackSocksDialer struct{ network *netstack.Net }

func (dialer netstackSocksDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialer.network.DialContext(ctx, network, address)
}

func (dialer netstackSocksDialer) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return dialer.network.LookupContextHost(ctx, host)
}

type socks5Server struct {
	dialer      socks5Dialer
	access      proxyAccessPolicy
	authEnabled bool
	username    string
	password    string
	udpEnabled  bool
}

type proxyAccessPolicy struct {
	listenIP      netip.Addr
	allowedPrefix netip.Prefix
}

type socksRequest struct {
	command byte
	host    string
	port    uint16
}

func validateSocksListenAddress(value string) (string, error) {
	address, _, err := validateProxyListenAddress(value, "", false)
	return address, err
}

func validateProxyListenAddress(value, allowedCIDR string, authEnabled bool) (string, proxyAccessPolicy, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", proxyAccessPolicy{}, fmt.Errorf("адрес прокси: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return "", proxyAccessPolicy{}, fmt.Errorf("прокси требует конкретный IPv4-адрес")
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil || port < 1 || port > 65535 {
		return "", proxyAccessPolicy{}, fmt.Errorf("порт прокси вне диапазона 1..65535")
	}
	policy := proxyAccessPolicy{listenIP: address}
	if address.IsLoopback() {
		if strings.TrimSpace(allowedCIDR) != "" {
			return "", proxyAccessPolicy{}, fmt.Errorf("для loopback нельзя задавать внешнюю подсеть")
		}
		return net.JoinHostPort(address.String(), fmt.Sprint(port)), policy, nil
	}
	if !address.IsPrivate() {
		return "", proxyAccessPolicy{}, fmt.Errorf("доступ разрешён только на loopback или частном IPv4-адресе")
	}
	if !authEnabled {
		return "", proxyAccessPolicy{}, fmt.Errorf("для доступа из локальной сети обязательна аутентификация")
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(allowedCIDR))
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 24 || prefix.Bits() > 30 {
		return "", proxyAccessPolicy{}, fmt.Errorf("некорректная разрешённая локальная подсеть")
	}
	prefix = prefix.Masked()
	if !prefix.Contains(address) {
		return "", proxyAccessPolicy{}, fmt.Errorf("адрес прокси не принадлежит разрешённой подсети")
	}
	policy.allowedPrefix = prefix
	return net.JoinHostPort(address.String(), fmt.Sprint(port)), policy, nil
}

func runSocks5Server(
	ctx context.Context,
	listenAddress string,
	tunnelNetwork *netstack.Net,
	authEnabled bool,
	username string,
	password string,
	udpEnabled bool,
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
		return fmt.Errorf("для SOCKS5-аутентификации нужны логин и пароль длиной до 255 байт")
	}
	listener, err := net.Listen("tcp4", validatedAddress)
	if err != nil {
		return fmt.Errorf("SOCKS5 не смог занять %s: %w", validatedAddress, err)
	}
	defer listener.Close()

	server := &socks5Server{
		dialer:      netstackSocksDialer{network: tunnelNetwork},
		access:      access,
		authEnabled: authEnabled,
		username:    username,
		password:    password,
		udpEnabled:  udpEnabled,
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
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("приём SOCKS5-клиента: %w", err)
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

func (server *socks5Server) serveClient(ctx context.Context, client net.Conn) error {
	if !server.access.allows(client.RemoteAddr()) {
		return fmt.Errorf("SOCKS5-клиент вне разрешённой подсети")
	}
	if err := client.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return err
	}
	reader := bufio.NewReader(client)
	if err := server.negotiateAuthentication(reader, client); err != nil {
		return err
	}
	request, err := readSocksRequest(reader)
	if err != nil {
		_ = writeSocksReply(client, socksReplyFailure, nil)
		return err
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return err
	}
	switch request.command {
	case socksCommandConnect:
		return server.serveConnect(ctx, client, request)
	case socksCommandUDP:
		if !server.udpEnabled {
			_ = writeSocksReply(client, socksReplyNotAllowed, nil)
			return fmt.Errorf("UDP ASSOCIATE отключён")
		}
		return server.serveUDPAssociation(ctx, client, request)
	default:
		_ = writeSocksReply(client, socksReplyUnsupported, nil)
		return fmt.Errorf("SOCKS5-команда %d не поддерживается", request.command)
	}
}

func (policy proxyAccessPolicy) allows(remote net.Addr) bool {
	if !policy.listenIP.IsValid() {
		return true
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() {
		return false
	}
	if policy.listenIP.IsLoopback() {
		return address.IsLoopback()
	}
	return policy.allowedPrefix.IsValid() && policy.allowedPrefix.Contains(address)
}

func (server *socks5Server) negotiateAuthentication(reader *bufio.Reader, client io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 || header[1] == 0 {
		return fmt.Errorf("некорректное SOCKS5-приветствие")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	wanted := byte(socksAuthNone)
	if server.authEnabled {
		wanted = socksAuthPassword
	}
	found := false
	for _, method := range methods {
		if method == wanted {
			found = true
			break
		}
	}
	if !found {
		_, _ = client.Write([]byte{socksVersion5, socksAuthUnavailable})
		return fmt.Errorf("клиент не предложил требуемый метод аутентификации")
	}
	if _, err := client.Write([]byte{socksVersion5, wanted}); err != nil {
		return err
	}
	if wanted == socksAuthPassword {
		return server.authenticatePassword(reader, client)
	}
	return nil
}

func (server *socks5Server) authenticatePassword(reader *bufio.Reader, client io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != 0x01 || header[1] == 0 {
		return fmt.Errorf("некорректный запрос логина SOCKS5")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return err
	}
	length, err := reader.ReadByte()
	if err != nil || length == 0 {
		return fmt.Errorf("некорректный пароль SOCKS5")
	}
	password := make([]byte, int(length))
	if _, err := io.ReadFull(reader, password); err != nil {
		return err
	}
	validUsername := subtle.ConstantTimeCompare(username, []byte(server.username))
	validPassword := subtle.ConstantTimeCompare(password, []byte(server.password))
	status := byte(0x00)
	if validUsername&validPassword != 1 {
		status = 0x01
	}
	_, _ = client.Write([]byte{0x01, status})
	if status != 0 {
		return fmt.Errorf("неверный логин или пароль SOCKS5")
	}
	return nil
}

func readSocksRequest(reader io.Reader) (socksRequest, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return socksRequest{}, err
	}
	if header[0] != socksVersion5 || header[2] != 0 {
		return socksRequest{}, fmt.Errorf("некорректный SOCKS5-запрос")
	}
	host, err := readSocksHost(reader, header[3])
	if err != nil {
		return socksRequest{}, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return socksRequest{}, err
	}
	return socksRequest{command: header[1], host: host, port: binary.BigEndian.Uint16(portBytes)}, nil
}

func readSocksHost(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case socksAddressIPv4:
		value := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		return net.IP(value).String(), nil
	case socksAddressDomain:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return "", fmt.Errorf("пустое доменное имя")
		}
		value := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", err
		}
		return string(value), nil
	case socksAddressIPv6:
		return "", fmt.Errorf("IPv6 пока отсутствует в профиле WDTT")
	default:
		return "", fmt.Errorf("неизвестный тип SOCKS5-адреса %d", addressType)
	}
}

func (server *socks5Server) resolveIPv4(ctx context.Context, host string, port uint16) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return "", fmt.Errorf("IPv6 пока отсутствует в профиле WDTT")
		}
		return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
	}
	addresses, err := server.dialer.LookupContextHost(ctx, host)
	if err != nil {
		return "", err
	}
	for _, value := range addresses {
		if ip, err := netip.ParseAddr(value); err == nil && ip.Is4() {
			return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
		}
	}
	return "", fmt.Errorf("у %s нет IPv4-адреса", host)
}

func (server *socks5Server) serveConnect(ctx context.Context, client net.Conn, request socksRequest) error {
	target, err := server.resolveIPv4(ctx, request.host, request.port)
	if err != nil {
		_ = writeSocksReply(client, socksReplyUnreachable, nil)
		return err
	}
	upstream, err := server.dialer.DialContext(ctx, "tcp4", target)
	if err != nil {
		_ = writeSocksReply(client, socksReplyUnreachable, nil)
		return err
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if err := writeSocksReply(client, socksReplyOK, upstream.LocalAddr()); err != nil {
		return err
	}
	return relayBidirectional(client, upstream)
}

func relayBidirectional(left, right net.Conn) error {
	errorsCh := make(chan error, 2)
	copySide := func(destination, source net.Conn) {
		_, err := io.Copy(destination, source)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errorsCh <- err
	}
	go copySide(left, right)
	go copySide(right, left)
	first := <-errorsCh
	second := <-errorsCh
	if first != nil && !errors.Is(first, net.ErrClosed) {
		return first
	}
	return second
}

type socksUDPFlow struct {
	connection net.Conn
	target     *net.UDPAddr
	lastUsed   time.Time
}

func prepareSocksUDPFlowSlot(flows map[string]*socksUDPFlow, now time.Time) {
	for key, flow := range flows {
		if now.Sub(flow.lastUsed) >= socksUDPFlowIdle {
			_ = flow.connection.Close()
			delete(flows, key)
		}
	}
	if len(flows) < socksMaxUDPFlows {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	for key, flow := range flows {
		if oldestKey == "" || flow.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = flow.lastUsed
		}
	}
	if oldestKey != "" {
		_ = flows[oldestKey].connection.Close()
		delete(flows, oldestKey)
	}
}

func (server *socks5Server) serveUDPAssociation(ctx context.Context, control net.Conn, request socksRequest) error {
	controlHost, _, err := net.SplitHostPort(control.RemoteAddr().String())
	if err != nil {
		_ = writeSocksReply(control, socksReplyFailure, nil)
		return err
	}
	requestedIP := net.ParseIP(request.host)
	if request.host != "" && request.host != "0.0.0.0" && requestedIP != nil && !requestedIP.Equal(net.ParseIP(controlHost)) {
		_ = writeSocksReply(control, socksReplyNotAllowed, nil)
		return fmt.Errorf("UDP ASSOCIATE запросил чужой адрес")
	}
	if request.host != "" && request.host != "0.0.0.0" && requestedIP == nil {
		_ = writeSocksReply(control, socksReplyNotAllowed, nil)
		return fmt.Errorf("UDP ASSOCIATE должен использовать адрес TCP-клиента")
	}

	relayIP := net.IPv4(127, 0, 0, 1)
	if server.access.listenIP.IsValid() {
		relayIP = net.IP(server.access.listenIP.AsSlice())
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: relayIP})
	if err != nil {
		_ = writeSocksReply(control, socksReplyFailure, nil)
		return err
	}
	defer relay.Close()
	if err := writeSocksReply(control, socksReplyOK, relay.LocalAddr()); err != nil {
		return err
	}

	associationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		var one [1]byte
		_, _ = control.Read(one[:])
		cancel()
		_ = relay.Close()
	}()

	flows := make(map[string]*socksUDPFlow)
	defer func() {
		for _, flow := range flows {
			_ = flow.connection.Close()
		}
	}()
	buffer := make([]byte, socksMaxUDPDatagram)
	var clientAddress *net.UDPAddr
	lastActivity := time.Now()
	for {
		_ = relay.SetReadDeadline(time.Now().Add(socksUDPReadTick))
		size, source, err := relay.ReadFromUDP(buffer)
		if err != nil {
			if associationCtx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if time.Since(lastActivity) >= socksUDPIdleTimeout {
					return nil
				}
				continue
			}
			return err
		}
		if !source.IP.Equal(net.ParseIP(controlHost)) {
			continue
		}
		if clientAddress == nil {
			if request.port != 0 && int(request.port) != source.Port {
				continue
			}
			clientAddress = source
		} else if !source.IP.Equal(clientAddress.IP) || source.Port != clientAddress.Port {
			continue
		}
		lastActivity = time.Now()
		target, payload, err := parseSocksUDPDatagram(buffer[:size])
		if err != nil {
			continue
		}
		resolved, err := server.resolveIPv4(associationCtx, target.host, target.port)
		if err != nil {
			continue
		}
		now := time.Now()
		flow := flows[resolved]
		if flow == nil {
			prepareSocksUDPFlowSlot(flows, now)
			connection, err := server.dialer.DialContext(associationCtx, "udp4", resolved)
			if err != nil {
				continue
			}
			udpTarget, err := net.ResolveUDPAddr("udp4", resolved)
			if err != nil {
				_ = connection.Close()
				continue
			}
			flow = &socksUDPFlow{connection: connection, target: udpTarget, lastUsed: now}
			flows[resolved] = flow
			go relaySocksUDPResponses(associationCtx, relay, clientAddress, flow)
		}
		flow.lastUsed = now
		_, _ = flow.connection.Write(payload)
	}
}

func parseSocksUDPDatagram(packet []byte) (socksRequest, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return socksRequest{}, nil, fmt.Errorf("некорректный UDP-заголовок SOCKS5")
	}
	if packet[2] != 0 {
		return socksRequest{}, nil, fmt.Errorf("фрагментация UDP SOCKS5 не поддерживается")
	}
	reader := bytes.NewReader(packet[4:])
	host, err := readSocksHost(reader, packet[3])
	if err != nil {
		return socksRequest{}, nil, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return socksRequest{}, nil, err
	}
	payload, err := io.ReadAll(reader)
	if err != nil || len(payload) == 0 {
		return socksRequest{}, nil, fmt.Errorf("пустая UDP-датаграмма SOCKS5")
	}
	return socksRequest{host: host, port: binary.BigEndian.Uint16(portBytes[:])}, payload, nil
}

func relaySocksUDPResponses(ctx context.Context, relay *net.UDPConn, client *net.UDPAddr, flow *socksUDPFlow) {
	buffer := make([]byte, socksMaxUDPDatagram)
	for {
		_ = flow.connection.SetReadDeadline(time.Now().Add(socksUDPReadTick))
		size, err := flow.connection.Read(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		packet, err := buildSocksUDPDatagram(flow.target, buffer[:size])
		if err == nil {
			_, _ = relay.WriteToUDP(packet, client)
		}
	}
}

func buildSocksUDPDatagram(address *net.UDPAddr, payload []byte) ([]byte, error) {
	ip := address.IP.To4()
	if ip == nil || address.Port < 1 || address.Port > 65535 {
		return nil, fmt.Errorf("ответ SOCKS5 не является IPv4 UDP")
	}
	packet := make([]byte, 10+len(payload))
	packet[3] = socksAddressIPv4
	copy(packet[4:8], ip)
	binary.BigEndian.PutUint16(packet[8:10], uint16(address.Port))
	copy(packet[10:], payload)
	return packet, nil
}

func writeSocksReply(writer io.Writer, reply byte, address net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if address != nil {
		host, portText, err := net.SplitHostPort(address.String())
		if err == nil {
			if parsed := net.ParseIP(host).To4(); parsed != nil {
				ip = parsed
			}
			port, _ = net.LookupPort("tcp", portText)
		}
	}
	response := []byte{socksVersion5, reply, 0, socksAddressIPv4, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(response[8:10], uint16(port))
	_, err := writer.Write(response)
	return err
}
