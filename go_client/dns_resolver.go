package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const dnsProbeHost = "login.vk.ru"

// Keep Android's resolver before setupGlobalResolver optionally replaces the
// process-wide resolver with a direct DNS route optimized for VK. Some public
// resolvers return different Cloudflare WARP API edges, so MASQUE enrollment
// must be able to consult the device resolver independently.
var deviceSystemResolver = net.DefaultResolver

type dnsRoute struct {
	Label   string
	Network string
	Address string
	System  bool
}

type dnsRouteProbe struct {
	Route dnsRoute
	Err   error
}

type directDNSProbe func(context.Context, dnsRoute, time.Duration) error
type systemDNSProbe func(context.Context, *net.Resolver, time.Duration) error

type peerEndpoint struct {
	Host    string
	Port    int
	Literal net.IP
}

type peerIPLookup func(context.Context, string) ([]net.IPAddr, error)
type peerResolveAttempt func(context.Context, peerEndpoint) (*net.UDPAddr, error)
type peerRetryWait func(context.Context, time.Duration) error

const peerDNSLookupTimeout = 1800 * time.Millisecond

func setupGlobalResolver() {
	systemResolver := deviceSystemResolver
	route, probes := chooseDNSRoute(context.Background(), systemResolver)
	if route.System {
		logDNSSystemRoute(probes)
		return
	}
	if route.Address == "" {
		logDNSUnavailable(probes)
		return
	}

	log.Printf("[DNS] Прямой DNS %s отвечает для %s; используем его", route.Label, dnsProbeHost)
	net.DefaultResolver = fixedDNSResolver(route)
}

func chooseDNSRoute(ctx context.Context, systemResolver *net.Resolver) (dnsRoute, []dnsRouteProbe) {
	return chooseDNSRouteWithProbes(ctx, systemResolver, probeDNSRoute, probeSystemDNS)
}

func chooseDNSRouteWithProbes(
	ctx context.Context,
	systemResolver *net.Resolver,
	probeDirect directDNSProbe,
	probeSystem systemDNSProbe,
) (dnsRoute, []dnsRouteProbe) {
	candidates := []dnsRoute{
		{Label: "77.88.8.8 UDP", Network: "udp", Address: "77.88.8.8:53"},
		{Label: "77.88.8.1 UDP", Network: "udp", Address: "77.88.8.1:53"},
		{Label: "77.88.8.8 TCP", Network: "tcp", Address: "77.88.8.8:53"},
		{Label: "77.88.8.1 TCP", Network: "tcp", Address: "77.88.8.1:53"},
	}

	probes := make([]dnsRouteProbe, 0, len(candidates)+1)
	for _, route := range candidates {
		timeout := 1200 * time.Millisecond
		if route.Network == "tcp" {
			timeout = 1500 * time.Millisecond
		}
		err := probeDirect(ctx, route, timeout)
		probes = append(probes, dnsRouteProbe{Route: route, Err: err})
		if err == nil {
			return route, probes
		}
	}

	systemRoute := dnsRoute{Label: "системный DNS устройства", System: true}
	err := probeSystem(ctx, systemResolver, 1800*time.Millisecond)
	probes = append(probes, dnsRouteProbe{Route: systemRoute, Err: err})
	if err == nil {
		return systemRoute, probes
	}
	return dnsRoute{}, probes
}

func probeDNSRoute(ctx context.Context, route dnsRoute, timeout time.Duration) error {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver := fixedDNSResolver(route)
	return lookupHostWithResolver(probeCtx, resolver, dnsProbeHost)
}

func probeSystemDNS(ctx context.Context, resolver *net.Resolver, timeout time.Duration) error {
	if resolver == nil {
		resolver = &net.Resolver{}
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return lookupHostWithResolver(probeCtx, resolver, dnsProbeHost)
}

func fixedDNSResolver(route dnsRoute) *net.Resolver {
	dialer := &net.Dialer{
		Timeout:   1200 * time.Millisecond,
		KeepAlive: 30 * time.Second,
	}
	if route.Network == "tcp" {
		dialer.Timeout = 1500 * time.Millisecond
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, route.Network, route.Address)
		},
	}
}

func lookupHostWithResolver(ctx context.Context, resolver *net.Resolver, host string) error {
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("пустой DNS-ответ")
	}
	return nil
}

func logDNSSystemRoute(probes []dnsRouteProbe) {
	failedDirect := summarizeDNSFailures(probes, false)
	if failedDirect == "" {
		log.Printf("[DNS] Системный DNS устройства отвечает для %s; используем его", dnsProbeHost)
		return
	}
	log.Printf("[DNS] Прямой DNS клиента недоступен (%s); системный DNS устройства отвечает — используем его", failedDirect)
}

func logDNSUnavailable(probes []dnsRouteProbe) {
	log.Printf("[DNS] DNS до VK недоступен: прямой DNS клиента и системный DNS устройства не ответили (%s)", summarizeDNSFailures(probes, true))
}

func summarizeDNSFailures(probes []dnsRouteProbe, includeSystem bool) string {
	parts := make([]string, 0, len(probes))
	for _, probe := range probes {
		if probe.Err == nil || (!includeSystem && probe.Route.System) {
			continue
		}
		parts = append(parts, probe.Route.Label+": "+shortDNSError(probe.Err))
	}
	return strings.Join(parts, "; ")
}

func shortDNSError(err error) string {
	if err == nil {
		return "OK"
	}
	text := strings.ReplaceAll(err.Error(), "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	if len(text) > 120 {
		return text[:120] + "…"
	}
	return text
}

func parsePeerEndpoint(value string) (peerEndpoint, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return peerEndpoint{}, fmt.Errorf("некорректный адрес сервера: %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return peerEndpoint{}, errors.New("адрес сервера не содержит имя или IP")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return peerEndpoint{}, errors.New("адрес сервера содержит некорректный порт")
	}
	endpoint := peerEndpoint{Host: host, Port: port}
	if literal := net.ParseIP(host); literal != nil {
		literal = literal.To4()
		if literal == nil {
			return peerEndpoint{}, errors.New("адрес сервера должен использовать IPv4")
		}
		endpoint.Literal = literal
	}
	return endpoint, nil
}

func peerDNSLookups() []peerIPLookup {
	lookups := make([]peerIPLookup, 0, 6)
	appendResolver := func(resolver *net.Resolver) {
		if resolver == nil {
			return
		}
		lookups = append(lookups, resolver.LookupIPAddr)
	}
	appendResolver(net.DefaultResolver)
	if deviceSystemResolver != net.DefaultResolver {
		appendResolver(deviceSystemResolver)
	}
	for _, route := range []dnsRoute{
		{Network: "udp", Address: "77.88.8.8:53"},
		{Network: "udp", Address: "77.88.8.1:53"},
		{Network: "tcp", Address: "77.88.8.8:53"},
		{Network: "tcp", Address: "77.88.8.1:53"},
	} {
		appendResolver(fixedDNSResolver(route))
	}
	return lookups
}

func resolvePeerUDPAddrOnceWithLookups(
	ctx context.Context,
	endpoint peerEndpoint,
	lookups []peerIPLookup,
) (*net.UDPAddr, error) {
	if endpoint.Literal != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), endpoint.Literal...), Port: endpoint.Port}, nil
	}
	if len(lookups) == 0 {
		return nil, errors.New("нет доступных DNS-маршрутов")
	}
	var lastErr error
	for _, lookup := range lookups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lookupCtx, cancel := context.WithTimeout(ctx, peerDNSLookupTimeout)
		addresses, err := lookup(lookupCtx, endpoint.Host)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		for _, address := range addresses {
			if ipv4 := address.IP.To4(); ipv4 != nil {
				return &net.UDPAddr{IP: append(net.IP(nil), ipv4...), Port: endpoint.Port}, nil
			}
		}
		lastErr = errors.New("DNS-ответ не содержит IPv4")
	}
	if lastErr == nil {
		lastErr = errors.New("пустой DNS-ответ")
	}
	return nil, lastErr
}

func peerDNSRetryDelay(attempt int) time.Duration {
	switch {
	case attempt <= 1:
		return 2 * time.Second
	case attempt == 2:
		return 4 * time.Second
	case attempt == 3:
		return 8 * time.Second
	default:
		return 15 * time.Second
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func waitForPeerUDPAddrWith(
	ctx context.Context,
	endpoint peerEndpoint,
	resolve peerResolveAttempt,
	wait peerRetryWait,
	onWaiting func(int, error),
) (*net.UDPAddr, int, error) {
	for attempt := 1; ; attempt++ {
		peer, err := resolve(ctx, endpoint)
		if err == nil {
			return peer, attempt - 1, nil
		}
		if ctx.Err() != nil {
			return nil, attempt - 1, ctx.Err()
		}
		if onWaiting != nil {
			onWaiting(attempt, err)
		}
		if err := wait(ctx, peerDNSRetryDelay(attempt)); err != nil {
			return nil, attempt, err
		}
	}
}

func waitForPeerUDPAddr(ctx context.Context, endpoint peerEndpoint) (*net.UDPAddr, error) {
	lookups := peerDNSLookups()
	peer, failures, err := waitForPeerUDPAddrWith(
		ctx,
		endpoint,
		func(resolveCtx context.Context, value peerEndpoint) (*net.UDPAddr, error) {
			return resolvePeerUDPAddrOnceWithLookups(resolveCtx, value, lookups)
		},
		waitForRetry,
		func(attempt int, _ error) {
			if attempt == 1 || attempt%4 == 0 {
				log.Printf("PEER_DNS_WAIT|%s", endpoint.Host)
			}
		},
	)
	if err != nil {
		return nil, err
	}
	if failures > 0 {
		log.Printf("PEER_DNS_READY|%s|%s", endpoint.Host, peer.IP.String())
	}
	return peer, nil
}
