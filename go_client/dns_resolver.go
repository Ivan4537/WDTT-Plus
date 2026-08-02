package main

import (
	"context"
	"fmt"
	"log"
	"net"
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
