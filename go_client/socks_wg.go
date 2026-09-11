package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const socksWireGuardDefaultMTU = 1280

type wgQuickConfig struct {
	privateKeyHex string
	addresses     []netip.Addr
	dns           []netip.Addr
	mtu           int
	peerPublicHex string
	allowedIPs    []netip.Prefix
	endpoint      string
	keepalive     uint16
}

func wireGuardKeyToHex(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("длина ключа %d вместо 32 байт", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func parseWgQuickConfig(rawConfig string) (*wgQuickConfig, error) {
	config := &wgQuickConfig{mtu: socksWireGuardDefaultMTU, keepalive: 25}
	section := ""
	peerCount := 0

	for lineNumber, rawLine := range strings.Split(rawConfig, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peerCount++
				if peerCount > 1 {
					return nil, fmt.Errorf("поддерживается ровно один WireGuard peer")
				}
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("строка %d: ожидается key = value", lineNumber+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				parsed, err := wireGuardKeyToHex(value)
				if err != nil {
					return nil, fmt.Errorf("PrivateKey: %w", err)
				}
				config.privateKeyHex = parsed
			case "address":
				for _, part := range strings.Split(value, ",") {
					prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
					if err != nil {
						return nil, fmt.Errorf("Address %q: %w", part, err)
					}
					config.addresses = append(config.addresses, prefix.Addr())
				}
			case "dns":
				for _, part := range strings.Split(value, ",") {
					address, err := netip.ParseAddr(strings.TrimSpace(part))
					if err != nil {
						return nil, fmt.Errorf("DNS %q: нужен IP-адрес", part)
					}
					config.dns = append(config.dns, address)
				}
			case "mtu":
				mtu, err := strconv.Atoi(value)
				if err != nil || mtu < 576 || mtu > 65535 {
					return nil, fmt.Errorf("MTU %q вне диапазона 576..65535", value)
				}
				config.mtu = mtu
			}
		case "peer":
			switch key {
			case "publickey":
				parsed, err := wireGuardKeyToHex(value)
				if err != nil {
					return nil, fmt.Errorf("PublicKey: %w", err)
				}
				config.peerPublicHex = parsed
			case "allowedips":
				for _, part := range strings.Split(value, ",") {
					prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
					if err != nil {
						return nil, fmt.Errorf("AllowedIPs %q: %w", part, err)
					}
					config.allowedIPs = append(config.allowedIPs, prefix)
				}
			case "endpoint":
				if _, _, err := netSplitHostPortStrict(value); err != nil {
					return nil, fmt.Errorf("Endpoint %q: %w", value, err)
				}
				config.endpoint = value
			case "persistentkeepalive":
				seconds, err := strconv.Atoi(value)
				if err != nil || seconds < 0 || seconds > 65535 {
					return nil, fmt.Errorf("PersistentKeepalive %q вне диапазона 0..65535", value)
				}
				config.keepalive = uint16(seconds)
			}
		}
	}

	if peerCount != 1 || config.privateKeyHex == "" || config.peerPublicHex == "" {
		return nil, fmt.Errorf("конфигурация не содержит полный Interface/Peer")
	}
	if len(config.addresses) == 0 || config.endpoint == "" {
		return nil, fmt.Errorf("конфигурация не содержит Address или Endpoint")
	}
	if len(config.allowedIPs) == 0 {
		return nil, fmt.Errorf("конфигурация не содержит AllowedIPs")
	}
	if len(config.dns) == 0 {
		config.dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	return config, nil
}

func netSplitHostPortStrict(value string) (string, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", "", err
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 || strings.TrimSpace(host) == "" {
		return "", "", fmt.Errorf("некорректный адрес или порт")
	}
	return host, port, nil
}

func (config *wgQuickConfig) ipcRequest() string {
	var request strings.Builder
	fmt.Fprintf(&request, "private_key=%s\n", config.privateKeyHex)
	fmt.Fprintf(&request, "public_key=%s\n", config.peerPublicHex)
	fmt.Fprintf(&request, "endpoint=%s\n", config.endpoint)
	fmt.Fprintf(&request, "persistent_keepalive_interval=%d\n", config.keepalive)
	for _, prefix := range config.allowedIPs {
		fmt.Fprintf(&request, "allowed_ip=%s\n", prefix)
	}
	return request.String()
}

func startSocksWireGuard(rawConfig string) (*device.Device, *netstack.Net, error) {
	config, err := parseWgQuickConfig(rawConfig)
	if err != nil {
		return nil, nil, err
	}
	tunDevice, tunnelNetwork, err := netstack.CreateNetTUN(config.addresses, config.dns, config.mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("создание userspace TUN: %w", err)
	}
	wgDevice := device.NewDevice(
		tunDevice,
		conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "[WG-SOCKS] "),
	)
	if err := wgDevice.IpcSet(config.ipcRequest()); err != nil {
		wgDevice.Close()
		return nil, nil, fmt.Errorf("применение WireGuard-конфигурации: %w", err)
	}
	if err := wgDevice.Up(); err != nil {
		wgDevice.Close()
		return nil, nil, fmt.Errorf("запуск WireGuard: %w", err)
	}
	return wgDevice, tunnelNetwork, nil
}
