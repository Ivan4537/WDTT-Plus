package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testWireGuardKey(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32)))
}

func TestParseWgQuickConfigForUserspaceTunnel(t *testing.T) {
	raw := `[Interface]
PrivateKey = ` + testWireGuardKey(1) + `
Address = 10.66.66.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = ` + testWireGuardKey(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:9000
PersistentKeepalive = 25`

	config, err := parseWgQuickConfig(raw)
	if err != nil {
		t.Fatalf("parseWgQuickConfig: %v", err)
	}
	if got := config.addresses[0].String(); got != "10.66.66.2" {
		t.Fatalf("address = %s", got)
	}
	if got := config.allowedIPs[0].String(); got != "0.0.0.0/0" {
		t.Fatalf("allowed IP = %s", got)
	}
	request := config.ipcRequest()
	for _, required := range []string{"private_key=", "public_key=", "endpoint=127.0.0.1:9000", "allowed_ip=0.0.0.0/0"} {
		if !strings.Contains(request, required) {
			t.Fatalf("IPC request does not contain %q: %s", required, request)
		}
	}
}

func TestParseWgQuickConfigFailsClosed(t *testing.T) {
	key := testWireGuardKey(1)
	for name, raw := range map[string]string{
		"missing allowed IPs":          "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 127.0.0.1:9000",
		"multiple peers":               "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9000\n[Peer]",
		"public endpoint without port": "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.com",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWgQuickConfig(raw); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
