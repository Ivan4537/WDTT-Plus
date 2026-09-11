package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeNativeStartupSecrets(t *testing.T) {
	want := nativeStartupSecrets{
		VKHashes:             "https://example.invalid/join/test",
		ConnectionPassword:   "connection-secret",
		CustomVKClientID:     "1234567",
		CustomVKClientSecret: "client-secret",
		SocksUsername:        "local-user",
		SocksPassword:        "local-password",
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)

	got, err := decodeNativeStartupSecrets(payload)
	if err != nil {
		t.Fatalf("decodeNativeStartupSecrets: %v", err)
	}
	if got != want {
		t.Fatalf("decoded secrets = %#v, want %#v", got, want)
	}
}

func TestDecodeNativeStartupSecretsRejectsInvalidInput(t *testing.T) {
	for _, payload := range []string{"", "%%%", strings.Repeat("A", 32*1024+1)} {
		if _, err := decodeNativeStartupSecrets(payload); err == nil {
			t.Fatalf("decodeNativeStartupSecrets(%q) succeeded", payload)
		}
	}
}
