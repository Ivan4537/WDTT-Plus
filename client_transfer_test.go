package main

import (
	"strings"
	"testing"
)

func TestClientTransferRoundTripOmitsServerState(t *testing.T) {
	encoded, err := encodeClientTransfer("ABCDEFGHJKLMNPQR", &PasswordEntry{
		Label:         "Телефон",
		VkHash:        "abcdefghijklmnop",
		ExpiresAt:     1900000000,
		DeviceID:      "device-secret",
		DownBytes:     123,
		Ports:         "56010,56011,9010",
		IsDeactivated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"device-secret", "down_bytes", "ports", "host"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("transfer leaked server-specific field %q: %s", forbidden, encoded)
		}
	}
	payload, err := decodeClientTransfer(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Password != "ABCDEFGHJKLMNPQR" || payload.Label != "Телефон" || !payload.Deactivated {
		t.Fatalf("payload changed after round trip: %#v", payload)
	}
}

func TestClientTransferRejectsInvalidPassword(t *testing.T) {
	_, err := decodeClientTransfer(`{"format":"wdtt-plus-client","version":1,"password":"bad password","expires_at":0}`)
	if err == nil {
		t.Fatal("invalid transfer password was accepted")
	}
}

func TestBotClientCreateAndPasswordChangeAreLive(t *testing.T) {
	configDir := t.TempDir()
	dbMutex.Lock()
	db = &Database{
		MainPassword: "owner-secret",
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords:    make(map[string]*PasswordEntry),
		Devices:      make(map[string]*ClientDevice),
	}
	dbFile = configDir + "/passwords.json"
	maxGeneratedPasswords = 10
	serverWrapKeys = newWrapKeyStore()
	dbMutex.Unlock()

	oldPassword := "ABCDEFGHJKLMNPQR"
	createdPassword, entry, err := createBotClient(nil, oldPassword, 30, -1, "Перенос", "abcdefghijklmnop", "56000,56001,9000", false)
	if err != nil {
		t.Fatal(err)
	}
	if createdPassword != oldPassword || entry.Label != "Перенос" || serverWrapKeys.Count() != 1 {
		t.Fatalf("custom bot client was not applied live: password=%q entry=%#v keys=%d", createdPassword, entry, serverWrapKeys.Count())
	}
	if _, _, err := createBotClient(nil, oldPassword, 30, -1, "Дубликат", "", "56000,56001,9000", false); err == nil {
		t.Fatal("bot accepted a duplicate client password")
	}
	entry.DeviceID = "phone"
	newPassword, err := changeBotClientPassword(nil, oldPassword, "RSTUVWXYZ2345678")
	if err != nil {
		t.Fatal(err)
	}
	if newPassword != "RSTUVWXYZ2345678" || serverWrapKeys.Count() != 1 {
		t.Fatalf("bot password replacement was not live: password=%q keys=%d", newPassword, serverWrapKeys.Count())
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if db.Passwords[oldPassword] != nil || db.Passwords[newPassword] == nil || db.Passwords[newPassword].DeviceID != "phone" {
		t.Fatal("bot password replacement lost the client or its binding")
	}
}
