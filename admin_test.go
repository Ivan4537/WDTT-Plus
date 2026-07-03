package main

import (
	"context"
	"reflect"
	"testing"
)

func TestAdminSocketAppliesClientChangesWithoutRestart(t *testing.T) {
	configDir := t.TempDir()
	loaded := &Database{
		MainPassword: "owner-secret",
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords:    make(map[string]*PasswordEntry),
		Devices:      make(map[string]*ClientDevice),
	}
	if err := saveAdminDB(configDir, loaded); err != nil {
		t.Fatal(err)
	}

	dbMutex.Lock()
	db = loaded
	dbFile = configDir + "/passwords.json"
	serverWrapKeys = newWrapKeyStore()
	dbMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startAdminSocket(ctx, configDir, nil); err != nil {
		t.Fatal(err)
	}
	denied, err := callAdminSocket(configDir, adminRequest{MainPassword: "wrong", Args: []string{"list"}})
	if err != nil {
		t.Fatal(err)
	}
	if denied.OK {
		t.Fatal("admin socket accepted an invalid main password")
	}

	request := func(args ...string) adminResponse {
		t.Helper()
		response, err := callAdminSocket(configDir, adminRequest{
			MainPassword: "owner-secret",
			Args:         args,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !response.OK {
			t.Fatalf("admin request %v failed: %s", args, response.Message)
		}
		if response.RestartRequired {
			t.Fatalf("admin request %v unexpectedly requires restart", args)
		}
		return response
	}

	created := request("create", "--days", "30", "--label", "Тест")
	if created.Password == nil || created.Password.Password == "" {
		t.Fatal("create did not return a password")
	}
	if created.Password.Label != "Тест" {
		t.Fatalf("create did not preserve client label: %q", created.Password.Label)
	}
	password := created.Password.Password
	if serverWrapKeys.Count() != 1 {
		t.Fatalf("expected one live WRAP key, got %d", serverWrapKeys.Count())
	}
	updated := request(
		"update-client", "--password", password,
		"--label", "Телефон", "--vk-hash", "hash-value", "--ports", "56010,56011,9010",
	)
	if updated.Password == nil || updated.Password.Label != "Телефон" || updated.Password.Ports != "56010,56011,9010" {
		t.Fatal("client fields were not updated")
	}
	renamed := request("set-label", "--password", password, "--label", "Папа")
	if renamed.Password == nil || renamed.Password.Label != "Папа" {
		t.Fatalf("set-label did not preserve client label: %#v", renamed.Password)
	}
	request(
		"update-settings", "--dns", "1.1.1.1,8.8.8.8", "--limit", "25",
		"--ports", "56000,56001,9000", "--public-ip", "vpn.example.com",
	)
	if db.DNS != "1.1.1.1,8.8.8.8" || db.MaxPasswords != 25 || getServerPublicIPOverride() != "vpn.example.com" {
		t.Fatal("live server settings were not applied")
	}

	request(
		"update-admin-profile",
		"--vk-hashes", "abcdefghijklmnop,qrstuvwxyzABCDEF",
		"--secondary-vk-hash", "1234567890abcdef",
		"--workers", "27",
		"--protocol", "tcp",
		"--listen-port", "9010",
		"--sni", "owner.example.com",
		"--ports", "56010,56011,9010",
		"--no-dns",
	)
	listedOwner := request("list")
	if listedOwner.Server == nil {
		t.Fatal("list did not return server state after owner profile update")
	}
	profile := listedOwner.Server.AdminProfile
	if profile.VkHashes != "abcdefghijklmnop,qrstuvwxyzABCDEF" ||
		profile.SecondaryVkHash != "1234567890abcdef" ||
		profile.WorkersPerHash != 27 ||
		profile.Protocol != "tcp" ||
		profile.ListenPort != 9010 ||
		profile.SNI != "owner.example.com" ||
		!profile.NoDNS ||
		profile.Ports != "56010,56011,9010" ||
		profile.UpdatedAt == 0 {
		t.Fatalf("owner profile was not returned intact: %#v", profile)
	}
	persisted, err := readAdminDB(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(persisted.AdminProfile, profile) {
		t.Fatalf("owner profile on disk differs from live state: disk=%#v live=%#v", persisted.AdminProfile, profile)
	}

	dbMutex.Lock()
	db.Devices["phone"] = &ClientDevice{DeviceID: "phone", IP: "10.66.66.2"}
	db.Devices["orphan"] = &ClientDevice{DeviceID: "orphan", IP: "10.66.66.3"}
	db.Passwords[password].DeviceID = "phone"
	db.Passwords[password].DownBytes = 1024
	db.Passwords[password].UpBytes = 2048
	if err := saveAdminDB(configDir, db); err != nil {
		dbMutex.Unlock()
		t.Fatal(err)
	}
	dbMutex.Unlock()
	listed := request("list")
	if listed.Server == nil || listed.Server.OrphanDeviceCount != 1 || len(listed.Server.OrphanDevices) != 1 || listed.Server.OrphanDevices[0].DeviceID != "orphan" {
		t.Fatal("orphan device preview is incomplete")
	}
	request("cleanup-orphans")
	dbMutex.Lock()
	if db.Devices["orphan"] != nil {
		dbMutex.Unlock()
		t.Fatal("orphan device was not removed")
	}
	dbMutex.Unlock()
	request("reset-traffic")
	if db.Passwords[password].DownBytes != 0 || db.Passwords[password].UpBytes != 0 {
		t.Fatal("traffic counters were not reset")
	}

	request("deactivate", "--password", password)
	dbMutex.Lock()
	if db.Passwords[password].DeviceID != "phone" || db.Devices["phone"] == nil {
		dbMutex.Unlock()
		t.Fatal("deactivation must preserve the device binding")
	}
	dbMutex.Unlock()
	if serverWrapKeys.Count() != 0 {
		t.Fatalf("expected deactivation to remove live WRAP key, got %d", serverWrapKeys.Count())
	}

	request("activate", "--password", password)
	if serverWrapKeys.Count() != 1 {
		t.Fatalf("expected activation to restore live WRAP key, got %d", serverWrapKeys.Count())
	}
	request("delete", "--password", password)
	if serverWrapKeys.Count() != 0 {
		t.Fatalf("expected deletion to remove live WRAP key, got %d", serverWrapKeys.Count())
	}
}
