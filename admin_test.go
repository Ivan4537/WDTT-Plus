package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestAdminServerInfoReportsRunningBinarySHA256(t *testing.T) {
	sum := runningBinarySHA256()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sum) {
		t.Fatalf("unexpected running binary SHA-256: %q", sum)
	}
	info := buildAdminServerInfo(t.TempDir(), &Database{
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords:    make(map[string]*PasswordEntry),
		Devices:      make(map[string]*ClientDevice),
	})
	if info.BinarySHA256 != sum {
		t.Fatalf("admin server SHA-256 = %q, want %q", info.BinarySHA256, sum)
	}
}

func TestAdminServerInfoReportsOpportunisticUDPWriteStats(t *testing.T) {
	stats := &opportunisticUDPWriteStats{}
	stats.singleWrites.Store(7)
	stats.batchCalls.Store(3)
	stats.batchMessages.Store(11)
	stats.partialBatchWrites.Store(1)
	stats.writeErrors.Store(2)
	stats.queueHighWater.Store(9)
	previous := activeOpportunisticUDPWriteStats.Swap(stats)
	defer activeOpportunisticUDPWriteStats.Store(previous)

	info := buildAdminServerInfo(t.TempDir(), &Database{
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords:    make(map[string]*PasswordEntry),
		Devices:      make(map[string]*ClientDevice),
	})
	if info.UDPWriteSingle != 7 ||
		info.UDPWriteBatchCalls != 3 ||
		info.UDPWriteBatchMessages != 11 ||
		info.UDPWritePartialBatches != 1 ||
		info.UDPWriteErrors != 2 ||
		info.UDPWriteQueueHighWater != 9 {
		t.Fatalf("unexpected UDP write stats: %+v", info)
	}
}

func TestAdminServerInfoSeparatesClientAndOwnerDevices(t *testing.T) {
	loaded := &Database{
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		AdminProfile: AdminProfileEntry{
			DeviceIDs: []string{"owner-phone", "shared-phone", "owner-phone"},
		},
		Passwords: map[string]*PasswordEntry{
			"client-one": {
				DeviceID: "shared-phone",
				BindHistory: []BindHistoryEntry{
					{DeviceID: "shared-phone", BoundAt: 10, Status: "active"},
					{DeviceID: "old-client-phone", BoundAt: 5, UnboundAt: 9, Status: "unbound"},
					{DeviceID: "rejected-phone", EventAt: 11, Status: "denied_mismatch"},
				},
			},
			"client-two": {},
		},
		Devices: map[string]*ClientDevice{
			"shared-phone": {DeviceID: "shared-phone"},
			"owner-phone":  {DeviceID: "owner-phone"},
			"orphan":       {DeviceID: "orphan"},
		},
	}

	info := buildAdminServerInfo(t.TempDir(), loaded)
	if info.DeviceCount != 2 {
		t.Fatalf("client device count = %d, want current plus successful history = 2", info.DeviceCount)
	}
	if info.OwnerDeviceCount != 2 {
		t.Fatalf("owner device count = %d, want 2 unique owner devices", info.OwnerDeviceCount)
	}
	if info.OrphanDeviceCount != 1 {
		t.Fatalf("orphan device count = %d, want 1", info.OrphanDeviceCount)
	}
}

func TestAdminClientStateMovesTrafficAndBindingHistoryExactlyOnce(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()
	password := "ABCDEFGHJKLMNPQR"
	today := time.Now().Format("2006-01-02")
	source := &Database{
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords: map[string]*PasswordEntry{
			password: {
				DownBytes: 8192,
				UpBytes:   4096,
				Traffic: []TrafficBucket{
					{Date: today, DownBytes: 8192, UpBytes: 4096},
				},
				TrafficImports: map[string]TrafficImport{
					"older-transfer": {DownBytes: 128, UpBytes: 64, AppliedAt: 100},
				},
				BindHistory: []BindHistoryEntry{
					{DeviceID: "old-phone", BoundAt: 10, UnboundAt: 20, Status: "unbound"},
					{DeviceID: "current-phone", BoundAt: 30, Status: "active"},
				},
			},
		},
		Devices: make(map[string]*ClientDevice),
	}
	exported, err := adminExportClientState(
		sourceDir,
		source,
		[]string{"--password", password},
	)
	if err != nil || exported.ClientState == nil {
		t.Fatalf("export-client-state failed: response=%#v error=%v", exported, err)
	}
	raw, err := json.Marshal(exported.ClientState)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	target := &Database{
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords: map[string]*PasswordEntry{
			password: {},
		},
		Devices: make(map[string]*ClientDevice),
	}
	args := []string{
		"--password", password,
		"--operation-id", "client-transfer-row",
		"--state", encoded,
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := adminImportClientState(targetDir, target, args); err != nil {
			t.Fatalf("import-client-state attempt %d failed: %v", attempt+1, err)
		}
	}
	entry := target.Passwords[password]
	if entry.DownBytes != 8192 || entry.UpBytes != 4096 {
		t.Fatalf("traffic totals changed during import: %#v", entry)
	}
	if !reflect.DeepEqual(entry.Traffic, source.Passwords[password].Traffic) {
		t.Fatalf("daily traffic history was not preserved: %#v", entry.Traffic)
	}
	if !reflect.DeepEqual(entry.BindHistory, source.Passwords[password].BindHistory) {
		t.Fatalf("binding history was not preserved: %#v", entry.BindHistory)
	}
	if _, ok := entry.TrafficImports["client-transfer-row"]; !ok {
		t.Fatal("idempotency marker was not recorded")
	}
	if entry.DeviceID != "" || len(target.Devices) != 0 {
		t.Fatal("live device keys must be rebound on the destination, not copied")
	}
}

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
		"--profile-name", "Домашний телефон",
		"--workers", "27",
		"--protocol", "tcp",
		"--listen-port", "9010",
		"--sni", "owner.example.com",
		"--ports", "56010,56011,9010",
		"--no-dns",
		"--vpn-dns-selection", "custom",
		"--vpn-dns-custom", "111.88.96.50,111.88.96.51",
	)
	listedOwner := request("list")
	if listedOwner.Server == nil {
		t.Fatal("list did not return server state after owner profile update")
	}
	profile := listedOwner.Server.AdminProfile
	if profile.VkHashes != "abcdefghijklmnop,qrstuvwxyzABCDEF" ||
		profile.SecondaryVkHash != "1234567890abcdef" ||
		profile.ProfileName != "Домашний телефон" ||
		profile.WorkersPerHash != 27 ||
		profile.Protocol != "tcp" ||
		profile.ListenPort != 9010 ||
		profile.SNI != "owner.example.com" ||
		!profile.NoDNS ||
		profile.VpnDNSSelection != "custom" ||
		profile.VpnDNSCustom != "111.88.96.50,111.88.96.51" ||
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

	request("update-admin-profile", "--vk-hashes", "fedcba9876543210")
	patchedOwner := request("list").Server.AdminProfile
	if patchedOwner.VkHashes != "fedcba9876543210" {
		t.Fatalf("owner profile patch did not update VK hashes: %#v", patchedOwner)
	}
	if patchedOwner.SecondaryVkHash != profile.SecondaryVkHash ||
		patchedOwner.ProfileName != profile.ProfileName ||
		patchedOwner.WorkersPerHash != profile.WorkersPerHash ||
		patchedOwner.Protocol != profile.Protocol ||
		patchedOwner.ListenPort != profile.ListenPort ||
		patchedOwner.SNI != profile.SNI ||
		patchedOwner.NoDNS != profile.NoDNS ||
		patchedOwner.VpnDNSSelection != profile.VpnDNSSelection ||
		patchedOwner.VpnDNSCustom != profile.VpnDNSCustom ||
		patchedOwner.Ports != profile.Ports {
		t.Fatalf("owner profile patch erased fields that were not provided: before=%#v after=%#v", profile, patchedOwner)
	}

	request("update-admin-profile", "--vpn-dns-selection", "cloudflare", "--vpn-dns-custom", "")
	publicDNSOwner := request("list").Server.AdminProfile
	if publicDNSOwner.VpnDNSSelection != "cloudflare" || publicDNSOwner.VpnDNSCustom != "" {
		t.Fatalf("owner VPN DNS selection did not clear stale custom addresses: %#v", publicDNSOwner)
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
	request(
		"merge-client-traffic",
		"--password", password,
		"--operation-id", "incident-row-return",
		"--down-bytes", "3072",
		"--up-bytes", "4096",
	)
	request(
		"merge-client-traffic",
		"--password", password,
		"--operation-id", "incident-row-return",
		"--down-bytes", "3072",
		"--up-bytes", "4096",
	)
	if db.Passwords[password].DownBytes != 3072 || db.Passwords[password].UpBytes != 4096 {
		t.Fatal("traffic import must be applied exactly once")
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

	custom := "ABCDEFGHJKLMNPQR"
	createdCustom := request(
		"create", "--client-password", custom, "--expires-at", "0", "--deactivated",
		"--label", "Перенос", "--vk-hash", "abcdefghijklmnop", "--ports", "56000,56001,9000",
	)
	if createdCustom.Password == nil || createdCustom.Password.Password != custom || createdCustom.Password.Status != "deactivated" {
		t.Fatalf("custom client was not created intact: %#v", createdCustom.Password)
	}
	if serverWrapKeys.Count() != 0 {
		t.Fatalf("deactivated custom client must not add a live WRAP key, got %d", serverWrapKeys.Count())
	}
	deactivatedPassword := "RSTUVWXYZ2345678"
	changedDeactivated := request("set-password", "--password", custom, "--new-password", deactivatedPassword)
	if changedDeactivated.Password == nil || changedDeactivated.Password.Status != "deactivated" || serverWrapKeys.Count() != 0 {
		t.Fatalf("deactivated password change enabled access: %#v keys=%d", changedDeactivated.Password, serverWrapKeys.Count())
	}
	custom = deactivatedPassword
	request("activate", "--password", custom)
	newPassword := "23456789ABCDEFGH"
	changed := request("set-password", "--password", custom, "--new-password", newPassword)
	if changed.Password == nil || changed.Password.Password != newPassword || changed.Password.Label != "Перенос" {
		t.Fatalf("password change lost client data: %#v", changed.Password)
	}
	if db.Passwords[custom] != nil || db.Passwords[newPassword] == nil {
		t.Fatal("password map key was not replaced")
	}
	if serverWrapKeys.Count() != 1 {
		t.Fatalf("password change must replace one live WRAP key, got %d", serverWrapKeys.Count())
	}
	request("delete", "--password", newPassword)
}

func TestClientPasswordValidation(t *testing.T) {
	valid := []string{"ABCDEFGHJKLMNPQR", "abcdefghjkmnpqrs", "23456789ABCDEFGH"}
	for _, value := range valid {
		if normalized, err := normalizeClientPassword(value); err != nil || normalized != value {
			t.Fatalf("valid password %q rejected: %v", value, err)
		}
	}
	invalid := []string{"short", "ABCDEFGHJKLMNPQ0", "ABCDEFGHJKLMNPQ_", "ABCDEFGHJKLMNPQRS"}
	for _, value := range invalid {
		if _, err := normalizeClientPassword(value); err == nil {
			t.Fatalf("invalid password %q accepted", value)
		}
	}
}

func TestAdminCreateRejectsPasswordConflicts(t *testing.T) {
	configDir := t.TempDir()
	loaded := &Database{
		MainPassword: "ABCDEFGHJKLMNPQR",
		DefaultPorts: "56000,56001,9000",
		MaxPasswords: 10,
		Passwords: map[string]*PasswordEntry{
			"RSTUVWXYZ2345678": {},
		},
		Devices: make(map[string]*ClientDevice),
	}
	if _, err := adminCreatePassword(configDir, loaded, []string{"--client-password", loaded.MainPassword}); err == nil {
		t.Fatal("main password was accepted as a client password")
	}
	if _, err := adminCreatePassword(configDir, loaded, []string{"--client-password", "RSTUVWXYZ2345678"}); err == nil {
		t.Fatal("duplicate client password was accepted")
	}
	if _, err := adminCreatePassword(configDir, loaded, []string{"--client-password", "23456789ABCDEFGH", "--expires-at", "1"}); err == nil {
		t.Fatal("expired imported client was accepted")
	}
	loaded.MaxPasswords = len(loaded.Passwords)
	if _, err := adminCreatePassword(configDir, loaded, []string{"--client-password", "23456789ABCDEFGH"}); err == nil {
		t.Fatal("client limit was ignored")
	}
}
