package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func backupTestConfig(t *testing.T) (string, *Database) {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "wdtt")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	loaded := &Database{
		MainPassword: "owner-password",
		Passwords: map[string]*PasswordEntry{
			"ABCDEFGHJKLMNPQR": {Label: "client", Ports: "56000,56001,9000"},
		},
		Devices: map[string]*ClientDevice{},
	}
	if err := persistDatabaseFile(filepath.Join(configDir, "passwords.json"), loaded); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(filepath.Join(configDir, "wg-keys.dat"), []byte(strings.Repeat(key+"\n", 4)), 0600); err != nil {
		t.Fatal(err)
	}
	return configDir, loaded
}

func TestServerBackupCreateVerifyAndExport(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	if err := os.WriteFile(filepath.Join(configDir, "outbound-profile.env"), []byte("WDTT_OUTBOUND_MODE=direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	created, err := createServerBackup(configDir, loaded, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if !created.Valid || created.PasswordCount != 1 || created.DeviceCount != 0 {
		t.Fatalf("unexpected summary: %+v", created)
	}
	if !created.ContentMetadata || !created.HasWireGuardKeys || !created.HasBackupPolicy || created.OutboundProfileMode != "direct" {
		t.Fatalf("backup content metadata is incomplete: %+v", created)
	}
	document, err := readServerBackupByID(configDir, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Files) != 4 {
		t.Fatalf("expected database, keys, outbound profile and backup policy, got %d files", len(document.Files))
	}
	policyFound := false
	for _, file := range document.Files {
		if file.Path == serverBackupPolicyFile {
			policyFound = true
		}
	}
	if !policyFound {
		t.Fatal("backup policy is missing from the full server backup")
	}
	response, err := adminBackupExport(configDir, []string{"--id", created.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.BackupDocument == nil || response.BackupDocument.ID != created.ID {
		t.Fatalf("unexpected export response: %+v", response)
	}
}

func TestServerBackupOutboundSummaryNeverExposesProfileValues(t *testing.T) {
	if got := summarizedBackupOutboundMode([]byte("WDTT_OUTBOUND_MODE=wireguard_vps\nWG_VPS_HOST_B64=c2VjcmV0\n")); got != "wireguard_vps" {
		t.Fatalf("expected safe outbound mode, got %q", got)
	}
	if got := summarizedBackupOutboundMode([]byte("WDTT_OUTBOUND_MODE=private-value\n")); got != "configured" {
		t.Fatalf("unexpected outbound value must be hidden, got %q", got)
	}
}

func TestServerBackupDeviceCountMatchesClientViewAndKeepsLegacyCompatibility(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	loaded.AdminProfile.DeviceIDs = []string{"owner-phone"}
	loaded.Passwords["ABCDEFGHJKLMNPQR"].DeviceID = "client-phone"
	loaded.Passwords["ABCDEFGHJKLMNPQR"].BindHistory = []BindHistoryEntry{
		{DeviceID: "client-phone", BoundAt: 10, Status: "active"},
		{DeviceID: "old-client-phone", BoundAt: 5, UnboundAt: 9, Status: "unbound"},
		{DeviceID: "rejected-phone", EventAt: 11, Status: "denied_mismatch"},
	}
	loaded.Devices = map[string]*ClientDevice{
		"client-phone": {DeviceID: "client-phone"},
		"owner-phone":  {DeviceID: "owner-phone"},
		"orphan":       {DeviceID: "orphan"},
	}
	if err := persistDatabaseFile(filepath.Join(configDir, "passwords.json"), loaded); err != nil {
		t.Fatal(err)
	}

	created, err := createServerBackup(configDir, loaded, "manual")
	if err != nil {
		t.Fatal(err)
	}
	info := buildAdminServerInfo(configDir, loaded)
	if created.DeviceCount != info.DeviceCount || created.DeviceCount != 2 {
		t.Fatalf("backup devices = %d, client view = %d, want 2", created.DeviceCount, info.DeviceCount)
	}
	document, err := readServerBackupByID(configDir, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if document.Version != serverBackupFormatVersion {
		t.Fatalf("backup version = %d, want %d", document.Version, serverBackupFormatVersion)
	}

	document.Version = serverBackupLegacyVersion
	document.DeviceCount = len(loaded.Devices)
	if err := validateServerBackupDocument(document); err != nil {
		t.Fatalf("legacy backup summary became invalid: %v", err)
	}
	if summary := backupSummaryFromDocument(document, nil); summary.DeviceCount != info.DeviceCount {
		t.Fatalf("legacy backup display devices = %d, client view = %d", summary.DeviceCount, info.DeviceCount)
	}
}

func TestServerBackupConfigureCreatesFirstCopyAndRotates(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	response, err := adminBackupConfigure(configDir, loaded, []string{
		"--enabled", "true", "--interval-hours", "12", "--retention", "2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.BackupStatus == nil || response.BackupStatus.ValidCount != 1 || !response.BackupStatus.Policy.Enabled {
		t.Fatalf("unexpected configured state: %+v", response.BackupStatus)
	}
	for i := 0; i < 3; i++ {
		loaded.AdminDownBytes++
		if _, err := createServerBackup(configDir, loaded, "manual"); err != nil {
			t.Fatal(err)
		}
	}
	status, err := serverBackupStatusFor(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.ValidCount != 2 || len(status.Backups) != 2 {
		t.Fatalf("retention did not keep exactly two valid copies: %+v", status)
	}
}

func TestServerBackupRotationNeverDeletesProtectedFreshCopy(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	for i := 0; i < 3; i++ {
		loaded.AdminDownBytes++
		if _, err := createServerBackup(configDir, loaded, "manual"); err != nil {
			t.Fatal(err)
		}
	}
	before, err := listServerBackups(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 3 {
		t.Fatalf("expected three backups before rotation, got %d", len(before))
	}
	protectedID := before[len(before)-1].ID
	if err := rotateServerBackups(configDir, 2, protectedID); err != nil {
		t.Fatal(err)
	}
	after, err := listServerBackups(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("expected two backups after rotation, got %d", len(after))
	}
	for _, backup := range after {
		if backup.ID == protectedID {
			return
		}
	}
	t.Fatalf("fresh protected backup %s was deleted during rotation", protectedID)
}

func TestServerBackupRejectsUnsafeSourceAndKeepsLastGoodCopy(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	created, err := createServerBackup(configDir, loaded, "manual")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(configDir, "outbound-profile.env")); err != nil {
		t.Fatal(err)
	}
	if _, err := createServerBackup(configDir, loaded, "manual"); err == nil {
		t.Fatal("backup unexpectedly followed an outbound-profile symlink")
	}
	if err := deleteServerBackup(configDir, created.ID); err == nil || !strings.Contains(err.Error(), "последнюю") {
		t.Fatalf("last valid backup deletion must be refused, got %v", err)
	}
}

func TestServerBackupReportsCorruptCopyWithoutDeletingIt(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	if _, err := createServerBackup(configDir, loaded, "manual"); err != nil {
		t.Fatal(err)
	}
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		t.Fatal(err)
	}
	badID := "20260902T120000Z-abcdef123456"
	badPath := filepath.Join(snapshots, badID+".wdtt-snapshot")
	if err := os.WriteFile(badPath, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := serverBackupStatusFor(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if status.ValidCount != 1 || status.BrokenCount != 1 {
		t.Fatalf("corrupt copy was not reported: %+v", status)
	}
	if status.TotalBytes <= int64(len("{broken")) {
		t.Fatalf("total size must include both valid and corrupt copies: %+v", status)
	}
	if _, err := os.Stat(badPath); err != nil {
		t.Fatalf("corrupt copy must not be auto-deleted: %v", err)
	}
}

func TestServerBackupPolicyValidation(t *testing.T) {
	for _, policy := range []serverBackupPolicy{
		{IntervalHours: 5, RetentionCount: 14},
		{IntervalHours: 24, RetentionCount: 1},
		{IntervalHours: 169, RetentionCount: 14},
		{IntervalHours: 24, RetentionCount: 91},
	} {
		if _, err := normalizeServerBackupPolicy(policy); err == nil {
			t.Fatalf("unsafe policy accepted: %+v", policy)
		}
	}
}

func TestServerBackupDocumentRejectsUnknownReasonAndUnsafeOutboundProfile(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	if err := os.WriteFile(filepath.Join(configDir, "outbound-profile.env"), []byte("WDTT_OUTBOUND_MODE=direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	created, err := createServerBackup(configDir, loaded, "manual")
	if err != nil {
		t.Fatal(err)
	}
	document, err := readServerBackupByID(configDir, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	document.Reason = "untrusted"
	if err := validateServerBackupDocument(document); err == nil {
		t.Fatal("unknown backup reason was accepted")
	}
	if err := validateBackupOutboundProfile([]byte("lowercase=value\n")); err == nil {
		t.Fatal("unsafe outbound profile field was accepted")
	}
}

func TestServerBackupFailureIsRecordedAndRetriesAreThrottled(t *testing.T) {
	configDir, loaded := backupTestConfig(t)
	if err := os.Chmod(filepath.Join(configDir, "wg-keys.dat"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := createServerBackup(configDir, loaded, "scheduled"); err == nil {
		t.Fatal("unsafe source permissions unexpectedly produced a backup")
	}
	state, err := loadServerBackupState(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastAttemptAt == 0 || state.LastError == "" || state.LastSuccessAt != 0 {
		t.Fatalf("backup failure was not persisted: %+v", state)
	}
	now := state.LastAttemptAt + 1
	next := nextServerBackupRunAt(defaultServerBackupPolicy(), state, now)
	want := state.LastAttemptAt + int64((15*time.Minute)/time.Second)
	if next != want {
		t.Fatalf("unexpected retry time: got %d want %d", next, want)
	}
}
