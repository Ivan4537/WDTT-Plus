package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDatabase(mainPassword string, passwordCount int) *Database {
	passwords := make(map[string]*PasswordEntry, passwordCount)
	for index := 0; index < passwordCount; index++ {
		passwords[string(rune('a'+index))] = &PasswordEntry{ExpiresAt: 0}
	}
	return &Database{
		MainPassword: mainPassword,
		DNS:          defaultDNS,
		MaxPasswords: defaultMaxGeneratedPasswords,
		DefaultPorts: "56000,56001,9000",
		Passwords:    passwords,
		Devices:      map[string]*ClientDevice{},
	}
}

func TestPersistDatabaseKeepsValidatedPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.json")
	first := testDatabase("owner-secret", 2)
	if err := persistDatabaseFile(path, first); err != nil {
		t.Fatalf("first persist failed: %v", err)
	}
	second := testDatabase("owner-secret", 1)
	if err := persistDatabaseFile(path, second); err != nil {
		t.Fatalf("second persist failed: %v", err)
	}

	current, err := loadDatabaseFile(path)
	if err != nil {
		t.Fatalf("current database is invalid: %v", err)
	}
	previous, err := loadDatabaseFile(path + databasePreviousSuffix)
	if err != nil {
		t.Fatalf("previous database is invalid: %v", err)
	}
	if len(current.Passwords) != 1 || len(previous.Passwords) != 2 {
		t.Fatalf("unexpected generations: current=%d previous=%d", len(current.Passwords), len(previous.Passwords))
	}
	for _, candidate := range []string{path, path + databasePreviousSuffix} {
		info, err := os.Stat(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o, want 600", candidate, info.Mode().Perm())
		}
	}
}

func TestPersistDatabaseRefusesToOverwriteCorruptCurrentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.json")
	corrupt := []byte(`{"main_password":"owner-secret","passwords":`)
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistDatabaseFile(path, testDatabase("owner-secret", 1)); err == nil {
		t.Fatal("corrupt current database was overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(corrupt) {
		t.Fatal("corrupt source changed after rejected persist")
	}
}

func TestInitDBFailsClosedForCorruptOrMissingDatabase(t *testing.T) {
	oldDB, oldDBFile := db, dbFile
	t.Cleanup(func() {
		db, dbFile = oldDB, oldDBFile
	})

	t.Run("corrupt existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "passwords.json")
		corrupt := []byte(`not-json`)
		if err := os.WriteFile(path, corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		if err := initDB(dir, "owner-secret", "", "", ""); err == nil {
			t.Fatal("initDB accepted corrupt database")
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(corrupt) {
			t.Fatal("initDB overwrote corrupt database")
		}
	})

	t.Run("missing file without explicit first-install password", func(t *testing.T) {
		dir := t.TempDir()
		if err := initDB(dir, "", "", "", ""); err == nil {
			t.Fatal("initDB created a database without a first-install password")
		}
		if _, err := os.Stat(filepath.Join(dir, "passwords.json")); !os.IsNotExist(err) {
			t.Fatalf("unexpected database after rejected init: %v", err)
		}
	})

	t.Run("missing primary with recovery generation", func(t *testing.T) {
		dir := t.TempDir()
		previousPath := filepath.Join(dir, "passwords.json") + databasePreviousSuffix
		if err := persistDatabaseFile(previousPath, testDatabase("owner-secret", 2)); err != nil {
			t.Fatal(err)
		}
		err := initDB(dir, "owner-secret", "", "", "")
		if err == nil || !strings.Contains(err.Error(), "предыдущая копия") {
			t.Fatalf("unexpected init result: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "passwords.json")); !os.IsNotExist(err) {
			t.Fatalf("primary database unexpectedly created: %v", err)
		}
	})
}

func TestInitDBCreatesFirstDatabaseOnlyWithExplicitPassword(t *testing.T) {
	oldDB, oldDBFile := db, dbFile
	t.Cleanup(func() {
		db, dbFile = oldDB, oldDBFile
	})
	dir := t.TempDir()
	if err := initDB(dir, "owner-secret", "", "", ""); err != nil {
		t.Fatalf("first init failed: %v", err)
	}
	loaded, err := loadDatabaseFile(filepath.Join(dir, "passwords.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MainPassword != "owner-secret" || len(loaded.Passwords) != 0 {
		t.Fatalf("unexpected first database: %#v", loaded)
	}
}

func TestInitDBPreservesStoredDNSWithoutExplicitOverride(t *testing.T) {
	oldDB, oldDBFile := db, dbFile
	t.Cleanup(func() {
		db, dbFile = oldDB, oldDBFile
	})
	dir := t.TempDir()
	stored := testDatabase("owner-secret", 0)
	stored.DNS = "1.1.1.1,1.0.0.1"
	if err := persistDatabaseFile(filepath.Join(dir, "passwords.json"), stored); err != nil {
		t.Fatal(err)
	}
	if err := initDB(dir, "", "", "", ""); err != nil {
		t.Fatalf("restart with stored DNS failed: %v", err)
	}
	if db.DNS != "1.1.1.1,1.0.0.1" || getServerDNS() != "1.1.1.1,1.0.0.1" {
		t.Fatalf("stored DNS was replaced on restart: db=%q runtime=%q", db.DNS, getServerDNS())
	}
}

func TestBotRuntimeCredentialsComeFromProtectedDatabaseAfterUpdate(t *testing.T) {
	oldDB, oldDBFile := db, dbFile
	t.Cleanup(func() {
		db, dbFile = oldDB, oldDBFile
	})
	dir := t.TempDir()
	stored := testDatabase("owner-secret", 0)
	stored.BotToken = "stored-bot-token"
	stored.AdminID = "123456"
	if err := persistDatabaseFile(filepath.Join(dir, "passwords.json"), stored); err != nil {
		t.Fatal(err)
	}

	// Version 16+ starts without secret command-line flags. The already stored
	// values must still activate the internal bot after the service restarts.
	if err := initDB(dir, "", "", "", ""); err != nil {
		t.Fatalf("restart with stored bot credentials failed: %v", err)
	}
	token, adminID := botRuntimeCredentials()
	if token != "stored-bot-token" || adminID != "123456" {
		t.Fatalf("stored bot credentials were not selected: token=%t admin=%q", token != "", adminID)
	}
}

func TestBotRuntimeCredentialsUseExplicitFirstInstallValues(t *testing.T) {
	oldDB, oldDBFile := db, dbFile
	t.Cleanup(func() {
		db, dbFile = oldDB, oldDBFile
	})
	dir := t.TempDir()
	if err := initDB(dir, "owner-secret", "654321", "first-install-token", ""); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	token, adminID := botRuntimeCredentials()
	if token != "first-install-token" || adminID != "654321" {
		t.Fatalf("first-install bot credentials were not selected: token=%t admin=%q", token != "", adminID)
	}
}

func TestInitDBValidatesExplicitDNSOverride(t *testing.T) {
	oldDB, oldDBFile := db, dbFile
	t.Cleanup(func() {
		db, dbFile = oldDB, oldDBFile
	})
	dir := t.TempDir()
	if err := initDB(dir, "owner-secret", "", "", "9.9.9.9, 149.112.112.112"); err != nil {
		t.Fatalf("valid DNS override failed: %v", err)
	}
	if db.DNS != "9.9.9.9,149.112.112.112" {
		t.Fatalf("DNS override was not normalized: %q", db.DNS)
	}

	dir = t.TempDir()
	if err := initDB(dir, "owner-secret", "", "", "invalid DNS"); err == nil {
		t.Fatal("invalid DNS override was accepted")
	}
}
