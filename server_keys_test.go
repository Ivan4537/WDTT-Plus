package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKeysRefusesCorruptExistingFile(t *testing.T) {
	oldDB := db
	t.Cleanup(func() { db = oldDB })
	db = testDatabase("owner-secret", 0)
	dir := t.TempDir()
	path := filepath.Join(dir, "wg-keys.dat")
	corrupt := []byte("not-a-key\n")
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateKeys(dir); err == nil {
		t.Fatal("corrupt key file was accepted or replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(corrupt) {
		t.Fatal("corrupt key file changed after rejected load")
	}
}

func TestLoadOrGenerateKeysRefusesMissingFileForExistingState(t *testing.T) {
	oldDB := db
	t.Cleanup(func() { db = oldDB })
	db = testDatabase("owner-secret", 1)
	dir := t.TempDir()
	if _, err := loadOrGenerateKeys(dir); err == nil {
		t.Fatal("missing key file was regenerated for existing access state")
	}
	if _, err := os.Stat(filepath.Join(dir, "wg-keys.dat")); !os.IsNotExist(err) {
		t.Fatalf("unexpected key file after rejected generation: %v", err)
	}
}

func TestLoadOrGenerateKeysCreatesAndReloadsFirstInstallKeys(t *testing.T) {
	oldDB := db
	t.Cleanup(func() { db = oldDB })
	db = testDatabase("owner-secret", 0)
	dir := t.TempDir()
	created, err := loadOrGenerateKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadOrGenerateKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *created != *reloaded {
		t.Fatal("reloaded keys differ from first-install keys")
	}
	info, err := os.Stat(filepath.Join(dir, "wg-keys.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode = %o, want 600", info.Mode().Perm())
	}
}
