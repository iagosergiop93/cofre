package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetPath(t *testing.T) {
	path, err := GetPath()
	if err != nil {
		t.Fatalf("GetPath() error: %v", err)
	}

	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, FileName)
	if path != expected {
		t.Errorf("GetPath() = %s, want %s", path, expected)
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Clean up before and after test
	defer Clear()
	Clear()

	derivedKey := make([]byte, 32)
	for i := range derivedKey {
		derivedKey[i] = byte(i)
	}
	vaultSalt := []byte("testsalt12345678")

	err := Save(derivedKey, vaultSalt, DefaultTTL)
	if err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	data, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if data == nil {
		t.Fatal("Load() returned nil data")
	}

	if len(data.DerivedKey) != 32 {
		t.Errorf("DerivedKey length = %d, want 32", len(data.DerivedKey))
	}
	for i := range derivedKey {
		if data.DerivedKey[i] != derivedKey[i] {
			t.Errorf("DerivedKey[%d] = %d, want %d", i, data.DerivedKey[i], derivedKey[i])
		}
	}

	if string(data.VaultSalt) != string(vaultSalt) {
		t.Errorf("VaultSalt = %s, want %s", data.VaultSalt, vaultSalt)
	}
}

func TestLoadNonExistent(t *testing.T) {
	defer Clear()
	Clear()

	data, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if data != nil {
		t.Errorf("Load() = %v, want nil for non-existent session", data)
	}
}

func TestClear(t *testing.T) {
	derivedKey := make([]byte, 32)
	vaultSalt := []byte("testsalt12345678")

	Save(derivedKey, vaultSalt, DefaultTTL)

	err := Clear()
	if err != nil {
		t.Fatalf("Clear() error: %v", err)
	}

	if Exists() {
		t.Error("Exists() = true after Clear(), want false")
	}
}

func TestIsValid(t *testing.T) {
	defer Clear()
	Clear()

	derivedKey := make([]byte, 32)
	vaultSalt := []byte("testsalt12345678")

	// No session exists
	if IsValid(vaultSalt) {
		t.Error("IsValid() = true for non-existent session, want false")
	}

	// Create valid session
	Save(derivedKey, vaultSalt, DefaultTTL)
	if !IsValid(vaultSalt) {
		t.Error("IsValid() = false for valid session, want true")
	}

	// Wrong salt
	wrongSalt := []byte("wrongsalt1234567")
	if IsValid(wrongSalt) {
		t.Error("IsValid() = true for wrong salt, want false")
	}
}

func TestExpiredSession(t *testing.T) {
	defer Clear()
	Clear()

	derivedKey := make([]byte, 32)
	vaultSalt := []byte("testsalt12345678")

	// Create session that expires immediately
	Save(derivedKey, vaultSalt, -1*time.Second)

	if IsValid(vaultSalt) {
		t.Error("IsValid() = true for expired session, want false")
	}

	data := GetValidSession(vaultSalt)
	if data != nil {
		t.Error("GetValidSession() returned non-nil for expired session")
	}
}

func TestGetValidSession(t *testing.T) {
	defer Clear()
	Clear()

	derivedKey := make([]byte, 32)
	for i := range derivedKey {
		derivedKey[i] = byte(i)
	}
	vaultSalt := []byte("testsalt12345678")

	// No session
	data := GetValidSession(vaultSalt)
	if data != nil {
		t.Error("GetValidSession() returned non-nil for no session")
	}

	// Create valid session
	Save(derivedKey, vaultSalt, DefaultTTL)
	data = GetValidSession(vaultSalt)
	if data == nil {
		t.Fatal("GetValidSession() returned nil for valid session")
	}

	// Verify key matches
	for i := range derivedKey {
		if data.DerivedKey[i] != derivedKey[i] {
			t.Errorf("DerivedKey[%d] = %d, want %d", i, data.DerivedKey[i], derivedKey[i])
		}
	}
}

func TestFilePermissions(t *testing.T) {
	defer Clear()
	Clear()

	derivedKey := make([]byte, 32)
	vaultSalt := []byte("testsalt12345678")

	Save(derivedKey, vaultSalt, DefaultTTL)

	path, _ := GetPath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}

	// Check that file permissions are 0600
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("File permissions = %o, want 0600", perm)
	}
}
