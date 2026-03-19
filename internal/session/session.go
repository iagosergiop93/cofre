// Package session manages temporary authentication sessions for the vault.
package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	FileName   = ".secrets-session"
	DefaultTTL = 30 * time.Minute
)

// File represents the session file structure on disk.
type File struct {
	DerivedKey string `json:"derived_key"` // base64-encoded 32-byte key
	VaultSalt  string `json:"vault_salt"`  // base64-encoded salt for vault binding
	ExpiresAt  int64  `json:"expires_at"`  // unix timestamp
}

// Data represents the decoded session data.
type Data struct {
	DerivedKey []byte
	VaultSalt  []byte
	ExpiresAt  time.Time
}

// GetPath returns the full path to the session file.
func GetPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, FileName), nil
}

// Exists checks if a session file exists.
func Exists() bool {
	path, err := GetPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// Save writes a new session file with the derived key and TTL.
func Save(derivedKey, vaultSalt []byte, ttl time.Duration) error {
	path, err := GetPath()
	if err != nil {
		return err
	}

	sessionFile := File{
		DerivedKey: base64.StdEncoding.EncodeToString(derivedKey),
		VaultSalt:  base64.StdEncoding.EncodeToString(vaultSalt),
		ExpiresAt:  time.Now().Add(ttl).Unix(),
	}

	data, err := json.MarshalIndent(sessionFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize session: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// Load reads and decodes the session file.
// Returns nil if the session doesn't exist or is corrupted.
func Load() (*Data, error) {
	path, err := GetPath()
	if err != nil {
		return nil, err
	}

	fileData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var sessionFile File
	if err := json.Unmarshal(fileData, &sessionFile); err != nil {
		return nil, fmt.Errorf("failed to parse session file: %w", err)
	}

	derivedKey, err := base64.StdEncoding.DecodeString(sessionFile.DerivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode derived key: %w", err)
	}

	vaultSalt, err := base64.StdEncoding.DecodeString(sessionFile.VaultSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault salt: %w", err)
	}

	return &Data{
		DerivedKey: derivedKey,
		VaultSalt:  vaultSalt,
		ExpiresAt:  time.Unix(sessionFile.ExpiresAt, 0),
	}, nil
}

// Clear removes the session file.
func Clear() error {
	path, err := GetPath()
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session file: %w", err)
	}

	return nil
}

// IsValid checks if a valid session exists for the given vault salt.
// Returns true if session exists, is not expired, and matches the vault salt.
func IsValid(vaultSalt []byte) bool {
	data, err := Load()
	if err != nil || data == nil {
		return false
	}

	// Check expiration
	if time.Now().After(data.ExpiresAt) {
		return false
	}

	// Check vault salt binding
	if !bytes.Equal(data.VaultSalt, vaultSalt) {
		return false
	}

	return true
}

// GetValidSession returns the session data if valid, nil otherwise.
func GetValidSession(vaultSalt []byte) *Data {
	data, err := Load()
	if err != nil || data == nil {
		return nil
	}

	if time.Now().After(data.ExpiresAt) {
		return nil
	}

	if !bytes.Equal(data.VaultSalt, vaultSalt) {
		return nil
	}

	return data
}
