// Package vault handles encrypted secrets storage and retrieval.
package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"secrets/internal/crypto"
)

const FileName = ".secrets-vault.json"

// File represents the encrypted vault file structure.
type File struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

// Secrets represents the decrypted secrets structure.
type Secrets struct {
	Entries map[string]string `json:"secrets"`
}

// GetPath returns the full path to the vault file.
func GetPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, FileName), nil
}

// Exists checks if the vault file exists.
func Exists() (bool, error) {
	path, err := GetPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Load reads and decrypts the vault file.
func Load(password string) (*Secrets, []byte, error) {
	path, err := GetPath()
	if err != nil {
		return nil, nil, err
	}

	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	var vaultFile File
	if err := json.Unmarshal(fileData, &vaultFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse vault file: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(vaultFile.Salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(vaultFile.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(vaultFile.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode data: %w", err)
	}

	key := crypto.DeriveKey(password, salt)
	plaintext, err := crypto.Decrypt(ciphertext, nonce, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt vault (wrong password?): %w", err)
	}

	var secrets Secrets
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, nil, fmt.Errorf("failed to parse secrets: %w", err)
	}

	return &secrets, salt, nil
}

// Save encrypts and writes the vault file.
func Save(data *Secrets, password string, salt []byte) error {
	path, err := GetPath()
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to serialize secrets: %w", err)
	}

	key := crypto.DeriveKey(password, salt)
	nonce, ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault: %w", err)
	}

	vaultFile := File{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Data:    base64.StdEncoding.EncodeToString(ciphertext),
	}

	fileData, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize vault: %w", err)
	}

	if err := os.WriteFile(path, fileData, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	return nil
}

// Create creates a new empty vault.
func Create(password string) error {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	data := &Secrets{
		Entries: make(map[string]string),
	}

	return Save(data, password, salt)
}
