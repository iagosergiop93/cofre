package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const VaultFileName = ".secrets-vault.json"

// VaultFile represents the encrypted vault file structure
type VaultFile struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

// SecretsData represents the decrypted secrets structure
type SecretsData struct {
	Secrets map[string]string `json:"secrets"`
}

// GetVaultPath returns the full path to the vault file
func GetVaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, VaultFileName), nil
}

// VaultExists checks if the vault file exists
func VaultExists() (bool, error) {
	path, err := GetVaultPath()
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

// LoadVault reads and decrypts the vault file
func LoadVault(password string) (*SecretsData, []byte, error) {
	path, err := GetVaultPath()
	if err != nil {
		return nil, nil, err
	}

	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	var vault VaultFile
	if err := json.Unmarshal(fileData, &vault); err != nil {
		return nil, nil, fmt.Errorf("failed to parse vault file: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(vault.Salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(vault.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(vault.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode data: %w", err)
	}

	key := DeriveKey(password, salt)
	plaintext, err := Decrypt(ciphertext, nonce, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt vault (wrong password?): %w", err)
	}

	var secrets SecretsData
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, nil, fmt.Errorf("failed to parse secrets: %w", err)
	}

	return &secrets, salt, nil
}

// SaveVault encrypts and writes the vault file
func SaveVault(data *SecretsData, password string, salt []byte) error {
	path, err := GetVaultPath()
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to serialize secrets: %w", err)
	}

	key := DeriveKey(password, salt)
	nonce, ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault: %w", err)
	}

	vault := VaultFile{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Data:    base64.StdEncoding.EncodeToString(ciphertext),
	}

	fileData, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize vault: %w", err)
	}

	if err := os.WriteFile(path, fileData, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	return nil
}

// CreateVault creates a new empty vault
func CreateVault(password string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	data := &SecretsData{
		Secrets: make(map[string]string),
	}

	return SaveVault(data, password, salt)
}
