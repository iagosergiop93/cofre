package cli

import (
	"fmt"

	"secrets/internal/crypto"
	"secrets/internal/session"
	"secrets/internal/vault"
)

// Unlock explicitly starts a session without performing another operation.
func Unlock() {
	requireVault()

	vaultSalt, err := vault.GetSalt()
	if err != nil {
		FatalErr(err)
	}

	// Check if already unlocked
	if session.IsValid(vaultSalt) {
		fmt.Println("Vault is already unlocked")
		return
	}

	password, err := ReadPassword("Enter master password: ")
	if err != nil {
		FatalErr(err)
	}

	// Verify password by attempting to load vault
	_, salt, err := vault.Load(password)
	if err != nil {
		FatalErr(err)
	}

	// Create session
	derivedKey := crypto.DeriveKey(password, salt)
	if err := session.Save(derivedKey, salt, session.DefaultTTL); err != nil {
		FatalErr(err)
	}

	fmt.Println("Vault unlocked for 30 minutes")
}

// Lock explicitly ends the session.
func Lock() {
	if err := session.Clear(); err != nil {
		FatalErr(err)
	}
	fmt.Println("Vault locked")
}

// Status shows current session state.
func Status() {
	exists, err := vault.Exists()
	if err != nil {
		FatalErr(err)
	}
	if !exists {
		fmt.Println("No vault exists")
		return
	}

	vaultSalt, err := vault.GetSalt()
	if err != nil {
		FatalErr(err)
	}

	if session.IsValid(vaultSalt) {
		fmt.Println("Vault is unlocked")
	} else {
		fmt.Println("Vault is locked")
	}
}
