package cli

import (
	"fmt"
	"sort"

	"secrets/internal/vault"
)

// requireVault checks that the vault exists and exits if it doesn't.
func requireVault() {
	exists, err := vault.Exists()
	if err != nil {
		FatalErr(err)
	}
	if !exists {
		Fatal("vault does not exist\nRun 'secrets init' first")
	}
}

// requireNoVault checks that no vault exists and exits if one does.
func requireNoVault() {
	exists, err := vault.Exists()
	if err != nil {
		FatalErr(err)
	}
	if exists {
		Fatal("vault already exists\nDelete ~/.secrets-vault.json to create a new vault")
	}
}

// unlockVault prompts for password and loads the vault.
func unlockVault() (*vault.Secrets, []byte, string) {
	password, err := ReadPassword("Enter master password: ")
	if err != nil {
		FatalErr(err)
	}

	data, salt, err := vault.Load(password)
	if err != nil {
		FatalErr(err)
	}

	return data, salt, password
}

// Init creates a new vault with a master password.
func Init() {
	requireNoVault()

	password, err := ReadPassword("Enter master password: ")
	if err != nil {
		FatalErr(err)
	}

	if len(password) < 8 {
		Fatal("password must be at least 8 characters")
	}

	confirm, err := ReadPassword("Confirm master password: ")
	if err != nil {
		FatalErr(err)
	}

	if password != confirm {
		Fatal("passwords do not match")
	}

	if err := vault.Create(password); err != nil {
		FatalErr(err)
	}

	fmt.Println("Vault created successfully")
}

// Set adds or updates a secret.
func Set(key string) {
	requireVault()
	data, salt, password := unlockVault()

	value, err := ReadPassword("Enter secret value: ")
	if err != nil {
		FatalErr(err)
	}

	_, updating := data.Entries[key]
	data.Entries[key] = value

	if err := vault.Save(data, password, salt); err != nil {
		FatalErr(err)
	}

	if updating {
		fmt.Printf("Secret '%s' updated\n", key)
	} else {
		fmt.Printf("Secret '%s' added\n", key)
	}
}

// Get retrieves a secret value.
func Get(key string) {
	requireVault()
	data, _, _ := unlockVault()

	value, ok := data.Entries[key]
	if !ok {
		Fatal("secret '%s' not found", key)
	}

	fmt.Println(value)
}

// List shows all secret keys.
func List() {
	requireVault()
	data, _, _ := unlockVault()

	if len(data.Entries) == 0 {
		fmt.Println("No secrets stored")
		return
	}

	keys := make([]string, 0, len(data.Entries))
	for k := range data.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Println(k)
	}
}

// Delete removes a secret.
func Delete(key string) {
	requireVault()
	data, salt, password := unlockVault()

	if _, ok := data.Entries[key]; !ok {
		Fatal("secret '%s' not found", key)
	}

	delete(data.Entries, key)

	if err := vault.Save(data, password, salt); err != nil {
		FatalErr(err)
	}

	fmt.Printf("Secret '%s' deleted\n", key)
}

// PrintUsage displays help information.
func PrintUsage() {
	fmt.Println("secrets - A secure secrets manager")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  secrets init          Create a new vault")
	fmt.Println("  secrets set <key>     Add or update a secret")
	fmt.Println("  secrets get <key>     Retrieve a secret")
	fmt.Println("  secrets list          List all secret keys")
	fmt.Println("  secrets delete <key>  Remove a secret")
	fmt.Println("  secrets help          Show this help message")
}
