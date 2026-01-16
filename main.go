package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init":
		cmdInit()
	case "set":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: missing key argument")
			fmt.Fprintln(os.Stderr, "Usage: secrets set <key>")
			os.Exit(1)
		}
		cmdSet(os.Args[2])
	case "get":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: missing key argument")
			fmt.Fprintln(os.Stderr, "Usage: secrets get <key>")
			os.Exit(1)
		}
		cmdGet(os.Args[2])
	case "list":
		cmdList()
	case "delete":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: missing key argument")
			fmt.Fprintln(os.Stderr, "Usage: secrets delete <key>")
			os.Exit(1)
		}
		cmdDelete(os.Args[2])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
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

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after password input
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}

func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func cmdInit() {
	exists, err := VaultExists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if exists {
		fmt.Fprintln(os.Stderr, "Error: vault already exists")
		fmt.Fprintln(os.Stderr, "Delete ~/.secrets-vault.json to create a new vault")
		os.Exit(1)
	}

	password, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "Error: password must be at least 8 characters")
		os.Exit(1)
	}

	confirm, err := readPassword("Confirm master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if password != confirm {
		fmt.Fprintln(os.Stderr, "Error: passwords do not match")
		os.Exit(1)
	}

	if err := CreateVault(password); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Vault created successfully")
}

func cmdSet(key string) {
	exists, err := VaultExists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !exists {
		fmt.Fprintln(os.Stderr, "Error: vault does not exist")
		fmt.Fprintln(os.Stderr, "Run 'secrets init' first")
		os.Exit(1)
	}

	password, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	data, salt, err := LoadVault(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	value, err := readPassword("Enter secret value: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	_, updating := data.Secrets[key]
	data.Secrets[key] = value

	if err := SaveVault(data, password, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if updating {
		fmt.Printf("Secret '%s' updated\n", key)
	} else {
		fmt.Printf("Secret '%s' added\n", key)
	}
}

func cmdGet(key string) {
	exists, err := VaultExists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !exists {
		fmt.Fprintln(os.Stderr, "Error: vault does not exist")
		fmt.Fprintln(os.Stderr, "Run 'secrets init' first")
		os.Exit(1)
	}

	password, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	data, _, err := LoadVault(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	value, ok := data.Secrets[key]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", key)
		os.Exit(1)
	}

	fmt.Println(value)
}

func cmdList() {
	exists, err := VaultExists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !exists {
		fmt.Fprintln(os.Stderr, "Error: vault does not exist")
		fmt.Fprintln(os.Stderr, "Run 'secrets init' first")
		os.Exit(1)
	}

	password, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	data, _, err := LoadVault(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(data.Secrets) == 0 {
		fmt.Println("No secrets stored")
		return
	}

	keys := make([]string, 0, len(data.Secrets))
	for k := range data.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Println(k)
	}
}

func cmdDelete(key string) {
	exists, err := VaultExists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !exists {
		fmt.Fprintln(os.Stderr, "Error: vault does not exist")
		fmt.Fprintln(os.Stderr, "Run 'secrets init' first")
		os.Exit(1)
	}

	password, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	data, salt, err := LoadVault(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if _, ok := data.Secrets[key]; !ok {
		fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", key)
		os.Exit(1)
	}

	delete(data.Secrets, key)

	if err := SaveVault(data, password, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Secret '%s' deleted\n", key)
}
