# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Instructions

Ensure the generated code is well-organized and modular with clear separation of concerns.

Use descriptive variable, function and class names that reflect their purpose.

Include concise, meaningful inline comments and documentation to explain non-obvious logic.

Adhere to established coding standards and style guides relevant to the language or framework.

Write code that is maintainable, with proper error handling and clear boundaries for functionality.

Incorporate unit tests or example test cases to demonstrate and verify functionality.

Write code that is self-contained with minimal dependencies, facilitating easy integration into larger projects.

## Build Commands

```bash
make build              # Build binary to bin/secrets
make test               # Run all tests
make clean              # Remove build artifacts
go test -v ./internal/crypto   # Run tests for a single package
```

## Architecture

Cofre is a CLI secrets manager that stores encrypted key-value pairs in `~/.secrets-vault.json`.

### Package Structure

```
cmd/secrets/main.go     → Entry point, command routing only
internal/
  cli/                  → User interaction (commands.go) and terminal I/O (input.go)
  vault/                → Vault file operations (Load, Save, Create, Exists)
  crypto/               → Cryptographic primitives (Argon2id key derivation, AES-256-GCM)
```

### Data Flow

CLI commands follow this pattern:
1. `requireVault()` / `requireNoVault()` - check vault state
2. `unlockVault()` - prompt password, derive key, decrypt vault
3. Modify `vault.Secrets.Entries` map
4. `vault.Save()` - re-encrypt and write

### Cryptography

- **Key derivation**: Argon2id (64MB memory, 4 threads, 1 iteration)
- **Encryption**: AES-256-GCM with random 12-byte nonce per save
- **Storage format**: JSON with base64-encoded salt, nonce, ciphertext
- **File permissions**: 0600
