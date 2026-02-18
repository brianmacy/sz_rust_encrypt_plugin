# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust encryption plugin project (`sz_rust_encrypt_plugin`). The repository is currently empty and ready for initial development.

## Development Commands

Since this is a new Rust project, the following commands will be relevant once the project is initialized:

```bash
# Initialize the Rust project
cargo init

# Build the project
cargo build

# Run tests
cargo test

# Run tests with coverage
cargo test -- --nocapture

# Run a specific test
cargo test test_name

# Check code without building
cargo check

# Format code
cargo fmt

# Lint with clippy
cargo clippy

# Build for release
cargo build --release
```

## Project Setup Guidelines

### Cargo.toml Configuration

- Use Rust 2024 edition when creating Cargo.toml
- Include appropriate encryption-related dependencies (e.g., `ring`, `aes`, `chacha20poly1305`)
- Add development dependencies for testing (e.g., `proptest` for property-based testing)

### Code Architecture Considerations

- Implement secure encryption/decryption interfaces
- Use strong typing for keys, nonces, and encrypted data
- Implement proper error handling for cryptographic operations
- Follow Rust's memory safety principles - avoid unsafe code unless absolutely necessary
- Design for thread safety if the plugin will be used in concurrent contexts

### Security Best Practices

- Never log or expose encryption keys or sensitive data
- Use constant-time operations for cryptographic comparisons
- Implement proper key derivation functions
- Use authenticated encryption modes
- Clear sensitive data from memory when possible (consider using zeroize crate)

### Testing Strategy

- Unit tests for all cryptographic functions
- Property-based tests for encryption/decryption round-trips
- Integration tests for plugin interfaces
- Security tests for timing attacks and side-channel resistance
- Test vector validation against known standards

### Dependencies to Consider

- `ring` or `rustcrypto` ecosystem for cryptographic primitives
- `zeroize` for secure memory clearing
- `serde` for serialization if needed
- `thiserror` or `anyhow` for error handling
- `proptest` for property-based testing
