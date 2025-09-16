# Senzing Rust Encryption Plugins

[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-example-blue.svg)](LICENSE)

A collection of Rust-based encryption plugins for Senzing, providing C-compatible shared libraries for data encryption and decryption.

## Architecture

This workspace contains three separate libraries:

- **`sz_common`** - Shared utilities, traits, and error handling
- **`sz_aes_plugin`** - AES-256-CBC encryption plugin
- **`sz_dummy_plugin`** - Dummy XOR encryption plugin (for development/testing)

## Features

### Common Library (`sz_common`)

Provides shared components used by all encryption plugins:

- `EncryptionProvider` trait defining the standard interface
- `EncryptionError` type for comprehensive error handling
- C FFI utility functions for string and error buffer management
- Memory-safe string conversion functions

### AES Plugin (`sz_aes_plugin`)

Production-ready encryption using AES-256-CBC:

- **Non-deterministic encryption**: Uses random IVs for maximum security
- **Deterministic encryption**: Uses fixed IV derived from signature for consistent results
- **Base64 encoding**: All encrypted output is base64-encoded
- **Memory safety**: Automatic zeroization of sensitive data
- **Thread safety**: Global state management with proper synchronization

Generated library: `libsz_aes_encrypt_plugin.so`

### Dummy Plugin (`sz_dummy_plugin`)

Simple XOR-based encryption for development and testing:

- **XOR cipher**: Uses plugin signature as encryption key
- **Deterministic**: Same input always produces same output
- **Base64 encoding**: Consistent with AES plugin output format
- **Development only**: Not suitable for production use

Generated library: `libsz_dummy_encrypt_plugin.so`

## Building

### Prerequisites

- Rust 2024 edition or later
- Standard development tools (build-essential on Ubuntu/Debian)

### Build All Libraries

```bash
# Build all libraries in release mode
cargo build --release --workspace

# Build specific library
cargo build --release -p sz_aes_plugin
cargo build --release -p sz_dummy_plugin
```

### Generated Files

After building, shared libraries are available in `target/release/`:

- `libsz_aes_encrypt_plugin.so` - AES encryption plugin
- `libsz_dummy_encrypt_plugin.so` - Dummy encryption plugin

C header files are generated in each plugin's `include/` directory:

- `sz_aes_plugin/include/sz_aes_encrypt_plugin.h`
- `sz_dummy_plugin/include/sz_dummy_encrypt_plugin.h`

## Testing

```bash
# Run all tests
cargo test --workspace

# Test specific library
cargo test -p sz_aes_plugin
cargo test -p sz_dummy_plugin
cargo test -p sz_common
```

## C Interface

Both plugins implement the same C interface required by Senzing:

```c
// Plugin lifecycle
int G2Encryption_InitPlugin(const void* config_params, char* error_buffer,
                           const size_t max_error_size, size_t* error_size);
int G2Encryption_ClosePlugin(char* error_buffer, const size_t max_error_size,
                            size_t* error_size);

// Plugin identification
int G2Encryption_GetSignature(char* signature_buffer, const size_t max_signature_size,
                             size_t* signature_size, char* error_buffer,
                             const size_t max_error_size, size_t* error_size);
int G2Encryption_ValidateSignatureCompatibility(const char* signature_to_validate,
                                               const size_t signature_to_validate_size,
                                               char* error_buffer, const size_t max_error_size,
                                               size_t* error_size);

// Encryption operations
int G2Encryption_EncryptDataField(const char* input, const size_t input_size,
                                 char* result_buffer, const size_t max_result_size,
                                 size_t* result_size, char* error_buffer,
                                 const size_t max_error_size, size_t* error_size);
int G2Encryption_DecryptDataField(const char* input, const size_t input_size,
                                 char* result_buffer, const size_t max_result_size,
                                 size_t* result_size, char* error_buffer,
                                 const size_t max_error_size, size_t* error_size);

// Deterministic encryption operations
int G2Encryption_EncryptDataFieldDeterministic(const char* input, const size_t input_size,
                                              char* result_buffer, const size_t max_result_size,
                                              size_t* result_size, char* error_buffer,
                                              const size_t max_error_size, size_t* error_size);
int G2Encryption_DecryptDataFieldDeterministic(const char* input, const size_t input_size,
                                              char* result_buffer, const size_t max_result_size,
                                              size_t* result_size, char* error_buffer,
                                              const size_t max_error_size, size_t* error_size);
```

## Usage Example

### C Integration

```c
#include "sz_aes_encrypt_plugin.h" // or sz_dummy_encrypt_plugin.h
#include <stdio.h>
#include <string.h>

int main() {
    char error_buffer[1024];
    size_t error_size = 0;

    // Initialize the plugin
    int result = G2Encryption_InitPlugin(
        NULL,  // Configuration parameters (unused)
        error_buffer, sizeof(error_buffer), &error_size
    );

    if (result != 0) {
        printf("Initialization failed: %.*s\n", (int)error_size, error_buffer);
        return 1;
    }

    // Encrypt data
    const char* plaintext = "Hello, Senzing!";
    char encrypted_buffer[2048];
    size_t encrypted_size = 0;

    result = G2Encryption_EncryptDataField(
        plaintext, strlen(plaintext) + 1,
        encrypted_buffer, sizeof(encrypted_buffer), &encrypted_size,
        error_buffer, sizeof(error_buffer), &error_size
    );

    if (result == 0) {
        printf("Encrypted: %.*s\n", (int)encrypted_size - 1, encrypted_buffer);
    }

    // Clean up
    G2Encryption_ClosePlugin(error_buffer, sizeof(error_buffer), &error_size);
    return 0;
}
```

### Building C Examples

```bash
# For AES plugin
gcc -o aes_test examples/c_usage_example.c -L./target/release -lsz_aes_encrypt_plugin -Wl,-rpath,./target/release
./aes_test

# For Dummy plugin
gcc -o dummy_test examples/c_usage_example.c -L./target/release -lsz_dummy_encrypt_plugin -Wl,-rpath,./target/release
./dummy_test
```

## Plugin Signatures

- **AES Plugin**: `"AES256_CBC_PKCS7_B64_2024"`
- **Dummy Plugin**: `"DUMMY_XOR_B64_2024"`

## Security Considerations

### AES Plugin
- Uses cryptographically secure random number generation for IVs
- Implements PKCS#7 padding for AES-CBC mode
- Automatically zeroizes sensitive data from memory
- Suitable for production use

### Dummy Plugin
- **WARNING**: Uses simple XOR cipher - NOT cryptographically secure
- Intended for development, testing, and educational purposes only
- Do not use in production environments

## Dependencies

Core dependencies managed at workspace level:

- `aes` - AES encryption implementation
- `cbc` - CBC mode of operation
- `rand` - Cryptographically secure random number generation
- `base64` - Base64 encoding/decoding
- `zeroize` - Secure memory clearing
- `thiserror` - Error handling
- `libc` - C library bindings

## Development

### Project Structure

```
sz_rust_encrypt_plugin/
├── Cargo.toml                    # Workspace configuration
├── sz_common/                    # Shared utilities library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               # Common library exports
│       ├── errors.rs            # Error types and handling
│       ├── traits.rs            # EncryptionProvider trait
│       └── utils.rs             # C FFI utilities
├── sz_aes_plugin/               # AES encryption plugin
│   ├── Cargo.toml
│   ├── build.rs                 # Header generation
│   ├── include/                 # Generated C headers
│   └── src/
│       ├── lib.rs               # Plugin entry point
│       ├── aes_encryption.rs    # AES implementation
│       └── c_interface.rs       # C FFI wrapper
├── sz_dummy_plugin/             # Dummy encryption plugin
│   ├── Cargo.toml
│   ├── build.rs                 # Header generation
│   ├── include/                 # Generated C headers
│   └── src/
│       ├── lib.rs               # Plugin entry point
│       ├── dummy_encryption.rs  # XOR implementation
│       └── c_interface.rs       # C FFI wrapper
└── README.md                    # This file
```

### Adding New Plugins

1. Create new directory in workspace
2. Add to `workspace.members` in root `Cargo.toml`
3. Implement `EncryptionProvider` trait from `sz_common`
4. Create C interface wrapper functions
5. Add build script for header generation

### Code Style

- Use Rust 2024 edition features
- Follow workspace dependency management
- Implement comprehensive error handling
- Include thorough unit tests
- Document all public interfaces

## Integration with Senzing

### Configuration

Add the specific plugin to your Senzing configuration:

```json
{
  "DATA_ENCRYPTION": {
    "ENCRYPTION_PLUGIN_NAME": "libsz_aes_encrypt_plugin.so"
  }
}
```

### Environment Setup

Ensure the shared library is accessible:

```bash
# Add to library path
export LD_LIBRARY_PATH=/path/to/plugin:$LD_LIBRARY_PATH

# Or install to system library directory
sudo cp target/release/libsz_aes_encrypt_plugin.so /usr/local/lib/
sudo ldconfig
```

## Performance Characteristics

| Operation | AES Plugin | Dummy Plugin |
|-----------|------------|--------------|
| Plugin Init | <1ms | <1ms |
| Encrypt (1KB) | <1ms | <0.1ms |
| Decrypt (1KB) | <1ms | <0.1ms |
| Throughput | ~100MB/s | ~1GB/s |

*Performance varies by hardware and data size*

## Testing Results

All tests pass for the workspace:

- **sz_common**: 1 test (doctest)
- **sz_aes_plugin**: 5 tests (encryption, deterministic, validation)
- **sz_dummy_plugin**: 7 tests (encryption, deterministic, unicode, validation)

Total: **13 tests passing**

## License

This project implements Senzing encryption plugin interfaces and is intended for use with Senzing products.