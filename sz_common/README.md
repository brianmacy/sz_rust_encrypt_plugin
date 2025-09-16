# Senzing Common Library

Shared utilities, traits, and error handling for Senzing encryption plugins.

## Purpose

This library provides common functionality used by all Senzing encryption plugins, ensuring consistency and reducing code duplication across different encryption implementations.

## Features

- **`EncryptionProvider` trait**: Standard interface for all encryption implementations
- **Comprehensive error handling**: Structured error types with detailed context
- **C FFI utilities**: Safe string and buffer conversion functions
- **Memory safety**: Proper handling of C interface boundaries
- **Consistent error reporting**: Standardized error messages and codes

## Core Components

### EncryptionProvider Trait

The main trait that all encryption implementations must implement:

```rust
pub trait EncryptionProvider: Send + Sync {
    fn init(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn signature(&self) -> &'static str;
    fn encrypt(&self, plaintext: &str) -> Result<String>;
    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String>;
    fn decrypt(&self, ciphertext: &str) -> Result<String>;
    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String>;
    fn validate_signature(&self, signature: &str) -> Result<()>;
}
```

### Error Types

Comprehensive error handling with `EncryptionError`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Plugin not initialized")]
    NotInitialized,

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Encryption failed: {message}")]
    EncryptionFailed { message: String },

    #[error("Decryption failed: {message}")]
    DecryptionFailed { message: String },

    #[error("Invalid signature: {signature}")]
    InvalidSignature { signature: String },

    #[error("Buffer too small: required {required}, available {available}")]
    BufferTooSmall { required: usize, available: usize },

    #[error("Internal error: {message}")]
    Internal { message: String },
}
```

### C FFI Utilities

Safe conversion functions for C interface:

```rust
// Convert C string to Rust String
pub fn c_str_to_string(ptr: *const libc::c_char, size: libc::size_t) -> Result<String>;

// Write Rust String to C buffer
pub fn string_to_c_buffer(
    source: &str,
    buffer: *mut libc::c_char,
    max_size: libc::size_t,
    actual_size: *mut libc::size_t,
) -> Result<()>;

// Write error to C buffer
pub fn error_to_c_buffer(
    error: &EncryptionError,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int;
```

## Usage

### Implementing a New Encryption Plugin

```rust
use sz_common::{EncryptionProvider, EncryptionError, Result};

pub struct MyEncryption {
    initialized: bool,
}

impl EncryptionProvider for MyEncryption {
    fn init(&mut self) -> Result<()> {
        // Initialize your encryption system
        self.initialized = true;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        // Clean up resources
        self.initialized = false;
        Ok(())
    }

    fn signature(&self) -> &'static str {
        "MY_ENCRYPTION_V1"
    }

    fn encrypt(&self, plaintext: &str) -> Result<String> {
        if !self.initialized {
            return Err(EncryptionError::NotInitialized);
        }
        // Implement your encryption logic
        todo!()
    }

    // ... implement other required methods
}
```

### Using C FFI Utilities

```rust
use sz_common::{c_str_to_string, string_to_c_buffer, error_to_c_buffer};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn my_encrypt_function(
    input: *const libc::c_char,
    input_size: libc::size_t,
    result_buffer: *mut libc::c_char,
    max_result_size: libc::size_t,
    result_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<()> {
        // Convert C string to Rust
        let plaintext = c_str_to_string(input, input_size)?;

        // Perform encryption
        let encrypted = my_encryption_logic(&plaintext)?;

        // Write result back to C buffer
        string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size)
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}
```

## Module Structure

```
sz_common/
├── Cargo.toml
└── src/
    ├── lib.rs      # Public API exports
    ├── errors.rs   # Error types and handling
    ├── traits.rs   # EncryptionProvider trait
    └── utils.rs    # C FFI utility functions
```

## Dependencies

- `thiserror` - Structured error handling
- `libc` - C library bindings
- `base64` - Base64 encoding/decoding
- `zeroize` - Secure memory clearing

## Design Principles

### Memory Safety

All C interface functions handle:
- Null pointer validation
- Buffer size checking
- UTF-8 validation
- Proper error propagation

### Error Consistency

Standardized error types ensure:
- Consistent error reporting across plugins
- No information leakage in error messages
- Proper error codes for C interface

### Thread Safety

The trait requires `Send + Sync` ensuring:
- Thread-safe implementations
- Concurrent access support
- Proper synchronization patterns

## Testing

```bash
# Run tests (includes doctest)
cargo test -p sz_common

# The test suite includes:
# - Doctest for EncryptionProvider trait example
# - Unit tests for utility functions
# - Error handling validation
```

## Integration

This library is designed to be used by:

1. **sz_aes_plugin** - AES-256-CBC encryption
2. **sz_dummy_plugin** - XOR-based testing encryption
3. **Future plugins** - Any new encryption implementations

### Workspace Integration

Add to your plugin's `Cargo.toml`:

```toml
[dependencies]
sz_common = { workspace = true }
```

## API Stability

The public API is designed for stability:

- Trait methods are fundamental and unlikely to change
- Error types are comprehensive and extensible
- Utility functions handle all common C interface patterns
- Version compatibility maintained through semantic versioning

## Contributing

When adding new functionality:

1. **Maintain API compatibility**
2. **Add comprehensive tests**
3. **Update documentation**
4. **Consider all plugin users**
5. **Follow Rust best practices**

## License

This project implements Senzing encryption plugin interfaces and is intended for use with Senzing products.