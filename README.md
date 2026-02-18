# Senzing Rust Encryption Plugins

Rust implementations of the Senzing encryption plugin interface. Each plugin compiles to a C-compatible shared library (`.so`) that Senzing loads at runtime via `dlopen`. Two plugins are included: an AES-256-CBC plugin for real encryption and a dummy XOR plugin for development. Both serve as reference implementations for writing your own.

## Quick Start

### Build

```bash
cargo build --release --workspace
```

Output: `target/release/libsz_aes_encrypt_plugin.so` and `target/release/libsz_dummy_encrypt_plugin.so`

### Configure Environment

AES plugin:

```bash
export SZ_AES_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 64 hex chars (32 bytes)
export SZ_AES_IV="0123456789abcdef0123456789abcdef"                                    # 32 hex chars (16 bytes)
```

Dummy plugin:

```bash
export SZ_DUMMY_KEY="44554d4d595f584f525f763130"  # any even number of hex chars
```

### Configure Senzing

Point Senzing at the plugin library and ensure it can find it:

```bash
export LD_LIBRARY_PATH=/path/to/target/release:$LD_LIBRARY_PATH
```

### Test

```bash
cargo test --workspace
```

No environment variables needed — tests use direct initialization to avoid `env::set_var` race conditions.

## Implementing Your Own Plugin

The dummy plugin (`sz_dummy_plugin`) is the simplest reference. Use it as your starting point. A plugin consists of three things:

1. A struct that implements `EncryptionProvider`
2. A one-line macro invocation that generates the C FFI
3. A `Cargo.toml` that builds a `cdylib`

### Step 1: Create the Crate

```
sz_my_plugin/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── my_encryption.rs
    └── c_interface.rs
```

Add to root `Cargo.toml`:

```toml
[workspace]
members = [
    "sz_common",
    "sz_my_plugin",
]
```

Your `Cargo.toml`:

```toml
[package]
name = "sz_my_plugin"
version = "0.1.0"
edition = "2024"

[lib]
name = "sz_my_encrypt_plugin"
crate-type = ["cdylib", "rlib"]  # cdylib = shared library for C, rlib = for Rust tests

[dependencies]
sz_common = { workspace = true }
libc = { workspace = true }
zeroize = { workspace = true }
# ... your crypto dependencies
```

### Step 2: Implement `EncryptionProvider`

The trait (`sz_common::traits`) defines the contract Senzing expects:

| Method                                     | Purpose                                                                 |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `init(&mut self)`                          | Read configuration (typically env vars), set up keys. Called once.      |
| `close(&mut self)`                         | Zeroize keys and release resources. Called once.                        |
| `signature(&self)`                         | Return a static string identifying your algorithm (e.g. `"MY_ALG_v1"`). |
| `validate_signature(&self, sig)`           | Return `Ok(())` if `sig` matches your signature, else error.            |
| `encrypt(&self, plaintext)`                | Non-deterministic encryption (random IV each call).                     |
| `encrypt_deterministic(&self, plaintext)`  | Same plaintext always produces same ciphertext.                         |
| `decrypt(&self, ciphertext)`               | Reverse of `encrypt`.                                                   |
| `decrypt_deterministic(&self, ciphertext)` | Reverse of `encrypt_deterministic`.                                     |

Your struct must also implement `Default` (the macro uses it to construct instances).

Minimal example (see `sz_dummy_plugin/src/dummy_encryption.rs` for the full version):

```rust
use sz_common::{EncryptionProvider, EncryptionError, Result, parse_hex_string};
use zeroize::Zeroize;

pub struct MyEncryption {
    key: Vec<u8>,
}

impl Default for MyEncryption {
    fn default() -> Self { Self { key: Vec::new() } }
}

impl EncryptionProvider for MyEncryption {
    fn init(&mut self) -> Result<()> {
        let key_hex = std::env::var("MY_KEY")
            .map_err(|_| EncryptionError::InitializationFailed {
                message: "MY_KEY environment variable not set".to_string(),
            })?;
        self.key = parse_hex_string(&key_hex, "MY_KEY")?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.key.zeroize();
        Ok(())
    }

    fn signature(&self) -> &'static str { "MY_ALG_v1" }

    fn validate_signature(&self, sig: &str) -> Result<()> {
        if sig == self.signature() { Ok(()) }
        else { Err(EncryptionError::InvalidSignature { signature: sig.to_string() }) }
    }

    fn encrypt(&self, plaintext: &str) -> Result<String> { todo!() }
    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> { todo!() }
    fn decrypt(&self, ciphertext: &str) -> Result<String> { todo!() }
    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> { todo!() }
}

impl Drop for MyEncryption {
    fn drop(&mut self) { self.key.zeroize(); }
}
```

Key rules:

- All encrypted output should be prefixed with `ENC:` (use `sz_common::add_encryption_prefix`)
- Decrypt must handle the `ENC:` prefix (use `sz_common::remove_encryption_prefix`)
- Use `sz_common::parse_hex_string` for hex key parsing instead of rolling your own
- Implement `Drop` to zeroize key material

### Step 3: Generate the C Interface

`c_interface.rs` — this is the entire file:

```rust
use crate::my_encryption::MyEncryption;

sz_common::declare_c_interface!(MyEncryption);
```

The macro generates all 8 `extern "C"` functions that Senzing expects (`G2Encryption_InitPlugin`, `G2Encryption_ClosePlugin`, etc.). It handles:

- Global singleton state via `OnceLock<Mutex<Option<T>>>`
- Thread-safe access via `Mutex`
- C string conversion and error buffer population
- Mapping `EncryptionError` variants to C error codes

### Step 4: Wire Up `lib.rs`

```rust
mod c_interface;
mod my_encryption;

pub use c_interface::*;
pub use my_encryption::MyEncryption;
pub use sz_common::{EncryptionError, EncryptionProvider, Result};

pub const MY_SIGNATURE: &str = "MY_ALG_v1";
```

### Step 5: Test Without Environment Variables

Add an `init_with_key` method gated behind `#[cfg(test)]` so tests don't need `env::set_var`:

```rust
#[cfg(test)]
pub fn init_with_key(&mut self, key_hex: &str) -> Result<()> {
    self.key = parse_hex_string(key_hex, "key")?;
    Ok(())
}
```

Build and verify:

```bash
cargo build --release -p sz_my_plugin
cargo test -p sz_my_plugin
```

## Architecture

Three layers, each with a single responsibility:

```
┌─────────────────────────────────────────────────┐
│  sz_common                                      │
│  ├── EncryptionProvider trait (the contract)     │
│  ├── declare_c_interface! macro (C FFI glue)    │
│  ├── EncryptionError (error types + C codes)    │
│  └── utils (hex parsing, string conversion)     │
└─────────────────────────────────────────────────┘
          ▲                        ▲
          │ implements trait        │ invokes macro
┌─────────┴──────────┐  ┌─────────┴──────────┐
│  sz_aes_plugin     │  │  sz_dummy_plugin   │
│  AesEncryption     │  │  DummyEncryption   │
│  (AES-256-CBC)     │  │  (XOR cipher)      │
└────────────────────┘  └────────────────────┘
```

Each plugin compiles to an independent `.so` with no runtime dependency on the other.

### Project Structure

```
sz_rust_encrypt_plugin/
├── Cargo.toml                    # Workspace root
├── deny.toml                     # License policy
├── include/
│   └── sz_encrypt_plugin.h       # Shared C header (all plugins export the same interface)
├── sz_common/src/
│   ├── traits.rs                 # EncryptionProvider trait
│   ├── c_interface_macro.rs      # declare_c_interface! macro
│   ├── errors.rs                 # EncryptionError + C error codes
│   └── utils.rs                  # parse_hex_string, C string helpers
├── sz_aes_plugin/src/
│   ├── aes_encryption.rs         # AES-256-CBC implementation
│   └── c_interface.rs            # One-line macro invocation
├── sz_dummy_plugin/src/
│   ├── dummy_encryption.rs       # XOR implementation
│   └── c_interface.rs            # One-line macro invocation
├── examples/
│   ├── test_aes_plugin.c         # C integration test
│   └── test_dummy_plugin.c       # C integration test
└── CMakeLists.txt                # Builds C examples against the .so files
```

## Reference

### C Interface

All plugins export the same 8 functions. See `include/sz_encrypt_plugin.h` for the full declarations.

| Function                                      | Purpose                        |
| --------------------------------------------- | ------------------------------ |
| `G2Encryption_InitPlugin`                     | Initialize plugin, read config |
| `G2Encryption_ClosePlugin`                    | Clean up and release resources |
| `G2Encryption_GetSignature`                   | Return algorithm identifier    |
| `G2Encryption_ValidateSignatureCompatibility` | Check if a signature is ours   |
| `G2Encryption_EncryptDataField`               | Non-deterministic encrypt      |
| `G2Encryption_DecryptDataField`               | Decrypt                        |
| `G2Encryption_EncryptDataFieldDeterministic`  | Deterministic encrypt          |
| `G2Encryption_DecryptDataFieldDeterministic`  | Deterministic decrypt          |

Return value: `0` on success, negative error code on failure.

### Error Codes

| Code | Meaning               |
| ---- | --------------------- |
| 0    | Success               |
| -1   | Buffer too small      |
| -2   | Invalid input         |
| -3   | Encryption failed     |
| -4   | Decryption failed     |
| -5   | Initialization failed |
| -6   | Not initialized       |
| -7   | Invalid signature     |
| -99  | Internal error        |

### Plugin Signatures

| Plugin | Signature         | Environment Variables     |
| ------ | ----------------- | ------------------------- |
| AES    | `AES256_CBC_v1.0` | `SZ_AES_KEY`, `SZ_AES_IV` |
| Dummy  | `DUMMY_XOR_v1.0`  | `SZ_DUMMY_KEY`            |

### Security Notes

- **AES plugin**: AES-256-CBC with PKCS#7 padding. Key material is zeroized on close and drop. The included implementation uses a fixed IV for both deterministic and non-deterministic modes (delegates `encrypt` to `encrypt_deterministic`) — a real deployment should use random IVs for non-deterministic mode.
- **Dummy plugin**: XOR cipher. Not cryptographically secure. Use only for development and testing.

## License

Apache-2.0. See [LICENSE](LICENSE).
