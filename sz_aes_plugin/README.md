# AES Encryption Plugin for Senzing

Reference AES-256-CBC encryption plugin for Senzing. Compiles to a C-compatible shared library that implements the Senzing encryption plugin interface. **This is a reference implementation, not a production cipher** — see [Security caveats](#security-caveats) below.

## Features

- **AES-256-CBC Encryption**: 256-bit keys in CBC mode
- **PKCS#7 Padding**: Manual PKCS#7 padding for block cipher operations
- **Operation Modes** (both use a fixed IV in this reference plugin):
  - `encrypt()` — delegates to `encrypt_deterministic()`; same plaintext always produces same ciphertext.
  - `encrypt_deterministic()` — fixed IV configured at init time (`SZ_AES_IV`).
- **Base64 Encoding**: All encrypted output is base64-encoded with an `ENC:` prefix
- **Memory Safety**: Automatic zeroization of sensitive data via `zeroize`
- **Thread Safety**: Concurrent access support
- **C Interface**: Full Senzing plugin API compatibility

## Security Specifications

- **Algorithm**: AES-256-CBC with PKCS#7 padding
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **IV Source**: Fixed IV from `SZ_AES_IV` env var, used for both `encrypt()` and `encrypt_deterministic()`
- **Memory Protection**: Automatic clearing of sensitive data using `zeroize`

## Plugin Signature

`"AES256_CBC_PKCS7_B64_2024"`

## Building

```bash
# Build from workspace root
cargo build --release -p sz_aes_plugin

# Or build from this directory
cd sz_aes_plugin
cargo build --release
```

### Generated Files

- `target/release/libsz_aes_encrypt_plugin.so` - Shared library
- `include/sz_aes_encrypt_plugin.h` - C header file

## Testing

```bash
# Run tests
cargo test -p sz_aes_plugin

# All 5 tests should pass:
# - test_aes_encryption_roundtrip
# - test_aes_deterministic_encryption
# - test_aes_encrypt_collapses_to_deterministic
# - test_empty_string
# - test_signature_validation
```

## C Interface Usage

```c
#include "sz_aes_encrypt_plugin.h"
#include <stdio.h>
#include <string.h>

int main() {
    char error_buffer[1024];
    size_t error_size = 0;

    // Initialize plugin
    int result = G2Encryption_InitPlugin(
        NULL, error_buffer, sizeof(error_buffer), &error_size
    );

    if (result != 0) {
        printf("Init failed: %.*s\n", (int)error_size, error_buffer);
        return 1;
    }

    // Encrypt data
    const char* plaintext = "Sensitive data";
    char encrypted[2048];
    size_t encrypted_size = 0;

    result = G2Encryption_EncryptDataField(
        plaintext, strlen(plaintext) + 1,
        encrypted, sizeof(encrypted), &encrypted_size,
        error_buffer, sizeof(error_buffer), &error_size
    );

    if (result == 0) {
        printf("Encrypted: %.*s\n", (int)encrypted_size - 1, encrypted);

        // Decrypt to verify
        char decrypted[1024];
        size_t decrypted_size = 0;

        result = G2Encryption_DecryptDataField(
            encrypted, encrypted_size,
            decrypted, sizeof(decrypted), &decrypted_size,
            error_buffer, sizeof(error_buffer), &error_size
        );

        if (result == 0) {
            printf("Decrypted: %.*s\n", (int)decrypted_size - 1, decrypted);
        }
    }

    // Cleanup
    G2Encryption_ClosePlugin(error_buffer, sizeof(error_buffer), &error_size);
    return 0;
}
```

### Compilation

```bash
gcc -o aes_test your_program.c -L../target/release -lsz_aes_encrypt_plugin -Wl,-rpath,../target/release
./aes_test
```

## Implementation Details

### Encryption Process

1. **Key**: Loaded from `SZ_AES_KEY` (hex-encoded 32 bytes) at init time.
2. **IV**: Loaded from `SZ_AES_IV` (hex-encoded 16 bytes) at init time. The same fixed IV is used for both `encrypt()` and `encrypt_deterministic()`.
3. **Encryption**: AES-256-CBC with manual PKCS#7 padding.
4. **Output Format**: `ENC:` + Base64(IV ‖ Ciphertext) — IV is prepended so decryption can recover it.

### Decryption Process

1. **Format Validation**: Check for `ENC:` prefix
2. **Base64 Decoding**: Extract IV and encrypted data
3. **IV Extraction**: First 16 bytes are the IV
4. **Decryption**: AES-256-CBC decryption
5. **Padding Removal**: PKCS#7 padding removal

## Dependencies

- `sz_common` - Shared utilities and traits
- `aes` - AES encryption implementation
- `cbc` - CBC mode of operation
- `rand` - Cryptographically secure random number generation
- `base64` - Base64 encoding/decoding
- `zeroize` - Secure memory clearing
- `libc` - C library bindings

## Integration with Senzing

Add to Senzing configuration:

```json
{
  "DATA_ENCRYPTION": {
    "ENCRYPTION_PLUGIN_NAME": "libsz_aes_encrypt_plugin.so"
  }
}
```

## Security caveats

This plugin is a **reference implementation**, intended as a starting point for writing your own AES plugin. It is not a production cipher.

- **Fixed IV in both modes**: `encrypt()` delegates to `encrypt_deterministic()`, so identical plaintexts always produce identical ciphertexts. Reusing a fixed IV across many AES-CBC encryptions leaks pattern information at the block level. A production AES plugin should generate a fresh random IV inside `encrypt()` and reserve the fixed IV for `encrypt_deterministic()` only.
- **Key management**: Key material is loaded from environment variables (`SZ_AES_KEY`, `SZ_AES_IV`). A production deployment should integrate with a real KMS / secrets store rather than environment variables.
- **Memory safety**: All sensitive data is automatically cleared via `zeroize` on `close` and `Drop`.
- **Timing attacks**: No constant-time guarantees beyond what the underlying `aes` crate provides.

### Recommendations for production

1. Replace `encrypt()` with a real random-IV implementation.
2. Manage keys via a KMS / secrets store, not env vars.
3. Plan for key rotation.
4. Monitor and update cryptographic dependencies.

## Performance

Typical performance characteristics:

- **Initialization**: <1ms
- **Encryption (1KB)**: <1ms
- **Decryption (1KB)**: <1ms
- **Throughput**: ~100MB/s (hardware dependent)

## License

This project implements Senzing encryption plugin interfaces and is intended for use with Senzing products.
