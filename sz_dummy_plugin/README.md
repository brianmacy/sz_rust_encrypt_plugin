# Dummy Encryption Plugin for Senzing

A simple XOR-based encryption plugin for Senzing, designed for development, testing, and educational purposes.

## ⚠️ Security Warning

**This plugin is NOT cryptographically secure and should NEVER be used in production environments.** It uses a simple XOR cipher which provides no real security. Use this plugin only for:

- Development and testing
- Educational purposes
- Non-sensitive data processing
- Plugin interface validation

## Features

- **XOR Cipher**: Simple XOR-based encryption using plugin signature as key
- **Deterministic**: Same input always produces same output
- **Base64 Encoding**: Consistent with production plugins
- **Fast Performance**: Very high throughput for testing
- **C Interface**: Full Senzing plugin API compatibility
- **Predictable**: Useful for debugging and testing

## Plugin Signature

`"DUMMY_XOR_B64_2024"`

## Building

```bash
# Build from workspace root
cargo build --release -p sz_dummy_plugin

# Or build from this directory
cd sz_dummy_plugin
cargo build --release
```

### Generated Files

- `target/release/libsz_dummy_encrypt_plugin.so` - Shared library
- `include/sz_dummy_encrypt_plugin.h` - C header file

## Testing

```bash
# Run tests
cargo test -p sz_dummy_plugin

# All 7 tests should pass:
# - test_dummy_encryption_roundtrip
# - test_dummy_encryption_deterministic
# - test_regular_and_deterministic_same
# - test_empty_string
# - test_invalid_ciphertext
# - test_unicode_support
# - test_signature_validation
```

## C Interface Usage

```c
#include "sz_dummy_encrypt_plugin.h"
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
    const char* plaintext = "Test data";
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

    // Test deterministic encryption (same input = same output)
    char det_encrypted1[2048], det_encrypted2[2048];
    size_t det_size1 = 0, det_size2 = 0;

    G2Encryption_EncryptDataFieldDeterministic(
        "same input", 11, det_encrypted1, sizeof(det_encrypted1), &det_size1,
        error_buffer, sizeof(error_buffer), &error_size
    );

    G2Encryption_EncryptDataFieldDeterministic(
        "same input", 11, det_encrypted2, sizeof(det_encrypted2), &det_size2,
        error_buffer, sizeof(error_buffer), &error_size
    );

    if (det_size1 == det_size2 && memcmp(det_encrypted1, det_encrypted2, det_size1) == 0) {
        printf("Deterministic encryption verified\n");
    }

    // Cleanup
    G2Encryption_ClosePlugin(error_buffer, sizeof(error_buffer), &error_size);
    return 0;
}
```

### Compilation

```bash
gcc -o dummy_test your_program.c -L../target/release -lsz_dummy_encrypt_plugin -Wl,-rpath,../target/release
./dummy_test
```

## Implementation Details

### XOR Encryption Process

1. **Key**: Plugin signature string used as repeating key
2. **XOR Operation**: Each byte of plaintext XORed with corresponding key byte (cycling)
3. **Output Format**: `ENC:` + Base64(XORed data)

### Deterministic Nature

Since XOR is deterministic and uses the same key every time:
- Same plaintext always produces same ciphertext
- Useful for testing and debugging
- Enables pattern analysis (which is why it's insecure)

### Example Encryption

```
Plaintext:  "Hello"
Key:        "DUMMY_XOR_B64_2024" (repeating)
XOR Result: Binary data
Base64:     Encoded binary
Output:     "ENC:" + Base64 encoded result
```

## Dependencies

- `sz_common` - Shared utilities and traits
- `base64` - Base64 encoding/decoding
- `zeroize` - Secure memory clearing (for consistency)
- `libc` - C library bindings

## Use Cases

### Development Testing

```bash
# Quick plugin interface validation
cargo test -p sz_dummy_plugin

# Performance baseline testing
time ./dummy_test < large_test_file.txt

# Integration testing with Senzing
# (Configure Senzing to use libsz_dummy_encrypt_plugin.so)
```

### Educational Purposes

Perfect for learning:

- Plugin architecture patterns
- C FFI implementation
- Encryption plugin lifecycle
- Buffer management in C interfaces
- Error handling patterns

### Debugging

The predictable nature helps with:

- Tracing data flow through encryption/decryption
- Validating plugin integration
- Testing error conditions
- Verifying correct C interface behavior

## Performance

Excellent performance characteristics:

- **Initialization**: <1ms
- **Encryption (1KB)**: <0.1ms
- **Decryption (1KB)**: <0.1ms
- **Throughput**: ~1GB/s (much faster than AES)

## Security Analysis

### Why It's Insecure

1. **XOR with Known Key**: Key is the plugin signature (publicly known)
2. **Pattern Preservation**: Same plaintext = same ciphertext
3. **Frequency Analysis**: Character frequencies are preserved
4. **No Authentication**: No integrity protection
5. **Repeating Key**: Short key repeats, enabling cryptanalysis

### Educational Value

This implementation demonstrates:

- Why proper encryption algorithms are necessary
- The importance of random keys and IVs
- How deterministic encryption can leak information
- The difference between encoding and encryption

## Comparison with AES Plugin

| Feature | Dummy Plugin | AES Plugin |
|---------|-------------|------------|
| Security | None | High |
| Speed | Very Fast | Fast |
| Deterministic | Always | Optional |
| Key Management | None | Required |
| Use Case | Development | Production |
| Algorithm | XOR | AES-256-CBC |

## License

This project implements Senzing encryption plugin interfaces and is intended for use with Senzing products.