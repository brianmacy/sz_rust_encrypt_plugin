//! Dummy XOR encryption implementation for development and testing.
//!
//! This module provides a simple XOR-based encryption that is NOT
//! cryptographically secure and should only be used for development
//! and testing purposes.

use crate::DUMMY_SIGNATURE;
use base64::{Engine as _, engine::general_purpose};
use sz_common::{
    EncryptionError, EncryptionProvider, Result, add_encryption_prefix, has_encryption_prefix,
    parse_hex_string, remove_encryption_prefix,
};
use zeroize::Zeroize;

/// Dummy XOR encryption implementation.
///
/// **WARNING: This is NOT cryptographically secure!**
///
/// This implementation uses a simple XOR cipher with a repeating key
/// derived from the plugin signature. It is suitable only for:
/// - Development and testing
/// - Demonstrating plugin interfaces
/// - Educational purposes
///
/// # Operating modes
///
/// The plugin selects its mode at `init()` time based on `SZ_DUMMY_KEY`:
///
/// - **`SZ_DUMMY_KEY` set to an even-length hex string** — XOR cipher with
///   that key, output is `"ENC:" + base64(XOR(plaintext, key))`. Standard
///   reference behavior.
/// - **`SZ_DUMMY_KEY` set to the empty string `""`** — *passthrough mode*: no
///   XOR, no base64. Output is `"ENC:" + plaintext`. Useful for test fixtures
///   where you want the plugin to be loaded and exercised end-to-end without
///   transforming the on-disk bytes — e.g. mirroring a cleartext-style
///   reference plugin where the corpus expected values are plaintext.
/// - **`SZ_DUMMY_KEY` not set** — `init()` returns an error. The empty string
///   is *set but empty*; the env var has to exist to opt into passthrough.
///
/// # Security
///
/// This implementation provides:
/// - No cryptographic security
/// - Deterministic encryption (same input = same output)
/// - Fast performance
/// - Simple debugging
pub struct DummyEncryption {
    key: Vec<u8>,
}

impl Default for DummyEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyEncryption {
    /// Create a new dummy encryption instance.
    ///
    /// The instance must be initialized using `init()` before use.
    pub fn new() -> Self {
        Self { key: Vec::new() }
    }

    /// Initialize with a hex key string directly.
    ///
    /// This avoids `env::set_var` race conditions in tests.
    /// Production code uses `init()` which reads environment variables.
    ///
    /// Empty `key_hex` selects passthrough mode (see struct doc for details).
    #[cfg(test)]
    pub fn init_with_key(&mut self, key_hex: &str) -> Result<()> {
        self.key = if key_hex.is_empty() {
            Vec::new()
        } else {
            parse_hex_string(key_hex, "key")?
        };
        Ok(())
    }

    /// Encrypt or decrypt data using XOR cipher.
    ///
    /// XOR is symmetric, so encryption and decryption use the same operation.
    fn xor_encrypt_decrypt(&self, data: &[u8]) -> Vec<u8> {
        if self.key.is_empty() {
            return data.to_vec();
        }

        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ self.key[i % self.key.len()])
            .collect()
    }
}

impl EncryptionProvider for DummyEncryption {
    fn init(&mut self) -> Result<()> {
        let key_hex =
            std::env::var("SZ_DUMMY_KEY").map_err(|_| EncryptionError::InitializationFailed {
                message: "SZ_DUMMY_KEY environment variable not set".to_string(),
            })?;

        // Empty value (env var set to "") selects passthrough mode — see struct doc.
        // Unset (env::var error above) is still rejected so the plugin doesn't
        // silently no-op when the operator forgot to configure it.
        self.key = if key_hex.is_empty() {
            Vec::new()
        } else {
            parse_hex_string(&key_hex, "SZ_DUMMY_KEY")?
        };
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        // Securely clear the key
        self.key.zeroize();
        Ok(())
    }

    fn signature(&self) -> &'static str {
        DUMMY_SIGNATURE
    }

    fn encrypt(&self, plaintext: &str) -> Result<String> {
        // For example purposes, just use deterministic encryption
        self.encrypt_deterministic(plaintext)
    }

    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> {
        // Passthrough mode: prefix only, no XOR, no base64. Output bytes are
        // exactly `"ENC:" + plaintext` so callers see a verbatim plaintext
        // payload behind a recognizable encryption marker.
        if self.key.is_empty() {
            return Ok(add_encryption_prefix(plaintext));
        }

        if plaintext.is_empty() {
            return Ok(add_encryption_prefix(""));
        }

        let plaintext_bytes = plaintext.as_bytes();
        let encrypted_bytes = self.xor_encrypt_decrypt(plaintext_bytes);
        let encoded = general_purpose::STANDARD.encode(&encrypted_bytes);
        Ok(add_encryption_prefix(&encoded))
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String> {
        // For example purposes, just use deterministic decryption
        self.decrypt_deterministic(ciphertext)
    }

    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> {
        if !has_encryption_prefix(ciphertext) {
            return Err(EncryptionError::DecryptionFailed {
                message: "Missing encryption prefix".to_string(),
            });
        }

        let encoded_data = remove_encryption_prefix(ciphertext)?;

        // Passthrough mode: just strip the prefix; payload is plaintext.
        if self.key.is_empty() {
            return Ok(encoded_data.to_string());
        }

        if encoded_data.is_empty() {
            return Ok(String::new());
        }

        let encrypted_bytes = general_purpose::STANDARD
            .decode(encoded_data)
            .map_err(|e| EncryptionError::DecryptionFailed {
                message: format!("Base64 decode error: {}", e),
            })?;

        let decrypted_bytes = self.xor_encrypt_decrypt(&encrypted_bytes);

        String::from_utf8(decrypted_bytes).map_err(|e| EncryptionError::DecryptionFailed {
            message: format!("UTF-8 decode error: {}", e),
        })
    }

    fn validate_signature(&self, signature: &str) -> Result<()> {
        if signature == DUMMY_SIGNATURE {
            Ok(())
        } else {
            Err(EncryptionError::InvalidSignature {
                signature: signature.to_string(),
            })
        }
    }
}

impl Drop for DummyEncryption {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "44554d4d595f584f525f763130";

    fn make_encryption() -> DummyEncryption {
        let mut enc = DummyEncryption::new();
        enc.init_with_key(TEST_KEY).unwrap();
        enc
    }

    #[test]
    fn test_dummy_encryption_roundtrip() {
        let encryption = make_encryption();

        let plaintext = "Hello, World!";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
        assert!(ciphertext.starts_with("ENC:"));
    }

    #[test]
    fn test_dummy_encryption_deterministic() {
        let encryption = make_encryption();

        let plaintext = "Deterministic test";
        let ciphertext1 = encryption.encrypt_deterministic(plaintext).unwrap();
        let ciphertext2 = encryption.encrypt_deterministic(plaintext).unwrap();

        assert_eq!(ciphertext1, ciphertext2);

        let decrypted = encryption.decrypt_deterministic(&ciphertext1).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_regular_and_deterministic_same() {
        let encryption = make_encryption();

        let plaintext = "Test data";
        let regular_encrypted = encryption.encrypt(plaintext).unwrap();
        let deterministic_encrypted = encryption.encrypt_deterministic(plaintext).unwrap();

        // For XOR, these should be the same
        assert_eq!(regular_encrypted, deterministic_encrypted);
    }

    #[test]
    fn test_empty_string() {
        let encryption = make_encryption();

        let ciphertext = encryption.encrypt("").unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!("", decrypted);
    }

    #[test]
    fn test_invalid_ciphertext() {
        let encryption = make_encryption();

        let result = encryption.decrypt("invalid_data");
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_validation() {
        let encryption = DummyEncryption::new();

        assert!(encryption.validate_signature(DUMMY_SIGNATURE).is_ok());
        assert!(encryption.validate_signature("INVALID").is_err());
    }

    #[test]
    fn test_unicode_support() {
        let encryption = make_encryption();

        let plaintext = "Hello 世界 🌍 café";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    fn make_passthrough_encryption() -> DummyEncryption {
        let mut enc = DummyEncryption::new();
        enc.init_with_key("").unwrap();
        enc
    }

    #[test]
    fn test_passthrough_no_xor_no_base64() {
        let encryption = make_passthrough_encryption();
        let ciphertext = encryption.encrypt("Hello, World!").unwrap();
        // Verbatim plaintext behind the prefix — no XOR, no base64.
        assert_eq!(ciphertext, "ENC:Hello, World!");
    }

    #[test]
    fn test_passthrough_roundtrip() {
        let encryption = make_passthrough_encryption();
        let plaintext = "Hello, World!";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_passthrough_empty_string() {
        let encryption = make_passthrough_encryption();
        let ciphertext = encryption.encrypt("").unwrap();
        assert_eq!(ciphertext, "ENC:");
        let decrypted = encryption.decrypt(&ciphertext).unwrap();
        assert_eq!("", decrypted);
    }

    #[test]
    fn test_passthrough_unicode() {
        let encryption = make_passthrough_encryption();
        let plaintext = "Hello 世界 🌍 café";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext, format!("ENC:{plaintext}"));
        let decrypted = encryption.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_passthrough_preserves_special_chars() {
        // Bytes that base64 would otherwise transform — passthrough must not.
        let encryption = make_passthrough_encryption();
        let plaintext = "G2Enc:already-prefixed | comma,delimited | \"quoted\"";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext, format!("ENC:{plaintext}"));
        let decrypted = encryption.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_passthrough_decrypt_requires_prefix() {
        let encryption = make_passthrough_encryption();
        // Same prefix-validation contract as the XOR path.
        assert!(encryption.decrypt("not_prefixed").is_err());
    }

    #[test]
    fn test_xor_mode_still_xors_after_passthrough_added() {
        // Regression: adding passthrough must not change XOR-mode output.
        let encryption = make_encryption();
        let plaintext = "data";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        // XOR mode: base64-encoded payload, never the verbatim plaintext.
        assert!(ciphertext.starts_with("ENC:"));
        assert_ne!(ciphertext, format!("ENC:{plaintext}"));
    }
}
