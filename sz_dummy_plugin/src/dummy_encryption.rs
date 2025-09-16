//! Dummy XOR encryption implementation for development and testing.
//!
//! This module provides a simple XOR-based encryption that is NOT
//! cryptographically secure and should only be used for development
//! and testing purposes.

use crate::DUMMY_SIGNATURE;
use base64::{Engine as _, engine::general_purpose};
use sz_common::{
    EncryptionError, EncryptionProvider, Result, add_encryption_prefix, has_encryption_prefix,
    remove_encryption_prefix,
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
/// # Security
///
/// This implementation provides:
/// - ❌ No cryptographic security
/// - ✅ Deterministic encryption (same input = same output)
/// - ✅ Fast performance
/// - ✅ Simple debugging
pub struct DummyEncryption {
    key: Vec<u8>,
}

impl DummyEncryption {
    /// Create a new dummy encryption instance.
    ///
    /// The instance must be initialized using `init()` before use.
    pub fn new() -> Self {
        Self { key: Vec::new() }
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
        // Use the signature as the XOR key
        self.key = DUMMY_SIGNATURE.as_bytes().to_vec();
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
        if plaintext.is_empty() {
            return Ok(add_encryption_prefix(""));
        }

        let plaintext_bytes = plaintext.as_bytes();
        let encrypted_bytes = self.xor_encrypt_decrypt(plaintext_bytes);
        let encoded = general_purpose::STANDARD.encode(&encrypted_bytes);
        Ok(add_encryption_prefix(&encoded))
    }

    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> {
        // For XOR encryption, deterministic and regular encryption are the same
        self.encrypt(plaintext)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String> {
        if !has_encryption_prefix(ciphertext) {
            return Err(EncryptionError::DecryptionFailed {
                message: "Missing encryption prefix".to_string(),
            });
        }

        let encoded_data = remove_encryption_prefix(ciphertext)?;

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

    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> {
        // For XOR encryption, deterministic and regular decryption are the same
        self.decrypt(ciphertext)
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

    #[test]
    fn test_dummy_encryption_roundtrip() {
        let mut encryption = DummyEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Hello, World!";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
        assert!(ciphertext.starts_with("ENC:"));
    }

    #[test]
    fn test_dummy_encryption_deterministic() {
        let mut encryption = DummyEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Deterministic test";
        let ciphertext1 = encryption.encrypt_deterministic(plaintext).unwrap();
        let ciphertext2 = encryption.encrypt_deterministic(plaintext).unwrap();

        assert_eq!(ciphertext1, ciphertext2);

        let decrypted = encryption.decrypt_deterministic(&ciphertext1).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_regular_and_deterministic_same() {
        let mut encryption = DummyEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Test data";
        let regular_encrypted = encryption.encrypt(plaintext).unwrap();
        let deterministic_encrypted = encryption.encrypt_deterministic(plaintext).unwrap();

        // For XOR, these should be the same
        assert_eq!(regular_encrypted, deterministic_encrypted);
    }

    #[test]
    fn test_empty_string() {
        let mut encryption = DummyEncryption::new();
        encryption.init().unwrap();

        let ciphertext = encryption.encrypt("").unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!("", decrypted);
    }

    #[test]
    fn test_invalid_ciphertext() {
        let mut encryption = DummyEncryption::new();
        encryption.init().unwrap();

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
        let mut encryption = DummyEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Hello 世界 🌍 café";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
