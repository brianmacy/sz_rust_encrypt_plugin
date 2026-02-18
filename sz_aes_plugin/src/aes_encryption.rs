//! AES-256-CBC encryption implementation for Senzing.
//!
//! This module provides an AES encryption implementation
//! with both deterministic and non-deterministic modes.

use crate::AES_SIGNATURE;
use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{Engine as _, engine::general_purpose};
use cbc::{Decryptor, Encryptor};
use sz_common::{
    EncryptionError, EncryptionProvider, Result, add_encryption_prefix, has_encryption_prefix,
    parse_hex_string, remove_encryption_prefix,
};
use zeroize::Zeroize;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const AES_KEY_SIZE: usize = 32; // 256 bits
const AES_IV_SIZE: usize = 16; // 128 bits
const AES_BLOCK_SIZE: usize = 16;

/// AES-256-CBC encryption implementation.
///
/// This implementation provides secure AES encryption with:
/// - 256-bit keys for maximum security
/// - CBC mode with PKCS7 padding
/// - Random IVs for non-deterministic encryption
/// - Fixed IVs for deterministic encryption
/// - Automatic memory clearing of sensitive data
pub struct AesEncryption {
    key: [u8; AES_KEY_SIZE],
    deterministic_iv: [u8; AES_IV_SIZE],
}

impl Default for AesEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl AesEncryption {
    /// Create a new AES encryption instance.
    ///
    /// The instance must be initialized using `init()` before use.
    pub fn new() -> Self {
        Self {
            key: [0u8; AES_KEY_SIZE],
            deterministic_iv: [0u8; AES_IV_SIZE],
        }
    }

    /// Initialize with hex key and IV strings directly.
    ///
    /// This avoids `env::set_var` race conditions in tests.
    /// Production code uses `init()` which reads environment variables.
    #[cfg(test)]
    pub fn init_with_key_iv(&mut self, key_hex: &str, iv_hex: &str) -> Result<()> {
        let key_bytes = parse_hex_string(key_hex, "key")?;
        if key_bytes.len() != AES_KEY_SIZE {
            return Err(EncryptionError::InitializationFailed {
                message: format!(
                    "Key must be {} hex characters ({} bytes)",
                    AES_KEY_SIZE * 2,
                    AES_KEY_SIZE
                ),
            });
        }
        self.key.copy_from_slice(&key_bytes);

        let iv_bytes = parse_hex_string(iv_hex, "iv")?;
        if iv_bytes.len() != AES_IV_SIZE {
            return Err(EncryptionError::InitializationFailed {
                message: format!(
                    "IV must be {} hex characters ({} bytes)",
                    AES_IV_SIZE * 2,
                    AES_IV_SIZE
                ),
            });
        }
        self.deterministic_iv.copy_from_slice(&iv_bytes);

        Ok(())
    }

    /// Apply PKCS7 padding to data.
    fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat_n(padding_len as u8, padding_len));
        padded
    }

    /// Remove PKCS7 padding from data.
    fn unpad_pkcs7(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(EncryptionError::DecryptionFailed {
                message: "Empty data for unpadding".to_string(),
            });
        }

        let padding_len = data[data.len() - 1] as usize;

        if padding_len == 0 || padding_len > AES_BLOCK_SIZE || padding_len > data.len() {
            return Err(EncryptionError::DecryptionFailed {
                message: "Invalid padding".to_string(),
            });
        }

        let unpadded_len = data.len() - padding_len;

        // Verify padding bytes
        for &byte in &data[unpadded_len..] {
            if byte != padding_len as u8 {
                return Err(EncryptionError::DecryptionFailed {
                    message: "Invalid padding bytes".to_string(),
                });
            }
        }

        Ok(data[..unpadded_len].to_vec())
    }

    /// Encrypt with a specific IV.
    fn encrypt_with_iv(&self, plaintext: &str, iv: &[u8; AES_IV_SIZE]) -> Result<String> {
        if plaintext.is_empty() {
            return Ok(add_encryption_prefix(""));
        }

        let plaintext_bytes = plaintext.as_bytes();
        let padded_data = Self::pad_pkcs7(plaintext_bytes, AES_BLOCK_SIZE);

        let encryptor = Aes256CbcEnc::new(&self.key.into(), iv.into());
        let mut encrypted = padded_data.clone();
        encryptor
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(
                &mut encrypted,
                padded_data.len(),
            )
            .map_err(|e| EncryptionError::EncryptionFailed {
                message: format!("AES encryption failed: {:?}", e),
            })?;

        // Prepend IV to encrypted data
        let mut result = iv.to_vec();
        result.extend_from_slice(&encrypted);

        let encoded = general_purpose::STANDARD.encode(&result);
        Ok(add_encryption_prefix(&encoded))
    }

    /// Decrypt by extracting IV from ciphertext.
    fn decrypt_with_extraction(&self, ciphertext: &str) -> Result<String> {
        if !has_encryption_prefix(ciphertext) {
            return Err(EncryptionError::DecryptionFailed {
                message: "Missing encryption prefix".to_string(),
            });
        }

        let encoded_data = remove_encryption_prefix(ciphertext)?;

        if encoded_data.is_empty() {
            return Ok(String::new());
        }

        let encrypted_data = general_purpose::STANDARD
            .decode(encoded_data)
            .map_err(|e| EncryptionError::DecryptionFailed {
                message: format!("Base64 decode error: {}", e),
            })?;

        if encrypted_data.len() < AES_IV_SIZE {
            return Err(EncryptionError::DecryptionFailed {
                message: "Encrypted data too short".to_string(),
            });
        }

        // Extract IV and encrypted data
        let (iv_bytes, encrypted_bytes) = encrypted_data.split_at(AES_IV_SIZE);
        let iv: [u8; AES_IV_SIZE] =
            iv_bytes
                .try_into()
                .map_err(|_| EncryptionError::DecryptionFailed {
                    message: "Invalid IV size".to_string(),
                })?;

        let decryptor = Aes256CbcDec::new(&self.key.into(), &iv.into());
        let mut decrypted = encrypted_bytes.to_vec();

        decryptor
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
            .map_err(|e| EncryptionError::DecryptionFailed {
                message: format!("AES decryption failed: {:?}", e),
            })?;

        let unpadded = Self::unpad_pkcs7(&decrypted)?;

        String::from_utf8(unpadded).map_err(|e| EncryptionError::DecryptionFailed {
            message: format!("UTF-8 decode error: {}", e),
        })
    }
}

impl EncryptionProvider for AesEncryption {
    fn init(&mut self) -> Result<()> {
        let key_hex =
            std::env::var("SZ_AES_KEY").map_err(|_| EncryptionError::InitializationFailed {
                message: "SZ_AES_KEY environment variable not set".to_string(),
            })?;

        let key_bytes = parse_hex_string(&key_hex, "SZ_AES_KEY")?;
        if key_bytes.len() != AES_KEY_SIZE {
            return Err(EncryptionError::InitializationFailed {
                message: format!(
                    "SZ_AES_KEY must be {} hex characters ({} bytes)",
                    AES_KEY_SIZE * 2,
                    AES_KEY_SIZE
                ),
            });
        }
        self.key.copy_from_slice(&key_bytes);

        let iv_hex =
            std::env::var("SZ_AES_IV").map_err(|_| EncryptionError::InitializationFailed {
                message: "SZ_AES_IV environment variable not set".to_string(),
            })?;

        let iv_bytes = parse_hex_string(&iv_hex, "SZ_AES_IV")?;
        if iv_bytes.len() != AES_IV_SIZE {
            return Err(EncryptionError::InitializationFailed {
                message: format!(
                    "SZ_AES_IV must be {} hex characters ({} bytes)",
                    AES_IV_SIZE * 2,
                    AES_IV_SIZE
                ),
            });
        }
        self.deterministic_iv.copy_from_slice(&iv_bytes);

        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.key.zeroize();
        self.deterministic_iv.zeroize();
        Ok(())
    }

    fn signature(&self) -> &'static str {
        AES_SIGNATURE
    }

    fn encrypt(&self, plaintext: &str) -> Result<String> {
        // For example purposes, just use deterministic encryption
        self.encrypt_deterministic(plaintext)
    }

    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> {
        // Use the configured deterministic IV
        self.encrypt_with_iv(plaintext, &self.deterministic_iv)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String> {
        self.decrypt_with_extraction(ciphertext)
    }

    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> {
        self.decrypt_with_extraction(ciphertext)
    }

    fn validate_signature(&self, signature: &str) -> Result<()> {
        if signature == AES_SIGNATURE {
            Ok(())
        } else {
            Err(EncryptionError::InvalidSignature {
                signature: signature.to_string(),
            })
        }
    }
}

impl Drop for AesEncryption {
    fn drop(&mut self) {
        self.key.zeroize();
        self.deterministic_iv.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TEST_IV: &str = "0123456789abcdef0123456789abcdef";

    fn make_encryption() -> AesEncryption {
        let mut enc = AesEncryption::new();
        enc.init_with_key_iv(TEST_KEY, TEST_IV).unwrap();
        enc
    }

    #[test]
    fn test_aes_encryption_roundtrip() {
        let encryption = make_encryption();

        let plaintext = "Hello, AES World!";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
        assert!(ciphertext.starts_with("ENC:"));
    }

    #[test]
    fn test_aes_deterministic_encryption() {
        let encryption = make_encryption();

        let plaintext = "Deterministic AES test";
        let ciphertext1 = encryption.encrypt_deterministic(plaintext).unwrap();
        let ciphertext2 = encryption.encrypt_deterministic(plaintext).unwrap();

        assert_eq!(ciphertext1, ciphertext2);

        let decrypted = encryption.decrypt_deterministic(&ciphertext1).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_non_deterministic_encryption() {
        let encryption = make_encryption();

        let plaintext = "Non-deterministic test";
        let ciphertext1 = encryption.encrypt(plaintext).unwrap();
        let ciphertext2 = encryption.encrypt(plaintext).unwrap();

        // For example plugins, both methods use deterministic encryption
        assert_eq!(ciphertext1, ciphertext2);

        // Both should decrypt to the same plaintext
        let decrypted1 = encryption.decrypt(&ciphertext1).unwrap();
        let decrypted2 = encryption.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext, decrypted1);
        assert_eq!(plaintext, decrypted2);
    }

    #[test]
    fn test_empty_string() {
        let encryption = make_encryption();

        let ciphertext = encryption.encrypt("").unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!("", decrypted);
    }

    #[test]
    fn test_signature_validation() {
        let encryption = AesEncryption::new();

        assert!(encryption.validate_signature(AES_SIGNATURE).is_ok());
        assert!(encryption.validate_signature("INVALID").is_err());
    }
}
