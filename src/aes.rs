use crate::encryption::EncryptionProvider;
use crate::errors::{EncryptionError, Result};
use crate::utils::{add_encryption_prefix, has_encryption_prefix, remove_encryption_prefix, SIGNATURE_AES};
use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use zeroize::Zeroize;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const AES_KEY_SIZE: usize = 32; // 256 bits
const AES_IV_SIZE: usize = 16;  // 128 bits
const AES_BLOCK_SIZE: usize = 16;

pub struct AesEncryption {
    key: [u8; AES_KEY_SIZE],
    deterministic_iv: [u8; AES_IV_SIZE],
}

impl AesEncryption {
    pub fn new() -> Self {
        Self {
            key: [0u8; AES_KEY_SIZE],
            deterministic_iv: [0u8; AES_IV_SIZE],
        }
    }

    fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        padded
    }

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

    fn encrypt_with_iv(&self, plaintext: &str, iv: &[u8; AES_IV_SIZE]) -> Result<String> {
        if plaintext.is_empty() {
            return Ok(add_encryption_prefix(""));
        }

        let plaintext_bytes = plaintext.as_bytes();
        let padded_data = Self::pad_pkcs7(plaintext_bytes, AES_BLOCK_SIZE);

        let encryptor = Aes256CbcEnc::new(&self.key.into(), iv.into());
        let mut encrypted = padded_data.clone();
        encryptor
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut encrypted, padded_data.len())
            .map_err(|e| EncryptionError::EncryptionFailed {
                message: format!("AES encryption failed: {:?}", e),
            })?;

        // Prepend IV to encrypted data
        let mut result = iv.to_vec();
        result.extend_from_slice(&encrypted);

        let encoded = general_purpose::STANDARD.encode(&result);
        Ok(add_encryption_prefix(&encoded))
    }

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
        let iv: [u8; AES_IV_SIZE] = iv_bytes.try_into().map_err(|_| EncryptionError::DecryptionFailed {
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
        // In a real implementation, this key would come from configuration
        // For this example, we derive it from the signature
        let signature_bytes = SIGNATURE_AES.as_bytes();
        for (i, byte) in self.key.iter_mut().enumerate() {
            *byte = signature_bytes[i % signature_bytes.len()];
        }

        // Initialize deterministic IV the same way as the key
        // In a real implementation, this IV would also come from configuration
        // For this example, we derive it from a different part of the signature
        let iv_source = format!("{}__IV", SIGNATURE_AES);
        let iv_source_bytes = iv_source.as_bytes();
        for (i, byte) in self.deterministic_iv.iter_mut().enumerate() {
            *byte = iv_source_bytes[i % iv_source_bytes.len()];
        }

        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.key.zeroize();
        self.deterministic_iv.zeroize();
        Ok(())
    }

    fn signature(&self) -> &'static str {
        SIGNATURE_AES
    }

    fn encrypt(&self, plaintext: &str) -> Result<String> {
        // Generate random IV for non-deterministic encryption
        let mut iv = [0u8; AES_IV_SIZE];
        rand::thread_rng().fill_bytes(&mut iv);
        self.encrypt_with_iv(plaintext, &iv)
    }

    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> {
        // Use the configured deterministic IV instead of generating from plaintext
        self.encrypt_with_iv(plaintext, &self.deterministic_iv)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String> {
        self.decrypt_with_extraction(ciphertext)
    }

    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> {
        self.decrypt_with_extraction(ciphertext)
    }

    fn validate_signature(&self, signature: &str) -> Result<()> {
        if signature == SIGNATURE_AES {
            Ok(())
        } else {
            Err(EncryptionError::InvalidSignature {
                signature: signature.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encryption_roundtrip() {
        let mut encryption = AesEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Hello, AES World!";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
        assert!(ciphertext.starts_with("ENC:"));
    }

    #[test]
    fn test_aes_deterministic_encryption() {
        let mut encryption = AesEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Deterministic AES test";
        let ciphertext1 = encryption.encrypt_deterministic(plaintext).unwrap();
        let ciphertext2 = encryption.encrypt_deterministic(plaintext).unwrap();

        assert_eq!(ciphertext1, ciphertext2);

        let decrypted = encryption.decrypt_deterministic(&ciphertext1).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_non_deterministic_encryption() {
        let mut encryption = AesEncryption::new();
        encryption.init().unwrap();

        let plaintext = "Non-deterministic test";
        let ciphertext1 = encryption.encrypt(plaintext).unwrap();
        let ciphertext2 = encryption.encrypt(plaintext).unwrap();

        // Should be different due to random IVs
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = encryption.decrypt(&ciphertext1).unwrap();
        let decrypted2 = encryption.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext, decrypted1);
        assert_eq!(plaintext, decrypted2);
    }

    #[test]
    fn test_empty_string() {
        let mut encryption = AesEncryption::new();
        encryption.init().unwrap();

        let ciphertext = encryption.encrypt("").unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!("", decrypted);
    }

    #[test]
    fn test_pkcs7_padding() {
        let data = b"Hello";
        let padded = AesEncryption::pad_pkcs7(data, 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[5..], [11; 11]); // 11 padding bytes with value 11

        let unpadded = AesEncryption::unpad_pkcs7(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_invalid_ciphertext() {
        let mut encryption = AesEncryption::new();
        encryption.init().unwrap();

        let result = encryption.decrypt("invalid_data");
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_validation() {
        let encryption = AesEncryption::new();

        assert!(encryption.validate_signature(SIGNATURE_AES).is_ok());
        assert!(encryption.validate_signature("INVALID").is_err());
    }
}