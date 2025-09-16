//! Core traits for Senzing encryption providers.
//!
//! This module defines the fundamental interface that all encryption
//! implementations must provide.

use crate::errors::Result;

/// Core trait that all encryption providers must implement.
///
/// This trait defines the standard interface for encryption plugins,
/// providing both deterministic and non-deterministic encryption modes.
///
/// # Example
///
/// ```rust
/// use sz_common::{EncryptionProvider, EncryptionError, Result};
///
/// struct MyEncryption;
///
/// impl EncryptionProvider for MyEncryption {
///     fn init(&mut self) -> Result<()> {
///         // Initialize encryption keys/state
///         Ok(())
///     }
///
///     fn close(&mut self) -> Result<()> {
///         // Clean up sensitive data
///         Ok(())
///     }
///
///     fn signature(&self) -> &'static str {
///         "MY_ENCRYPTION_v1.0"
///     }
///
///     fn encrypt(&self, plaintext: &str) -> Result<String> {
///         // Implement non-deterministic encryption
///         todo!()
///     }
///
///     fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> {
///         // Implement deterministic encryption
///         todo!()
///     }
///
///     fn decrypt(&self, ciphertext: &str) -> Result<String> {
///         // Implement decryption
///         todo!()
///     }
///
///     fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> {
///         // Implement deterministic decryption
///         todo!()
///     }
///
///     fn validate_signature(&self, signature: &str) -> Result<()> {
///         if signature == self.signature() {
///             Ok(())
///         } else {
///             Err(EncryptionError::InvalidSignature {
///                 signature: signature.to_string(),
///             })
///         }
///     }
/// }
/// ```
pub trait EncryptionProvider: Send + Sync {
    /// Initialize the encryption provider.
    ///
    /// This method should set up any necessary keys, state, or resources
    /// required for encryption operations. It must be called before any
    /// encryption/decryption operations.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful initialization, or an `EncryptionError` if
    /// initialization fails.
    fn init(&mut self) -> Result<()>;

    /// Close and clean up the encryption provider.
    ///
    /// This method should securely clear any sensitive data (keys, intermediate
    /// values) and release any resources. After calling this method, the
    /// provider should not be used for further operations.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful cleanup, or an `EncryptionError` if cleanup fails.
    fn close(&mut self) -> Result<()>;

    /// Get the encryption signature for this provider.
    ///
    /// The signature identifies the encryption algorithm and version, allowing
    /// Senzing to validate compatibility between different plugin instances.
    ///
    /// # Returns
    ///
    /// A static string identifying the encryption algorithm and version.
    fn signature(&self) -> &'static str;

    /// Encrypt plaintext using non-deterministic encryption.
    ///
    /// Non-deterministic encryption produces different ciphertext for the same
    /// plaintext on each call, providing maximum security. This is suitable
    /// for sensitive data that doesn't need to be searched or indexed.
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The string to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted string, typically with a prefix identifying it as encrypted
    /// and base64-encoded for safe transport.
    fn encrypt(&self, plaintext: &str) -> Result<String>;

    /// Encrypt plaintext using deterministic encryption.
    ///
    /// Deterministic encryption produces the same ciphertext for the same
    /// plaintext on each call. This enables searching and indexing of encrypted
    /// data but provides slightly less security than non-deterministic encryption.
    ///
    /// # Parameters
    ///
    /// * `plaintext` - The string to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted string, which will be identical for identical inputs.
    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String>;

    /// Decrypt ciphertext that was encrypted with non-deterministic encryption.
    ///
    /// This method decrypts data that was previously encrypted using the
    /// `encrypt` method.
    ///
    /// # Parameters
    ///
    /// * `ciphertext` - The encrypted string to decrypt
    ///
    /// # Returns
    ///
    /// The original plaintext string.
    fn decrypt(&self, ciphertext: &str) -> Result<String>;

    /// Decrypt ciphertext that was encrypted with deterministic encryption.
    ///
    /// This method decrypts data that was previously encrypted using the
    /// `encrypt_deterministic` method.
    ///
    /// # Parameters
    ///
    /// * `ciphertext` - The encrypted string to decrypt
    ///
    /// # Returns
    ///
    /// The original plaintext string.
    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String>;

    /// Validate that the given signature is compatible with this provider.
    ///
    /// This method checks if the provider can decrypt data that was encrypted
    /// by a plugin with the given signature.
    ///
    /// # Parameters
    ///
    /// * `signature` - The signature to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is compatible, or an `EncryptionError` if not.
    fn validate_signature(&self, signature: &str) -> Result<()>;
}
