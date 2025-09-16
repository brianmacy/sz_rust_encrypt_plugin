//! Error handling for the encryption plugin.
//!
//! This module defines the comprehensive error types used throughout the plugin,
//! providing structured error information that can be properly translated to
//! C error codes and messages.

use thiserror::Error;

/// Comprehensive error type for all encryption plugin operations.
///
/// This enum covers all possible error conditions that can occur during
/// plugin operations, from initialization failures to encryption/decryption
/// errors. Each variant includes contextual information to aid in debugging.
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// Buffer provided is too small to hold the result.
    ///
    /// This error occurs when C interface functions are called with output
    /// buffers that are insufficient to hold the encrypted/decrypted data.
    #[error("Buffer too small: required {required}, available {available}")]
    BufferTooSmall {
        /// The number of bytes required for the operation
        required: usize,
        /// The number of bytes available in the provided buffer
        available: usize,
    },

    /// Invalid input data was provided.
    ///
    /// This covers malformed data, null pointers, invalid UTF-8, and other
    /// input validation failures.
    #[error("Invalid input: {message}")]
    InvalidInput {
        /// Detailed description of the input validation failure
        message: String,
    },

    /// Encryption operation failed.
    ///
    /// This indicates a failure in the actual encryption process, such as
    /// cryptographic library errors or invalid encryption parameters.
    #[error("Encryption failed: {message}")]
    EncryptionFailed {
        /// Detailed description of the encryption failure
        message: String,
    },

    /// Decryption operation failed.
    ///
    /// This indicates a failure in the decryption process, such as invalid
    /// ciphertext, wrong keys, or corrupted data.
    #[error("Decryption failed: {message}")]
    DecryptionFailed {
        /// Detailed description of the decryption failure
        message: String,
    },

    /// Plugin initialization failed.
    ///
    /// This error occurs during plugin initialization when configuration
    /// is invalid or required resources cannot be obtained.
    #[error("Initialization failed: {message}")]
    InitializationFailed {
        /// Detailed description of the initialization failure
        message: String,
    },

    /// Plugin has not been properly initialized.
    ///
    /// This error occurs when encryption/decryption operations are attempted
    /// before calling the initialization function.
    #[error("Plugin not initialized")]
    NotInitialized,

    /// Invalid or incompatible encryption signature.
    ///
    /// This occurs when signature validation fails, indicating that the
    /// plugin cannot handle data encrypted by a different implementation.
    #[error("Invalid signature: {signature}")]
    InvalidSignature {
        /// The signature that failed validation
        signature: String,
    },

    /// Internal plugin error.
    ///
    /// This covers unexpected errors such as threading issues, memory
    /// allocation failures, or other system-level problems.
    #[error("Internal error: {message}")]
    Internal {
        /// Detailed description of the internal error
        message: String,
    },
}

impl EncryptionError {
    /// Convert the error to a C-compatible error code.
    ///
    /// These error codes are returned by the C interface functions to
    /// indicate the type of error that occurred. Negative values indicate
    /// errors, with 0 indicating success.
    ///
    /// # Error Code Mapping
    ///
    /// - `-1`: Buffer too small
    /// - `-2`: Invalid input
    /// - `-3`: Encryption failed
    /// - `-4`: Decryption failed
    /// - `-5`: Initialization failed
    /// - `-6`: Plugin not initialized
    /// - `-7`: Invalid signature
    /// - `-99`: Internal error
    pub fn to_error_code(&self) -> i32 {
        match self {
            EncryptionError::BufferTooSmall { .. } => -1,
            EncryptionError::InvalidInput { .. } => -2,
            EncryptionError::EncryptionFailed { .. } => -3,
            EncryptionError::DecryptionFailed { .. } => -4,
            EncryptionError::InitializationFailed { .. } => -5,
            EncryptionError::NotInitialized => -6,
            EncryptionError::InvalidSignature { .. } => -7,
            EncryptionError::Internal { .. } => -99,
        }
    }
}

/// Convenient Result type alias for encryption operations.
///
/// This type alias simplifies function signatures throughout the codebase
/// by providing a default error type for all encryption-related operations.
pub type Result<T> = std::result::Result<T, EncryptionError>;
