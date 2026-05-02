//! # Senzing AES Encryption Plugin
//!
//! Reference AES-256-CBC encryption plugin for Senzing. Both `encrypt()` and
//! `encrypt_deterministic()` use the same fixed IV configured at init time —
//! see `aes_encryption::AesEncryption` for the security trade-off and what a
//! production-quality plugin would do differently.

mod aes_encryption;
mod c_interface;

pub use aes_encryption::AesEncryption;
pub use c_interface::*;
pub use sz_common::{EncryptionError, EncryptionProvider, Result};

/// Plugin signature for AES encryption
pub const AES_SIGNATURE: &str = "AES256_CBC_v1.0";
