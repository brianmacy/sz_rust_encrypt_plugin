//! # Senzing AES Encryption Plugin
//!
//! A production-ready AES-256-CBC encryption plugin for Senzing that provides
//! both deterministic and non-deterministic encryption modes.

mod aes_encryption;
mod c_interface;

pub use aes_encryption::AesEncryption;
pub use c_interface::*;
pub use sz_common::{EncryptionError, EncryptionProvider, Result};

/// Plugin signature for AES encryption
pub const AES_SIGNATURE: &str = "AES256_CBC_v1.0";
