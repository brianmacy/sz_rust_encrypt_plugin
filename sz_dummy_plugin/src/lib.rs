//! # Senzing Dummy Encryption Plugin
//!
//! A simple XOR-based encryption plugin for development and testing purposes.
//! This plugin should NOT be used in production environments.

mod c_interface;
mod dummy_encryption;

pub use c_interface::*;
pub use dummy_encryption::DummyEncryption;
pub use sz_common::{EncryptionError, EncryptionProvider, Result};

/// Plugin signature for dummy encryption
pub const DUMMY_SIGNATURE: &str = "DUMMY_XOR_v1.0";
