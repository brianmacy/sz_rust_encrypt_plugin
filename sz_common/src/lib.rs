//! # Senzing Encryption Plugin Common Library
//!
//! This library provides common traits, utilities, and error types shared
//! across all Senzing encryption plugin implementations.

pub mod errors;
pub mod traits;
pub mod utils;

// Re-export commonly used types
pub use errors::{EncryptionError, Result};
pub use traits::EncryptionProvider;
pub use utils::*;
