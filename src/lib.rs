//! # Senzing Encryption Plugin - Rust Implementation
//!
//! A Rust implementation of a Senzing encryption plugin that provides a C-compatible
//! shared library interface. This plugin demonstrates secure encryption patterns and
//! serves as a working example for developers implementing encryption plugins for the
//! Senzing data platform.
//!
//! ## Features
//!
//! - **C Compatible Interface**: Implements the exact C API that Senzing expects
//! - **Multiple Encryption Methods**: Dummy XOR and AES-256-CBC implementations
//! - **Deterministic and Non-deterministic Encryption**: Supports both modes
//! - **Memory Safe**: Built with Rust's memory safety guarantees
//! - **Thread Safe**: Concurrent access support for multi-threaded environments
//!
//! ## Architecture
//!
//! The plugin is structured in layers:
//!
//! - **C Interface Layer** (`c_interface`): FFI wrapper functions for C compatibility
//! - **Manager Layer** (`encryption`): High-level encryption management
//! - **Implementation Layer** (`dummy`, `aes`): Specific encryption algorithms
//! - **Utility Layer** (`utils`, `errors`): Common functionality and error handling
//!
//! ## Example Usage
//!
//! ```rust
//! use sz_encrypt_plugin::{EncryptionManager, EncryptionType};
//!
//! // Create and initialize encryption manager
//! let mut manager = EncryptionManager::new(EncryptionType::Aes256)?;
//! manager.init()?;
//!
//! // Encrypt data
//! let plaintext = "Sensitive data";
//! let encrypted = manager.encrypt(plaintext)?;
//!
//! // Decrypt data
//! let decrypted = manager.decrypt(&encrypted)?;
//! assert_eq!(plaintext, decrypted);
//!
//! // Clean up
//! manager.close()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod aes;
pub mod c_interface;
pub mod dummy;
pub mod encryption;
pub mod errors;
pub mod utils;

// Re-export main types for easy access
pub use encryption::{EncryptionManager, EncryptionProvider, EncryptionType};
pub use errors::{EncryptionError, Result};

// Re-export C interface functions
pub use c_interface::*;
