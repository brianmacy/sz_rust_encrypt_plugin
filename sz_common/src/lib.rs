//! # Senzing Encryption Plugin Common Library
//!
//! This library provides common traits, utilities, and error types shared
//! across all Senzing encryption plugin implementations.

pub mod c_interface_macro;
pub mod errors;
pub mod traits;
pub mod utils;

// Re-export commonly used types
pub use errors::{EncryptionError, Result};
pub use traits::EncryptionProvider;
pub use utils::*;

// Re-export FFI types for cbindgen visibility
pub use c_interface_macro::{
    CParameterList, CParameterTuple, G2EncryptionPluginClosePluginFuncPtr,
    G2EncryptionPluginDecryptDataFieldDeterministicFuncPtr,
    G2EncryptionPluginDecryptDataFieldFuncPtr,
    G2EncryptionPluginEncryptDataFieldDeterministicFuncPtr,
    G2EncryptionPluginEncryptDataFieldFuncPtr, G2EncryptionPluginGetSignatureFuncPtr,
    G2EncryptionPluginInitPluginFuncPtr, G2EncryptionPluginValidateSignatureCompatibilityFuncPtr,
};
pub use errors::{
    G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR, G2_ENCRYPTION_PLUGIN___FAILED_SIGNATURE_VALIDATION,
    G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR, G2_ENCRYPTION_PLUGIN___SIMPLE_ERROR,
    G2_ENCRYPTION_PLUGIN___SUCCESS,
};
