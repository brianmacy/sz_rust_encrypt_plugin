//! C interface for the AES encryption plugin.
//!
//! This module provides the C-compatible functions required by Senzing
//! for dynamic plugin loading and operation.

use crate::aes_encryption::AesEncryption;
use std::sync::{Mutex, OnceLock};
use sz_common::{
    EncryptionError, EncryptionProvider, c_str_to_string, error_to_c_buffer, string_to_c_buffer,
};

static AES_ENCRYPTION: OnceLock<Mutex<Option<AesEncryption>>> = OnceLock::new();

fn get_encryption() -> &'static Mutex<Option<AesEncryption>> {
    AES_ENCRYPTION.get_or_init(|| Mutex::new(None))
}

fn with_encryption<F, R>(f: F) -> Result<R, EncryptionError>
where
    F: FnOnce(&AesEncryption) -> Result<R, EncryptionError>,
{
    let encryption_lock = get_encryption()
        .lock()
        .map_err(|_| EncryptionError::Internal {
            message: "Failed to acquire encryption lock".to_string(),
        })?;

    match encryption_lock.as_ref() {
        Some(encryption) => f(encryption),
        None => Err(EncryptionError::NotInitialized),
    }
}

/// Initialize the AES encryption plugin
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_InitPlugin(
    _config_params: *const libc::c_void,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let mut encryption = AesEncryption::new();
        encryption.init()?;

        let mut encryption_lock =
            get_encryption()
                .lock()
                .map_err(|_| EncryptionError::Internal {
                    message: "Failed to acquire encryption lock".to_string(),
                })?;

        *encryption_lock = Some(encryption);
        Ok(())
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Close the AES encryption plugin
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_ClosePlugin(
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let mut encryption_lock =
            get_encryption()
                .lock()
                .map_err(|_| EncryptionError::Internal {
                    message: "Failed to acquire encryption lock".to_string(),
                })?;

        if let Some(ref mut encryption) = encryption_lock.as_mut() {
            encryption.close()?;
        }

        *encryption_lock = None;
        Ok(())
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Get the AES encryption signature
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_GetSignature(
    signature_buffer: *mut libc::c_char,
    max_signature_size: libc::size_t,
    signature_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = with_encryption(|encryption| {
        let signature = encryption.signature();
        unsafe {
            string_to_c_buffer(
                signature,
                signature_buffer,
                max_signature_size,
                signature_size,
            )
        }
    });

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Validate signature compatibility
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_ValidateSignatureCompatibility(
    signature_to_validate: *const libc::c_char,
    signature_to_validate_size: libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let signature = c_str_to_string(signature_to_validate, signature_to_validate_size)?;
        with_encryption(|encryption| encryption.validate_signature(&signature))
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Encrypt a data field
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_EncryptDataField(
    input: *const libc::c_char,
    input_size: libc::size_t,
    result_buffer: *mut libc::c_char,
    max_result_size: libc::size_t,
    result_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let plaintext = c_str_to_string(input, input_size)?;
        let encrypted = with_encryption(|encryption| encryption.encrypt(&plaintext))?;
        unsafe { string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size) }
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Decrypt a data field
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_DecryptDataField(
    input: *const libc::c_char,
    input_size: libc::size_t,
    result_buffer: *mut libc::c_char,
    max_result_size: libc::size_t,
    result_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let ciphertext = c_str_to_string(input, input_size)?;
        let decrypted = with_encryption(|encryption| encryption.decrypt(&ciphertext))?;
        unsafe { string_to_c_buffer(&decrypted, result_buffer, max_result_size, result_size) }
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Encrypt a data field (deterministic)
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_EncryptDataFieldDeterministic(
    input: *const libc::c_char,
    input_size: libc::size_t,
    result_buffer: *mut libc::c_char,
    max_result_size: libc::size_t,
    result_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let plaintext = c_str_to_string(input, input_size)?;
        let encrypted = with_encryption(|encryption| encryption.encrypt_deterministic(&plaintext))?;
        unsafe { string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size) }
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}

/// Decrypt a data field (deterministic)
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers passed from C
/// - Assumes pointers are valid for the duration of the call
/// - Requires proper C ABI calling convention
///
/// Callers must ensure all pointer parameters are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_DecryptDataFieldDeterministic(
    input: *const libc::c_char,
    input_size: libc::size_t,
    result_buffer: *mut libc::c_char,
    max_result_size: libc::size_t,
    result_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let ciphertext = c_str_to_string(input, input_size)?;
        let decrypted =
            with_encryption(|encryption| encryption.decrypt_deterministic(&ciphertext))?;
        unsafe { string_to_c_buffer(&decrypted, result_buffer, max_result_size, result_size) }
    })();

    match result {
        Ok(()) => 0,
        Err(e) => unsafe { error_to_c_buffer(&e, error_buffer, max_error_size, error_size) },
    }
}
