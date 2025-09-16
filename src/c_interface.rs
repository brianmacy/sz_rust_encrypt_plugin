use crate::encryption::{EncryptionManager, EncryptionType};
use crate::errors::EncryptionError;
use crate::utils::{c_str_to_string, error_to_c_buffer, string_to_c_buffer};
use std::sync::{Mutex, OnceLock};

static ENCRYPTION_MANAGER: OnceLock<Mutex<Option<EncryptionManager>>> = OnceLock::new();

fn get_manager() -> &'static Mutex<Option<EncryptionManager>> {
    ENCRYPTION_MANAGER.get_or_init(|| Mutex::new(None))
}

fn with_manager<F, R>(f: F) -> Result<R, EncryptionError>
where
    F: FnOnce(&EncryptionManager) -> Result<R, EncryptionError>,
{
    let manager_lock = get_manager().lock().map_err(|_| EncryptionError::Internal {
        message: "Failed to acquire manager lock".to_string(),
    })?;

    match manager_lock.as_ref() {
        Some(manager) => f(manager),
        None => Err(EncryptionError::NotInitialized),
    }
}


/// Initialize the encryption plugin
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_InitPlugin(
    _config_params: *const libc::c_void, // CParameterList not implemented for this example
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        // For this example, we'll use the dummy encryption by default
        // In a real implementation, this would be parsed from config_params
        let encryption_type = EncryptionType::Dummy;

        let mut manager = EncryptionManager::new(encryption_type)?;
        manager.init()?;

        let mut manager_lock = get_manager().lock().map_err(|_| EncryptionError::Internal {
            message: "Failed to acquire manager lock".to_string(),
        })?;

        *manager_lock = Some(manager);
        Ok(())
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Close the encryption plugin
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_ClosePlugin(
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = (|| -> Result<(), EncryptionError> {
        let mut manager_lock = get_manager().lock().map_err(|_| EncryptionError::Internal {
            message: "Failed to acquire manager lock".to_string(),
        })?;

        if let Some(ref mut manager) = manager_lock.as_mut() {
            manager.close()?;
        }

        *manager_lock = None;
        Ok(())
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Get the encryption signature
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
#[unsafe(no_mangle)]
pub unsafe extern "C" fn G2Encryption_GetSignature(
    signature_buffer: *mut libc::c_char,
    max_signature_size: libc::size_t,
    signature_size: *mut libc::size_t,
    error_buffer: *mut libc::c_char,
    max_error_size: libc::size_t,
    error_size: *mut libc::size_t,
) -> libc::c_int {
    let result = with_manager(|manager| {
        let signature = manager.signature();
        string_to_c_buffer(signature, signature_buffer, max_signature_size, signature_size)
    });

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Validate signature compatibility
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
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
        with_manager(|manager| manager.validate_signature(&signature))
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Encrypt a data field
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
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
        let encrypted = with_manager(|manager| manager.encrypt(&plaintext))?;
        string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size)
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Decrypt a data field
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
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
        let decrypted = with_manager(|manager| manager.decrypt(&ciphertext))?;
        string_to_c_buffer(&decrypted, result_buffer, max_result_size, result_size)
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Encrypt a data field (deterministic)
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
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
        let encrypted = with_manager(|manager| manager.encrypt_deterministic(&plaintext))?;
        string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size)
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}

/// Decrypt a data field (deterministic)
///
/// # Safety
/// This function is intended to be called from C code and assumes:
/// - All pointer parameters are valid for the duration of the call
/// - Buffer sizes are accurate
/// - Strings are properly null-terminated
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
        let decrypted = with_manager(|manager| manager.decrypt_deterministic(&ciphertext))?;
        string_to_c_buffer(&decrypted, result_buffer, max_result_size, result_size)
    })();

    match result {
        Ok(()) => 0,
        Err(e) => error_to_c_buffer(&e, error_buffer, max_error_size, error_size),
    }
}