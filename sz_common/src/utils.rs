use crate::errors::{EncryptionError, Result};

pub const ENCRYPTION_PREFIX: &str = "ENC:";
pub const SIGNATURE_DUMMY: &str = "DUMMY_XOR_v1.0";
pub const SIGNATURE_AES: &str = "AES256_CBC_v1.0";

pub fn c_str_to_string(c_str: *const libc::c_char, len: usize) -> Result<String> {
    if c_str.is_null() {
        return Err(EncryptionError::InvalidInput {
            message: "Null pointer provided".to_string(),
        });
    }

    let slice = unsafe { std::slice::from_raw_parts(c_str as *const u8, len) };

    // Remove null terminator if present
    let actual_len = if slice.last() == Some(&0) && len > 0 {
        len - 1
    } else {
        len
    };

    String::from_utf8(slice[..actual_len].to_vec()).map_err(|e| EncryptionError::InvalidInput {
        message: format!("Invalid UTF-8: {}", e),
    })
}

/// Convert a Rust string to a C buffer with null termination.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers (`buffer` and `actual_size`)
/// - Assumes the pointers are valid and properly aligned
/// - Assumes the buffer has at least `max_size` bytes allocated
/// - Writes to memory through raw pointers
///
/// The caller must ensure:
/// - `buffer` points to a valid memory region of at least `max_size` bytes
/// - `actual_size` points to a valid `usize` location
/// - The pointers remain valid for the duration of this function call
/// - No other code is concurrently modifying the pointed-to memory
pub unsafe fn string_to_c_buffer(
    s: &str,
    buffer: *mut libc::c_char,
    max_size: usize,
    actual_size: *mut usize,
) -> Result<()> {
    if buffer.is_null() || actual_size.is_null() {
        return Err(EncryptionError::InvalidInput {
            message: "Null pointer provided".to_string(),
        });
    }

    let bytes = s.as_bytes();
    let required_size = bytes.len() + 1; // +1 for null terminator

    unsafe {
        *actual_size = required_size;
    }

    if required_size > max_size {
        return Err(EncryptionError::BufferTooSmall {
            required: required_size,
            available: max_size,
        });
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        *((buffer as *mut u8).add(bytes.len())) = 0; // null terminator
    }

    Ok(())
}

/// Convert an error to a C buffer and return error code.
///
/// # Safety
///
/// This function is unsafe because it calls `string_to_c_buffer` which
/// dereferences raw pointers. See `string_to_c_buffer` safety requirements.
pub unsafe fn error_to_c_buffer(
    error: &EncryptionError,
    error_buffer: *mut libc::c_char,
    max_error_size: usize,
    error_size: *mut usize,
) -> i32 {
    let error_code = error.to_error_code();
    let error_message = error.to_string();

    if !error_buffer.is_null() && !error_size.is_null() {
        unsafe {
            let _ = string_to_c_buffer(&error_message, error_buffer, max_error_size, error_size);
        }
    }

    error_code
}

pub fn has_encryption_prefix(data: &str) -> bool {
    data.starts_with(ENCRYPTION_PREFIX)
}

pub fn add_encryption_prefix(data: &str) -> String {
    format!("{}{}", ENCRYPTION_PREFIX, data)
}

pub fn remove_encryption_prefix(data: &str) -> Result<&str> {
    if !has_encryption_prefix(data) {
        return Err(EncryptionError::InvalidInput {
            message: "Data does not have encryption prefix".to_string(),
        });
    }
    Ok(&data[ENCRYPTION_PREFIX.len()..])
}
