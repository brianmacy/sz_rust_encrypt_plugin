use crate::errors::{EncryptionError, Result};

/// Parse a hex string into a `Vec<u8>`.
///
/// `var_name` is included in error messages to identify which value failed.
pub fn parse_hex_string(hex: &str, var_name: &str) -> Result<Vec<u8>> {
    if hex.is_empty() {
        return Err(EncryptionError::InitializationFailed {
            message: format!("{var_name} cannot be empty"),
        });
    }
    if hex.len() & 1 != 0 {
        return Err(EncryptionError::InitializationFailed {
            message: format!("{var_name} must have even number of hex characters"),
        });
    }

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex_str =
                std::str::from_utf8(chunk).map_err(|_| EncryptionError::InitializationFailed {
                    message: format!("Invalid hex characters in {var_name}"),
                })?;
            u8::from_str_radix(hex_str, 16).map_err(|_| EncryptionError::InitializationFailed {
                message: format!("Invalid hex characters in {var_name}"),
            })
        })
        .collect()
}

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
    // Buffer must hold the data plus a trailing null terminator we always write
    // for C-string callers; that's the size we check against `max_size`.
    let required_size = bytes.len() + 1;

    if required_size > max_size {
        // Spec: on OUTPUT_BUFFER_SIZE_ERROR the plugin's preamble already set
        // `*actual_size = 0`; the success path is the only one that writes a
        // payload length. Don't touch `*actual_size` here so we mirror the
        // C++ macro POSTAMBLE behavior — the caller's retry loop expects to
        // read back zero on the too-small path (see DataEncryptionLoader.cpp).
        return Err(EncryptionError::BufferTooSmall {
            required: required_size,
            available: max_size,
        });
    }

    // Success path. `*actual_size` is the *data* length only — the trailing
    // null we write past the payload is not counted. The Senzing plugin spec
    // and the C++ reference (`g2EncryptDataClearText`: `*resultSize = inputSize`)
    // both define it that way, and the consumer assigns exactly that many
    // bytes (`output.assign(buffer.getBuffer(), resultSize)` in
    // `DataEncryptionLoader::encrypt`). Reporting `bytes.len() + 1` historically
    // leaked the trailing `\0` into every encrypted row on disk.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
        *((buffer as *mut u8).add(bytes.len())) = 0; // null terminator
        *actual_size = bytes.len();
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
) -> i64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `actual_size` reports payload length only — the trailing null we write
    /// for C-string callers is *not* counted. Reporting `len + 1` historically
    /// caused the engine to read the null as data and store `<value>\0` rows
    /// on disk, breaking SQL_TABLE comparisons against C++ reference plugins
    /// that follow the spec.
    #[test]
    fn string_to_c_buffer_reports_data_length_only() {
        let s = "hello";
        let mut buf = [0u8; 16];
        let mut size: usize = 0;
        let rc = unsafe {
            string_to_c_buffer(
                s,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut size,
            )
        };
        assert!(rc.is_ok());
        assert_eq!(
            size, 5,
            "actual_size must equal payload length, not buffer length"
        );
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(
            buf[5], 0,
            "buffer must still be null-terminated past the payload"
        );
    }

    #[test]
    fn string_to_c_buffer_empty_string() {
        let mut buf = [0xFFu8; 4];
        let mut size: usize = usize::MAX;
        let rc = unsafe {
            string_to_c_buffer(
                "",
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut size,
            )
        };
        assert!(rc.is_ok());
        assert_eq!(size, 0);
        assert_eq!(buf[0], 0, "empty payload still leaves a null at offset 0");
    }

    #[test]
    fn string_to_c_buffer_buffer_too_small() {
        // Need 5 + 1 = 6 bytes to hold "hello\0"; provide only 5.
        let s = "hello";
        let mut buf = [0u8; 5];
        // Caller's preamble pattern (mirrors C++ POSTAMBLE): zero the size
        // before the call, expect it to stay at zero on too-small.
        let mut size: usize = 0;
        let rc = unsafe {
            string_to_c_buffer(
                s,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut size,
            )
        };
        assert!(matches!(rc, Err(EncryptionError::BufferTooSmall { .. })));
        assert_eq!(
            size, 0,
            "too-small path must not write *actual_size; caller's zero-init must survive"
        );
    }

    #[test]
    fn string_to_c_buffer_unicode() {
        // 7 UTF-8 bytes for "héllo!" (é = 2 bytes), ensure size is byte length.
        let s = "héllo!";
        assert_eq!(s.len(), 7);
        let mut buf = [0u8; 16];
        let mut size: usize = 0;
        let rc = unsafe {
            string_to_c_buffer(
                s,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut size,
            )
        };
        assert!(rc.is_ok());
        assert_eq!(size, 7);
        assert_eq!(&buf[..7], s.as_bytes());
        assert_eq!(buf[7], 0);
    }
}
