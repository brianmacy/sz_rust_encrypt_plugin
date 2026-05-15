//! Macro to generate the C FFI layer for any `EncryptionProvider` implementation.
//!
//! Each Senzing encryption plugin exports the same 8 `extern "C"` functions.
//! This macro generates all of them from a single invocation, eliminating
//! ~300 lines of duplicated boilerplate per plugin.

/// FFI-compatible parameter tuple matching `CParameterTuple` from the Senzing spec.
#[repr(C)]
pub struct CParameterTuple {
    pub param_name: *const libc::c_char,
    pub param_value: *const libc::c_char,
}

/// FFI-compatible parameter list matching `CParameterList` from the Senzing spec.
#[repr(C)]
pub struct CParameterList {
    pub param_tuples: *mut CParameterTuple,
    pub num_parameters: libc::size_t,
}

// Function pointer typedefs for dlsym casting.
// cbindgen generates these as C `typedef ... (*Name)(...);` declarations.

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginInitPluginFuncPtr = Option<
    unsafe extern "C" fn(
        *const CParameterList,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginClosePluginFuncPtr =
    Option<unsafe extern "C" fn(*mut libc::c_char, libc::size_t, *mut libc::size_t) -> i64>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginGetSignatureFuncPtr = Option<
    unsafe extern "C" fn(
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginValidateSignatureCompatibilityFuncPtr = Option<
    unsafe extern "C" fn(
        *const libc::c_char,
        libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginEncryptDataFieldFuncPtr = Option<
    unsafe extern "C" fn(
        *const libc::c_char,
        libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginDecryptDataFieldFuncPtr = Option<
    unsafe extern "C" fn(
        *const libc::c_char,
        libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginEncryptDataFieldDeterministicFuncPtr = Option<
    unsafe extern "C" fn(
        *const libc::c_char,
        libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

#[allow(non_camel_case_types)]
pub type G2EncryptionPluginDecryptDataFieldDeterministicFuncPtr = Option<
    unsafe extern "C" fn(
        *const libc::c_char,
        libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
        *mut libc::c_char,
        libc::size_t,
        *mut libc::size_t,
    ) -> i64,
>;

/// Generate the complete C FFI interface for an encryption plugin.
///
/// The supplied type must implement `EncryptionProvider + Default`.
/// `Default::default()` is used to construct a fresh instance inside
/// `G2Encryption_InitPlugin`, which then calls `init()` on it.
///
/// # Example
///
/// ```rust,ignore
/// use sz_common::declare_c_interface;
/// declare_c_interface!(MyEncryption);
/// ```
#[macro_export]
macro_rules! declare_c_interface {
    ($encryption_type:ty) => {
        use std::sync::{Mutex, OnceLock};
        use $crate::{
            EncryptionError, EncryptionProvider, c_str_to_string, error_to_c_buffer,
            string_to_c_buffer,
        };

        static ENCRYPTION: OnceLock<Mutex<Option<$encryption_type>>> = OnceLock::new();

        fn get_encryption() -> &'static Mutex<Option<$encryption_type>> {
            ENCRYPTION.get_or_init(|| Mutex::new(None))
        }

        fn with_encryption<F, R>(f: F) -> Result<R, EncryptionError>
        where
            F: FnOnce(&$encryption_type) -> Result<R, EncryptionError>,
        {
            let encryption_lock =
                get_encryption()
                    .lock()
                    .map_err(|_| EncryptionError::Internal {
                        message: "Failed to acquire encryption lock".to_string(),
                    })?;

            match encryption_lock.as_ref() {
                Some(encryption) => f(encryption),
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
            _config_params: *const $crate::c_interface_macro::CParameterList,
            error_buffer: *mut libc::c_char,
            max_error_size: libc::size_t,
            error_size: *mut libc::size_t,
        ) -> i64 {
            let result = (|| -> Result<(), EncryptionError> {
                let mut encryption = <$encryption_type>::default();
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
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Close the encryption plugin
        ///
        /// # Safety
        /// Callers must ensure all pointer parameters are valid.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn G2Encryption_ClosePlugin(
            error_buffer: *mut libc::c_char,
            max_error_size: libc::size_t,
            error_size: *mut libc::size_t,
        ) -> i64 {
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
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Get the encryption signature
        ///
        /// # Safety
        /// Callers must ensure all pointer parameters are valid.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn G2Encryption_GetSignature(
            signature_buffer: *mut libc::c_char,
            max_signature_size: libc::size_t,
            signature_size: *mut libc::size_t,
            error_buffer: *mut libc::c_char,
            max_error_size: libc::size_t,
            error_size: *mut libc::size_t,
        ) -> i64 {
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
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Validate signature compatibility
        ///
        /// # Safety
        /// Callers must ensure all pointer parameters are valid.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn G2Encryption_ValidateSignatureCompatibility(
            signature_to_validate: *const libc::c_char,
            signature_to_validate_size: libc::size_t,
            error_buffer: *mut libc::c_char,
            max_error_size: libc::size_t,
            error_size: *mut libc::size_t,
        ) -> i64 {
            let result = (|| -> Result<(), EncryptionError> {
                let signature = c_str_to_string(signature_to_validate, signature_to_validate_size)?;
                with_encryption(|encryption| encryption.validate_signature(&signature))
            })();

            match result {
                Ok(()) => 0,
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Encrypt a data field
        ///
        /// # Safety
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
        ) -> i64 {
            let result = (|| -> Result<(), EncryptionError> {
                let plaintext = c_str_to_string(input, input_size)?;
                let encrypted = with_encryption(|encryption| encryption.encrypt(&plaintext))?;
                unsafe {
                    string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size)
                }
            })();

            match result {
                Ok(()) => 0,
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Decrypt a data field
        ///
        /// # Safety
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
        ) -> i64 {
            let result = (|| -> Result<(), EncryptionError> {
                let ciphertext = c_str_to_string(input, input_size)?;
                let decrypted = with_encryption(|encryption| encryption.decrypt(&ciphertext))?;
                unsafe {
                    string_to_c_buffer(&decrypted, result_buffer, max_result_size, result_size)
                }
            })();

            match result {
                Ok(()) => 0,
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Encrypt a data field (deterministic)
        ///
        /// # Safety
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
        ) -> i64 {
            let result = (|| -> Result<(), EncryptionError> {
                let plaintext = c_str_to_string(input, input_size)?;
                let encrypted =
                    with_encryption(|encryption| encryption.encrypt_deterministic(&plaintext))?;
                unsafe {
                    string_to_c_buffer(&encrypted, result_buffer, max_result_size, result_size)
                }
            })();

            match result {
                Ok(()) => 0,
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        /// Decrypt a data field (deterministic)
        ///
        /// # Safety
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
        ) -> i64 {
            let result = (|| -> Result<(), EncryptionError> {
                let ciphertext = c_str_to_string(input, input_size)?;
                let decrypted =
                    with_encryption(|encryption| encryption.decrypt_deterministic(&ciphertext))?;
                unsafe {
                    string_to_c_buffer(&decrypted, result_buffer, max_result_size, result_size)
                }
            })();

            match result {
                Ok(()) => 0,
                Err(e) => unsafe {
                    error_to_c_buffer(&e, error_buffer, max_error_size, error_size)
                },
            }
        }

        // Compile-time check: each function's signature must match its typedef.
        // If the macro-generated extern "C" function drifts from the type alias
        // in c_interface_macro.rs, this block fails to compile.
        #[allow(dead_code, unused_variables)]
        fn _sz_assert_ffi_signatures() {
            use $crate::c_interface_macro::*;
            let _a: G2EncryptionPluginInitPluginFuncPtr = Some(G2Encryption_InitPlugin);
            let _b: G2EncryptionPluginClosePluginFuncPtr = Some(G2Encryption_ClosePlugin);
            let _c: G2EncryptionPluginGetSignatureFuncPtr = Some(G2Encryption_GetSignature);
            let _d: G2EncryptionPluginValidateSignatureCompatibilityFuncPtr =
                Some(G2Encryption_ValidateSignatureCompatibility);
            let _e: G2EncryptionPluginEncryptDataFieldFuncPtr = Some(G2Encryption_EncryptDataField);
            let _f: G2EncryptionPluginDecryptDataFieldFuncPtr = Some(G2Encryption_DecryptDataField);
            let _g: G2EncryptionPluginEncryptDataFieldDeterministicFuncPtr =
                Some(G2Encryption_EncryptDataFieldDeterministic);
            let _h: G2EncryptionPluginDecryptDataFieldDeterministicFuncPtr =
                Some(G2Encryption_DecryptDataFieldDeterministic);
        }
    };
}
