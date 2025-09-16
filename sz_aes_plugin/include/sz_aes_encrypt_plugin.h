/* Senzing AES Encryption Plugin - Rust Implementation */
#ifndef SZ_AES_ENCRYPT_PLUGIN_H
#define SZ_AES_ENCRYPT_PLUGIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int G2Encryption_InitPlugin(
    const void* config_params,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_ClosePlugin(
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_GetSignature(
    char* signature_buffer,
    const size_t max_signature_size,
    size_t* signature_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_ValidateSignatureCompatibility(
    const char* signature_to_validate,
    const size_t signature_to_validate_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_EncryptDataField(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_DecryptDataField(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_EncryptDataFieldDeterministic(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int G2Encryption_DecryptDataFieldDeterministic(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

#ifdef __cplusplus
}
#endif

#endif /* SZ_AES_ENCRYPT_PLUGIN_H */
