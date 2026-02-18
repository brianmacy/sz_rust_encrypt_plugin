/* Senzing Encryption Plugin Interface - Rust Implementation
 *
 * Single shared header for all Senzing encryption plugins.
 * All plugins export the same C interface; the specific algorithm
 * is determined by which shared library is loaded at runtime.
 *
 * Conforms to:
 * https://github.com/Senzing/senzing-data-encryption-specification/blob/main/src/interface/g2EncryptionPluginInterface_defs.h
 */
#ifndef SZ_ENCRYPT_PLUGIN_H
#define SZ_ENCRYPT_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Senzing spec structs */
struct CParameterTuple {
    const char *paramName;
    const char *paramValue;
};

struct CParameterList {
    struct CParameterTuple *paramTuples;
    size_t numParameters;
};

/* Return codes per spec */
#define G2_ENCRYPTION_PLUGIN___SUCCESS                      0
#define G2_ENCRYPTION_PLUGIN___SIMPLE_ERROR                -1
#define G2_ENCRYPTION_PLUGIN___OUTPUT_BUFFER_SIZE_ERROR    -5
#define G2_ENCRYPTION_PLUGIN___CRITICAL_ERROR              -20
#define G2_ENCRYPTION_PLUGIN___FAILED_SIGNATURE_VALIDATION -30

int64_t G2Encryption_InitPlugin(
    const struct CParameterList* config_params,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_ClosePlugin(
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_GetSignature(
    char* signature_buffer,
    const size_t max_signature_size,
    size_t* signature_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_ValidateSignatureCompatibility(
    const char* signature_to_validate,
    const size_t signature_to_validate_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_EncryptDataField(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_DecryptDataField(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_EncryptDataFieldDeterministic(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int64_t G2Encryption_DecryptDataFieldDeterministic(
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

#endif /* SZ_ENCRYPT_PLUGIN_H */
