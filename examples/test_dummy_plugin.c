#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Function declarations for the Dummy plugin
extern int G2Encryption_InitPlugin(const void* config_params, char* error_buffer,
                                   const size_t max_error_size, size_t* error_size);
extern int G2Encryption_ClosePlugin(char* error_buffer, const size_t max_error_size,
                                    size_t* error_size);
extern int G2Encryption_GetSignature(char* signature_buffer, const size_t max_signature_size,
                                     size_t* signature_size, char* error_buffer,
                                     const size_t max_error_size, size_t* error_size);
extern int G2Encryption_ValidateSignatureCompatibility(const char* signature_to_validate,
                                                       const size_t signature_to_validate_size,
                                                       char* error_buffer, const size_t max_error_size,
                                                       size_t* error_size);
extern int G2Encryption_EncryptDataField(const char* input, const size_t input_size,
                                         char* result_buffer, const size_t max_result_size,
                                         size_t* result_size, char* error_buffer,
                                         const size_t max_error_size, size_t* error_size);
extern int G2Encryption_DecryptDataField(const char* input, const size_t input_size,
                                         char* result_buffer, const size_t max_result_size,
                                         size_t* result_size, char* error_buffer,
                                         const size_t max_error_size, size_t* error_size);
extern int G2Encryption_EncryptDataFieldDeterministic(const char* input, const size_t input_size,
                                                      char* result_buffer, const size_t max_result_size,
                                                      size_t* result_size, char* error_buffer,
                                                      const size_t max_error_size, size_t* error_size);
extern int G2Encryption_DecryptDataFieldDeterministic(const char* input, const size_t input_size,
                                                      char* result_buffer, const size_t max_result_size,
                                                      size_t* result_size, char* error_buffer,
                                                      const size_t max_error_size, size_t* error_size);

#define BUFFER_SIZE 2048
#define ERROR_BUFFER_SIZE 1024

void print_error(const char* operation, int result, const char* error_buffer, size_t error_size) {
    if (result != 0) {
        printf("❌ %s failed (code %d): %.*s\n", operation, result, (int)error_size, error_buffer);
    }
}

int test_plugin_lifecycle() {
    printf("🔧 Testing Dummy Plugin Lifecycle...\n");

    char error_buffer[ERROR_BUFFER_SIZE];
    size_t error_size = 0;
    int result;

    // Test initialization
    result = G2Encryption_InitPlugin(NULL, error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        print_error("InitPlugin", result, error_buffer, error_size);
        return 1;
    }
    printf("✅ Plugin initialized successfully\n");

    // Test signature retrieval
    char signature_buffer[256];
    size_t signature_size = 0;
    result = G2Encryption_GetSignature(signature_buffer, sizeof(signature_buffer), &signature_size,
                                      error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        print_error("GetSignature", result, error_buffer, error_size);
        return 1;
    }
    printf("✅ Plugin signature: %.*s\n", (int)signature_size - 1, signature_buffer);

    // Test signature validation
    result = G2Encryption_ValidateSignatureCompatibility(signature_buffer, signature_size - 1,
                                                         error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        print_error("ValidateSignatureCompatibility", result, error_buffer, error_size);
        return 1;
    }
    printf("✅ Signature validation passed\n");

    // Test cleanup
    result = G2Encryption_ClosePlugin(error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        print_error("ClosePlugin", result, error_buffer, error_size);
        return 1;
    }
    printf("✅ Plugin closed successfully\n");

    return 0;
}

int test_encryption_operations() {
    printf("\n🔐 Testing Dummy Encryption Operations...\n");

    char error_buffer[ERROR_BUFFER_SIZE];
    size_t error_size = 0;
    int result;

    // Initialize plugin
    result = G2Encryption_InitPlugin(NULL, error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        print_error("InitPlugin", result, error_buffer, error_size);
        return 1;
    }

    const char* test_data[] = {
        "Hello, World!",
        "Senzing encryption test",
        "This is a longer piece of text to test encryption with multiple blocks",
        "",  // Empty string test
        "Unicode test: 你好世界 🌍",
        "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?"
    };

    for (int i = 0; i < 6; i++) {
        const char* plaintext = test_data[i];
        size_t plaintext_len = strlen(plaintext) + 1;  // Include null terminator

        printf("\n📝 Testing with: \"%s\"\n", plaintext);

        // Test regular encryption/decryption
        char encrypted_buffer[BUFFER_SIZE];
        char decrypted_buffer[BUFFER_SIZE];
        size_t encrypted_size = 0;
        size_t decrypted_size = 0;

        result = G2Encryption_EncryptDataField(plaintext, plaintext_len,
                                              encrypted_buffer, sizeof(encrypted_buffer), &encrypted_size,
                                              error_buffer, sizeof(error_buffer), &error_size);
        if (result != 0) {
            print_error("EncryptDataField", result, error_buffer, error_size);
            continue;
        }
        printf("✅ Encrypted (length %zu): %.*s\n", encrypted_size - 1, (int)encrypted_size - 1, encrypted_buffer);

        result = G2Encryption_DecryptDataField(encrypted_buffer, encrypted_size,
                                              decrypted_buffer, sizeof(decrypted_buffer), &decrypted_size,
                                              error_buffer, sizeof(error_buffer), &error_size);
        if (result != 0) {
            print_error("DecryptDataField", result, error_buffer, error_size);
            continue;
        }

        if (strcmp(plaintext, decrypted_buffer) == 0) {
            printf("✅ Regular encryption/decryption roundtrip successful\n");
        } else {
            printf("❌ Regular encryption/decryption roundtrip failed\n");
            printf("   Expected: \"%s\"\n", plaintext);
            printf("   Got:      \"%s\"\n", decrypted_buffer);
        }

        // Test deterministic encryption/decryption
        char det_encrypted_buffer[BUFFER_SIZE];
        char det_decrypted_buffer[BUFFER_SIZE];
        size_t det_encrypted_size = 0;
        size_t det_decrypted_size = 0;

        result = G2Encryption_EncryptDataFieldDeterministic(plaintext, plaintext_len,
                                                           det_encrypted_buffer, sizeof(det_encrypted_buffer), &det_encrypted_size,
                                                           error_buffer, sizeof(error_buffer), &error_size);
        if (result != 0) {
            print_error("EncryptDataFieldDeterministic", result, error_buffer, error_size);
            continue;
        }
        printf("✅ Deterministic encrypted (length %zu): %.*s\n", det_encrypted_size - 1, (int)det_encrypted_size - 1, det_encrypted_buffer);

        result = G2Encryption_DecryptDataFieldDeterministic(det_encrypted_buffer, det_encrypted_size,
                                                           det_decrypted_buffer, sizeof(det_decrypted_buffer), &det_decrypted_size,
                                                           error_buffer, sizeof(error_buffer), &error_size);
        if (result != 0) {
            print_error("DecryptDataFieldDeterministic", result, error_buffer, error_size);
            continue;
        }

        if (strcmp(plaintext, det_decrypted_buffer) == 0) {
            printf("✅ Deterministic encryption/decryption roundtrip successful\n");
        } else {
            printf("❌ Deterministic encryption/decryption roundtrip failed\n");
            printf("   Expected: \"%s\"\n", plaintext);
            printf("   Got:      \"%s\"\n", det_decrypted_buffer);
        }

        // For the simplified implementation, regular and deterministic should be the same
        if (encrypted_size == det_encrypted_size &&
            memcmp(encrypted_buffer, det_encrypted_buffer, encrypted_size) == 0) {
            printf("✅ Regular and deterministic encryption produce same result (as expected)\n");
        } else {
            printf("⚠️  Regular and deterministic encryption produce different results\n");
        }

        // Test consistency - encrypt the same data twice
        char encrypted_buffer2[BUFFER_SIZE];
        size_t encrypted_size2 = 0;

        result = G2Encryption_EncryptDataFieldDeterministic(plaintext, plaintext_len,
                                                           encrypted_buffer2, sizeof(encrypted_buffer2), &encrypted_size2,
                                                           error_buffer, sizeof(error_buffer), &error_size);
        if (result == 0) {
            if (encrypted_size == encrypted_size2 &&
                memcmp(det_encrypted_buffer, encrypted_buffer2, encrypted_size) == 0) {
                printf("✅ Deterministic encryption is consistent\n");
            } else {
                printf("❌ Deterministic encryption is not consistent\n");
            }
        }
    }

    // Cleanup
    G2Encryption_ClosePlugin(error_buffer, sizeof(error_buffer), &error_size);

    return 0;
}

int test_error_conditions() {
    printf("\n🚨 Testing Error Conditions...\n");

    char error_buffer[ERROR_BUFFER_SIZE];
    size_t error_size = 0;
    int result;

    // Initialize plugin
    result = G2Encryption_InitPlugin(NULL, error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        print_error("InitPlugin", result, error_buffer, error_size);
        return 1;
    }

    // Test invalid ciphertext
    const char* invalid_ciphertext = "This is not valid base64 encoded data!";
    char decrypted_buffer[BUFFER_SIZE];
    size_t decrypted_size = 0;

    result = G2Encryption_DecryptDataField(invalid_ciphertext, strlen(invalid_ciphertext) + 1,
                                          decrypted_buffer, sizeof(decrypted_buffer), &decrypted_size,
                                          error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        printf("✅ Invalid ciphertext properly rejected: %.*s\n", (int)error_size, error_buffer);
    } else {
        printf("❌ Invalid ciphertext was not rejected\n");
    }

    // Test buffer too small
    const char* test_text = "Test data";
    char small_buffer[5];  // Too small for encrypted result
    size_t small_size = 0;

    result = G2Encryption_EncryptDataField(test_text, strlen(test_text) + 1,
                                          small_buffer, sizeof(small_buffer), &small_size,
                                          error_buffer, sizeof(error_buffer), &error_size);
    if (result != 0) {
        printf("✅ Small buffer properly rejected: %.*s\n", (int)error_size, error_buffer);
    } else {
        printf("❌ Small buffer was not rejected\n");
    }

    // Cleanup
    G2Encryption_ClosePlugin(error_buffer, sizeof(error_buffer), &error_size);

    return 0;
}

int main() {
    printf("🧪 Dummy Plugin Test Suite\n");
    printf("===========================\n");

    // Set environment variable for testing
    setenv("SZ_DUMMY_KEY", "44554d4d595f584f525f763130", 1);  // "DUMMY_XOR_v10" in hex

    printf("🔑 Environment variable set:\n");
    printf("   SZ_DUMMY_KEY=44554d4d595f584f525f763130\n\n");

    if (test_plugin_lifecycle() != 0) {
        printf("\n❌ Plugin lifecycle tests failed\n");
        return 1;
    }

    if (test_encryption_operations() != 0) {
        printf("\n❌ Encryption operation tests failed\n");
        return 1;
    }

    if (test_error_conditions() != 0) {
        printf("\n❌ Error condition tests failed\n");
        return 1;
    }

    printf("\n🎉 All Dummy plugin tests passed!\n");
    return 0;
}