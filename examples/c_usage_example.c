#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function declarations for the Senzing encryption plugin
extern int G2Encryption_InitPlugin(
    const void* config_params,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

extern int G2Encryption_ClosePlugin(
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

extern int G2Encryption_GetSignature(
    char* signature_buffer,
    const size_t max_signature_size,
    size_t* signature_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

extern int G2Encryption_EncryptDataField(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

extern int G2Encryption_DecryptDataField(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

extern int G2Encryption_EncryptDataFieldDeterministic(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

extern int G2Encryption_DecryptDataFieldDeterministic(
    const char* input,
    const size_t input_size,
    char* result_buffer,
    const size_t max_result_size,
    size_t* result_size,
    char* error_buffer,
    const size_t max_error_size,
    size_t* error_size
);

int main() {
    printf("Senzing Encryption Plugin - C Usage Example\n");
    printf("===========================================\n\n");

    char error_buffer[1024];
    size_t error_size = 0;
    int result;

    // Initialize the plugin
    printf("1. Initializing plugin...\n");
    result = G2Encryption_InitPlugin(
        NULL,  // No config params for this example
        error_buffer,
        sizeof(error_buffer),
        &error_size
    );

    if (result != 0) {
        printf("   ✗ Failed to initialize plugin: %.*s\n", (int)error_size, error_buffer);
        return 1;
    }
    printf("   ✓ Plugin initialized successfully\n");

    // Get the signature
    printf("\n2. Getting plugin signature...\n");
    char signature_buffer[256];
    size_t signature_size = 0;

    result = G2Encryption_GetSignature(
        signature_buffer,
        sizeof(signature_buffer),
        &signature_size,
        error_buffer,
        sizeof(error_buffer),
        &error_size
    );

    if (result != 0) {
        printf("   ✗ Failed to get signature: %.*s\n", (int)error_size, error_buffer);
    } else {
        printf("   ✓ Plugin signature: %.*s\n", (int)signature_size - 1, signature_buffer);
    }

    // Test encryption and decryption
    printf("\n3. Testing encryption/decryption...\n");
    const char* plaintext = "Hello from C! This is a test message.";
    printf("   Original: %s\n", plaintext);

    char encrypted_buffer[2048];
    size_t encrypted_size = 0;

    result = G2Encryption_EncryptDataField(
        plaintext,
        strlen(plaintext) + 1,  // Include null terminator
        encrypted_buffer,
        sizeof(encrypted_buffer),
        &encrypted_size,
        error_buffer,
        sizeof(error_buffer),
        &error_size
    );

    if (result != 0) {
        printf("   ✗ Encryption failed: %.*s\n", (int)error_size, error_buffer);
    } else {
        printf("   ✓ Encrypted: %.*s\n", (int)encrypted_size - 1, encrypted_buffer);

        // Now decrypt it back
        char decrypted_buffer[2048];
        size_t decrypted_size = 0;

        result = G2Encryption_DecryptDataField(
            encrypted_buffer,
            encrypted_size,
            decrypted_buffer,
            sizeof(decrypted_buffer),
            &decrypted_size,
            error_buffer,
            sizeof(error_buffer),
            &error_size
        );

        if (result != 0) {
            printf("   ✗ Decryption failed: %.*s\n", (int)error_size, error_buffer);
        } else {
            printf("   ✓ Decrypted: %.*s\n", (int)decrypted_size - 1, decrypted_buffer);

            // Verify round-trip
            if (strcmp(plaintext, decrypted_buffer) == 0) {
                printf("   ✓ Round-trip successful!\n");
            } else {
                printf("   ✗ Round-trip failed: data mismatch\n");
            }
        }
    }

    // Test deterministic encryption
    printf("\n4. Testing deterministic encryption...\n");
    char det_encrypted1[2048];
    char det_encrypted2[2048];
    size_t det_size1 = 0, det_size2 = 0;

    const char* det_plaintext = "Deterministic test message";

    // First encryption
    result = G2Encryption_EncryptDataFieldDeterministic(
        det_plaintext,
        strlen(det_plaintext) + 1,
        det_encrypted1,
        sizeof(det_encrypted1),
        &det_size1,
        error_buffer,
        sizeof(error_buffer),
        &error_size
    );

    if (result != 0) {
        printf("   ✗ First deterministic encryption failed: %.*s\n", (int)error_size, error_buffer);
    } else {
        // Second encryption
        result = G2Encryption_EncryptDataFieldDeterministic(
            det_plaintext,
            strlen(det_plaintext) + 1,
            det_encrypted2,
            sizeof(det_encrypted2),
            &det_size2,
            error_buffer,
            sizeof(error_buffer),
            &error_size
        );

        if (result != 0) {
            printf("   ✗ Second deterministic encryption failed: %.*s\n", (int)error_size, error_buffer);
        } else {
            printf("   ✓ First:  %.*s\n", (int)det_size1 - 1, det_encrypted1);
            printf("   ✓ Second: %.*s\n", (int)det_size2 - 1, det_encrypted2);

            if (det_size1 == det_size2 && strcmp(det_encrypted1, det_encrypted2) == 0) {
                printf("   ✓ Deterministic encryption is consistent!\n");
            } else {
                printf("   ✗ Deterministic encryption results differ\n");
            }
        }
    }

    // Close the plugin
    printf("\n5. Closing plugin...\n");
    result = G2Encryption_ClosePlugin(
        error_buffer,
        sizeof(error_buffer),
        &error_size
    );

    if (result != 0) {
        printf("   ✗ Failed to close plugin: %.*s\n", (int)error_size, error_buffer);
        return 1;
    }
    printf("   ✓ Plugin closed successfully\n");

    printf("\nAll tests completed!\n");
    return 0;
}