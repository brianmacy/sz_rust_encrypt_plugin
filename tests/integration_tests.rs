use sz_encrypt_plugin::{EncryptionManager, EncryptionType};

#[test]
fn test_dummy_encryption_integration() {
    let mut manager = EncryptionManager::new(EncryptionType::Dummy).unwrap();
    manager.init().unwrap();

    let plaintext = "Integration test for dummy encryption";

    // Test regular encryption
    let encrypted = manager.encrypt(plaintext).unwrap();
    assert!(encrypted.starts_with("ENC:"));

    let decrypted = manager.decrypt(&encrypted).unwrap();
    assert_eq!(plaintext, decrypted);

    // Test deterministic encryption
    let encrypted_det1 = manager.encrypt_deterministic(plaintext).unwrap();
    let encrypted_det2 = manager.encrypt_deterministic(plaintext).unwrap();
    assert_eq!(encrypted_det1, encrypted_det2);

    let decrypted_det = manager.decrypt_deterministic(&encrypted_det1).unwrap();
    assert_eq!(plaintext, decrypted_det);

    // Test signature
    assert_eq!(manager.signature(), "DUMMY_XOR_v1.0");
    assert!(manager.validate_signature("DUMMY_XOR_v1.0").is_ok());
    assert!(manager.validate_signature("INVALID").is_err());

    manager.close().unwrap();
}

#[test]
fn test_aes_encryption_integration() {
    let mut manager = EncryptionManager::new(EncryptionType::Aes256).unwrap();
    manager.init().unwrap();

    let plaintext = "Integration test for AES encryption";

    // Test regular encryption
    let encrypted = manager.encrypt(plaintext).unwrap();
    assert!(encrypted.starts_with("ENC:"));

    let decrypted = manager.decrypt(&encrypted).unwrap();
    assert_eq!(plaintext, decrypted);

    // Test deterministic encryption
    let encrypted_det1 = manager.encrypt_deterministic(plaintext).unwrap();
    let encrypted_det2 = manager.encrypt_deterministic(plaintext).unwrap();
    assert_eq!(encrypted_det1, encrypted_det2);

    let decrypted_det = manager.decrypt_deterministic(&encrypted_det1).unwrap();
    assert_eq!(plaintext, decrypted_det);

    // Test signature
    assert_eq!(manager.signature(), "AES256_CBC_v1.0");
    assert!(manager.validate_signature("AES256_CBC_v1.0").is_ok());
    assert!(manager.validate_signature("INVALID").is_err());

    manager.close().unwrap();
}

#[test]
fn test_cross_encryption_compatibility() {
    // Test that AES and Dummy can't decrypt each other's data
    let mut dummy_manager = EncryptionManager::new(EncryptionType::Dummy).unwrap();
    let mut aes_manager = EncryptionManager::new(EncryptionType::Aes256).unwrap();

    dummy_manager.init().unwrap();
    aes_manager.init().unwrap();

    let plaintext = "Cross compatibility test";

    let dummy_encrypted = dummy_manager.encrypt(plaintext).unwrap();
    let aes_encrypted = aes_manager.encrypt(plaintext).unwrap();

    // Each should decrypt its own
    assert_eq!(dummy_manager.decrypt(&dummy_encrypted).unwrap(), plaintext);
    assert_eq!(aes_manager.decrypt(&aes_encrypted).unwrap(), plaintext);

    // But not the other's (this should fail gracefully)
    assert!(dummy_manager.decrypt(&aes_encrypted).is_err());
    assert!(aes_manager.decrypt(&dummy_encrypted).is_err());

    dummy_manager.close().unwrap();
    aes_manager.close().unwrap();
}

#[test]
fn test_empty_string_handling() {
    let mut manager = EncryptionManager::new(EncryptionType::Dummy).unwrap();
    manager.init().unwrap();

    let encrypted = manager.encrypt("").unwrap();
    let decrypted = manager.decrypt(&encrypted).unwrap();
    assert_eq!("", decrypted);

    manager.close().unwrap();
}

#[test]
fn test_large_data() {
    let mut manager = EncryptionManager::new(EncryptionType::Aes256).unwrap();
    manager.init().unwrap();

    let large_data = "x".repeat(10000);
    let encrypted = manager.encrypt(&large_data).unwrap();
    let decrypted = manager.decrypt(&encrypted).unwrap();
    assert_eq!(large_data, decrypted);

    manager.close().unwrap();
}

#[test]
fn test_unicode_data() {
    let mut manager = EncryptionManager::new(EncryptionType::Dummy).unwrap();
    manager.init().unwrap();

    let unicode_data = "Hello 世界 🌍 café résumé naïve";
    let encrypted = manager.encrypt(unicode_data).unwrap();
    let decrypted = manager.decrypt(&encrypted).unwrap();
    assert_eq!(unicode_data, decrypted);

    manager.close().unwrap();
}

#[test]
fn test_manager_lifecycle() {
    let mut manager = EncryptionManager::new(EncryptionType::Dummy).unwrap();

    // Should fail before init
    assert!(manager.encrypt("test").is_err());

    manager.init().unwrap();

    // Should work after init
    assert!(manager.encrypt("test").is_ok());

    manager.close().unwrap();

    // Should fail after close
    assert!(manager.encrypt("test").is_err());
}