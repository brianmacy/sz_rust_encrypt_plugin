use sz_encrypt_plugin::{EncryptionManager, EncryptionType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Senzing Encryption Plugin - Rust Implementation Example");
    println!("========================================================");

    // Example 1: Dummy (XOR) Encryption
    println!("\n1. Dummy XOR Encryption Example:");
    demo_encryption(EncryptionType::Dummy)?;

    // Example 2: AES Encryption
    println!("\n2. AES-256-CBC Encryption Example:");
    demo_encryption(EncryptionType::Aes256)?;

    // Example 3: Cross-compatibility test
    println!("\n3. Cross-compatibility Test:");
    cross_compatibility_test()?;

    println!("\nAll examples completed successfully!");
    Ok(())
}

fn demo_encryption(encryption_type: EncryptionType) -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = EncryptionManager::new(encryption_type)?;
    manager.init()?;

    let plaintext = "Hello, Senzing! This is a test message.";
    println!("  Original text: {}", plaintext);

    // Regular encryption
    let encrypted = manager.encrypt(plaintext)?;
    println!("  Encrypted:     {}", encrypted);

    let decrypted = manager.decrypt(&encrypted)?;
    println!("  Decrypted:     {}", decrypted);

    assert_eq!(plaintext, decrypted);

    // Deterministic encryption
    let det_encrypted1 = manager.encrypt_deterministic(plaintext)?;
    let det_encrypted2 = manager.encrypt_deterministic(plaintext)?;
    println!("  Det. Encrypt1: {}", det_encrypted1);
    println!("  Det. Encrypt2: {}", det_encrypted2);

    assert_eq!(det_encrypted1, det_encrypted2);

    let det_decrypted = manager.decrypt_deterministic(&det_encrypted1)?;
    assert_eq!(plaintext, det_decrypted);

    // Signature information
    println!("  Signature:     {}", manager.signature());

    manager.close()?;
    println!("  ✓ All operations successful");

    Ok(())
}

fn cross_compatibility_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut dummy_manager = EncryptionManager::new(EncryptionType::Dummy)?;
    let mut aes_manager = EncryptionManager::new(EncryptionType::Aes256)?;

    dummy_manager.init()?;
    aes_manager.init()?;

    let plaintext = "Cross-compatibility test message";

    let dummy_encrypted = dummy_manager.encrypt(plaintext)?;
    let aes_encrypted = aes_manager.encrypt(plaintext)?;

    println!("  Dummy encrypted: {}", dummy_encrypted);
    println!("  AES encrypted:   {}", aes_encrypted);

    // Each should decrypt its own successfully
    assert_eq!(dummy_manager.decrypt(&dummy_encrypted)?, plaintext);
    assert_eq!(aes_manager.decrypt(&aes_encrypted)?, plaintext);

    // But not the other's (should fail gracefully)
    println!("  Testing cross-decryption (should fail):");

    match dummy_manager.decrypt(&aes_encrypted) {
        Ok(_) => println!("    ✗ Unexpected success: Dummy decrypted AES data"),
        Err(e) => println!("    ✓ Expected failure: {}", e),
    }

    match aes_manager.decrypt(&dummy_encrypted) {
        Ok(_) => println!("    ✗ Unexpected success: AES decrypted Dummy data"),
        Err(e) => println!("    ✓ Expected failure: {}", e),
    }

    dummy_manager.close()?;
    aes_manager.close()?;

    Ok(())
}