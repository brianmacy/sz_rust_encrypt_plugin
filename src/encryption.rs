use crate::errors::Result;

pub trait EncryptionProvider: Send + Sync {
    fn init(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn signature(&self) -> &'static str;
    fn encrypt(&self, plaintext: &str) -> Result<String>;
    fn encrypt_deterministic(&self, plaintext: &str) -> Result<String>;
    fn decrypt(&self, ciphertext: &str) -> Result<String>;
    fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String>;
    fn validate_signature(&self, signature: &str) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionType {
    Dummy,
    Aes256,
}

impl Default for EncryptionType {
    fn default() -> Self {
        EncryptionType::Dummy
    }
}

pub struct EncryptionManager {
    provider: Box<dyn EncryptionProvider>,
    initialized: bool,
}

impl EncryptionManager {
    pub fn new(encryption_type: EncryptionType) -> Result<Self> {
        let provider: Box<dyn EncryptionProvider> = match encryption_type {
            EncryptionType::Dummy => Box::new(crate::dummy::DummyEncryption::new()),
            EncryptionType::Aes256 => Box::new(crate::aes::AesEncryption::new()),
        };

        Ok(EncryptionManager {
            provider,
            initialized: false,
        })
    }

    pub fn init(&mut self) -> Result<()> {
        self.provider.init()?;
        self.initialized = true;
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        if self.initialized {
            self.provider.close()?;
            self.initialized = false;
        }
        Ok(())
    }

    pub fn signature(&self) -> &str {
        self.provider.signature()
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        if !self.initialized {
            return Err(crate::errors::EncryptionError::NotInitialized);
        }
        self.provider.encrypt(plaintext)
    }

    pub fn encrypt_deterministic(&self, plaintext: &str) -> Result<String> {
        if !self.initialized {
            return Err(crate::errors::EncryptionError::NotInitialized);
        }
        self.provider.encrypt_deterministic(plaintext)
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String> {
        if !self.initialized {
            return Err(crate::errors::EncryptionError::NotInitialized);
        }
        self.provider.decrypt(ciphertext)
    }

    pub fn decrypt_deterministic(&self, ciphertext: &str) -> Result<String> {
        if !self.initialized {
            return Err(crate::errors::EncryptionError::NotInitialized);
        }
        self.provider.decrypt_deterministic(ciphertext)
    }

    pub fn validate_signature(&self, signature: &str) -> Result<()> {
        self.provider.validate_signature(signature)
    }
}