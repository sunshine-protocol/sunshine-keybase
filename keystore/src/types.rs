use crate::crypto::{AuthSecret, Secret, SECRET_LEN};
use bip39::Mnemonic;
use secrecy::SecretString;
use strobe_rs::AuthError;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct DeviceKey(Secret);

impl DeviceKey {
    pub async fn generate() -> Self {
        Self(Secret::generate().await)
    }

    pub fn from_seed(secret: [u8; SECRET_LEN]) -> Self {
        Self(Secret::new(secret))
    }

    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, NotEnoughEntropyError> {
        let entropy = mnemonic.entropy();
        if entropy.len() < SECRET_LEN {
            return Err(NotEnoughEntropyError);
        }
        let mut buf = [0; SECRET_LEN];
        buf.copy_from_slice(&entropy[..SECRET_LEN]);
        Ok(Self(Secret::new(buf)))
    }

    pub fn expose_secret(&self) -> &[u8; SECRET_LEN] {
        self.0.expose_secret()
    }

    pub(crate) async fn encrypt(&self, key: &RandomKey) -> EncryptedDeviceKey {
        EncryptedDeviceKey(self.0.auth_encrypt(&key.0).await)
    }
}

#[derive(Debug, Error)]
#[error("Mnemonic didn't contain enough entropy. Needs to provide at least 256 bits of entropy.")]
pub struct NotEnoughEntropyError;

pub(crate) struct EncryptedDeviceKey(pub AuthSecret);

impl EncryptedDeviceKey {
    pub fn decrypt(&self, key: &RandomKey) -> Result<DeviceKey, AuthError> {
        Ok(DeviceKey(self.0.auth_decrypt(&key.0)?))
    }
}

pub(crate) struct RandomKey(Secret);

impl RandomKey {
    pub async fn generate() -> Self {
        Self(Secret::generate().await)
    }

    pub fn public(&self, pass: &Password) -> PublicDeviceKey {
        PublicDeviceKey(self.0.xor(&pass.0))
    }

    pub fn password(&self, pdk: &PublicDeviceKey) -> Password {
        Password(self.0.xor(&pdk.0))
    }

    pub fn encrypt(&self, noise: &Secret) -> EncryptedRandomKey {
        EncryptedRandomKey(self.0.encrypt(noise))
    }
}

pub(crate) struct EncryptedRandomKey(pub Secret);

impl EncryptedRandomKey {
    pub fn decrypt(&self, key: &Secret) -> RandomKey {
        RandomKey(self.0.decrypt(key))
    }
}

#[derive(Clone, Debug)]
pub struct Password(Secret);

impl Password {
    pub fn new(plain: &SecretString) -> Self {
        Password(Secret::kdf(plain))
    }

    pub fn expose_secret(&self) -> &[u8; SECRET_LEN] {
        self.0.expose_secret()
    }

    pub(crate) fn mask(&self, other: &Password) -> Mask {
        Mask(self.0.xor(&other.0))
    }

    pub(crate) fn apply_mask(&self, mask: &Mask) -> Password {
        Password(self.0.xor(&mask.0))
    }
}

impl From<String> for Password {
    fn from(s: String) -> Password {
        Self::new(&SecretString::new(s))
    }
}

pub struct PublicDeviceKey(pub Secret);

impl PublicDeviceKey {
    pub fn new(pdk: [u8; SECRET_LEN]) -> Self {
        Self(Secret::new(pdk))
    }

    pub(crate) fn private(&self, pass: &Password) -> RandomKey {
        RandomKey(self.0.xor(&pass.0))
    }
}

impl core::ops::Deref for PublicDeviceKey {
    type Target = [u8; SECRET_LEN];

    fn deref(&self) -> &Self::Target {
        self.0.expose_secret()
    }
}

pub struct Mask(Secret);

impl Mask {
    pub fn new(mask: [u8; SECRET_LEN]) -> Self {
        Self(Secret::new(mask))
    }
}

impl core::ops::Deref for Mask {
    type Target = [u8; SECRET_LEN];

    fn deref(&self) -> &Self::Target {
        self.0.expose_secret()
    }
}
