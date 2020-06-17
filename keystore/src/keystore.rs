use crate::crypto::{AuthSecret, Secret, SECRET_LEN};
use crate::file::{AuthSecretFile, NoiseFile, SecretFile};
use bip39::Mnemonic;
use secrecy::SecretString;
use std::path::Path;
use strobe_rs::AuthError;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct DeviceKey(Secret);

impl DeviceKey {
    pub fn generate() -> Self {
        Self(Secret::generate())
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

    fn encrypt(&self, key: &RandomKey) -> EncryptedDeviceKey {
        EncryptedDeviceKey(self.0.auth_encrypt(&key.0))
    }
}

#[derive(Debug, Error)]
#[error("Mnemonic didn't contain enough entropy. Needs to provide at least 256 bits of entropy.")]
pub struct NotEnoughEntropyError;

struct EncryptedDeviceKey(AuthSecret);

impl EncryptedDeviceKey {
    fn decrypt(&self, key: &RandomKey) -> Result<DeviceKey, AuthError> {
        Ok(DeviceKey(self.0.auth_decrypt(&key.0)?))
    }
}

struct RandomKey(Secret);

impl RandomKey {
    fn generate() -> Self {
        Self(Secret::generate())
    }

    fn public(&self, pass: &Password) -> PublicDeviceKey {
        PublicDeviceKey(self.0.xor(&pass.0))
    }

    fn password(&self, pdk: &PublicDeviceKey) -> Password {
        Password(self.0.xor(&pdk.0))
    }

    fn encrypt(&self, noise: &Secret) -> EncryptedRandomKey {
        EncryptedRandomKey(self.0.encrypt(noise))
    }
}

struct EncryptedRandomKey(Secret);

impl EncryptedRandomKey {
    fn decrypt(&self, key: &Secret) -> RandomKey {
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

    fn mask(&self, other: &Password) -> Mask {
        Mask(self.0.xor(&other.0))
    }
}

impl From<String> for Password {
    fn from(s: String) -> Password {
        Self::new(&SecretString::new(s))
    }
}

pub struct PublicDeviceKey(Secret);

impl PublicDeviceKey {
    pub fn new(pdk: [u8; SECRET_LEN]) -> Self {
        Self(Secret::new(pdk))
    }

    fn private(&self, pass: &Password) -> RandomKey {
        RandomKey(self.0.xor(&pass.0))
    }

    pub fn apply_mask(&mut self, mask: &Mask) {
        self.0 = self.0.xor(&mask.0);
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

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("authentication failed")]
    Auth,
    #[error("keystore doesn't have a pdk")]
    NoPdk,
}

impl From<AuthError> for Error {
    fn from(_err: AuthError) -> Self {
        Self::Auth
    }
}

pub struct KeyStore {
    edk: AuthSecretFile,
    erk: SecretFile,
    noise: NoiseFile,
    pdk: SecretFile,
}

impl Default for KeyStore {
    fn default() -> KeyStore {
        let mut path = std::env::temp_dir();
        path.push("keystore");
        KeyStore::new(path)
    }
}

impl KeyStore {
    /// Creates a new keystore.
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Self {
            edk: AuthSecretFile::new(path.as_ref().join("encrypted_device_key")),
            erk: SecretFile::new(path.as_ref().join("encrypted_random_key")),
            noise: NoiseFile::new(path.as_ref().join("noise")),
            pdk: SecretFile::new(path.as_ref().join("public_device_key")),
        }
    }

    /// Checks if the keystore is initialized.
    pub fn is_initialized(&self) -> bool {
        self.edk.exists()
    }

    /// Initializes the keystore.
    pub fn initialize(&self, dk: &DeviceKey, pass: &Password) -> Result<(), Error> {
        let path = self.edk.parent().expect("joined a file name on init; qed");
        std::fs::create_dir_all(path)?;

        let rk = RandomKey::generate();

        let edk = dk.encrypt(&rk);
        self.edk.write(&edk.0)?;

        let pdk = rk.public(&pass);
        self.pdk.write(&pdk.0)?;

        self.unlock(pass)?;

        Ok(())
    }

    /// Unlocking the keystore makes the random key decryptable.
    pub fn unlock(&self, pass: &Password) -> Result<DeviceKey, Error> {
        let pdk = self.public()?;
        let rk = pdk.private(pass);

        self.noise.generate()?;
        let nk = self.noise.read_secret()?;

        let erk = rk.encrypt(&nk);
        self.erk.write(&erk.0)?;

        self.device_key()
    }

    /// Locks the keystore by zeroizing the noise file. This makes the encrypted
    /// random key undecryptable without a password.
    pub fn lock(&self) -> Result<(), Error> {
        self.noise.zeroize()?;
        Ok(())
    }

    fn random_key(&self) -> Result<RandomKey, Error> {
        let nk = self.noise.read_secret()?;
        let erk = EncryptedRandomKey(self.erk.read()?);
        Ok(erk.decrypt(&nk))
    }

    /// The random key is used to decrypt the device key.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub fn device_key(&self) -> Result<DeviceKey, Error> {
        let rk = self.random_key()?;
        let edk = EncryptedDeviceKey(self.edk.read()?);
        let dk = edk.decrypt(&rk)?;
        Ok(dk)
    }

    /// The random key is used to recover the password.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub fn password(&self) -> Result<Password, Error> {
        let rk = self.random_key()?;
        let pdk = self.public()?;
        Ok(rk.password(&pdk))
    }

    /// Returns the public device key.
    pub fn public(&self) -> Result<PublicDeviceKey, Error> {
        Ok(PublicDeviceKey(self.pdk.read()?))
    }

    /// Apply mask to public device key.
    pub fn apply_mask(&self, mask: &Mask) -> Result<(), Error> {
        let mut pdk = self.public()?;
        pdk.apply_mask(mask);
        self.pdk.write(&pdk.0)?;
        Ok(())
    }

    /// Change password.
    pub fn change_password(&self, password: &Password) -> Result<Mask, Error> {
        let old_password = self.password()?;
        let mut pdk = self.public()?;
        let mask = old_password.mask(password);
        pdk.apply_mask(&mask);
        self.pdk.write(&pdk.0)?;
        Ok(mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore() {
        let store = KeyStore::new("/tmp/keystore");

        // generate
        let key = DeviceKey::generate();
        let p1 = Password::from("password".to_string());
        store.initialize(&key, &p1).unwrap();

        // check reading the device key.
        let key2 = store.device_key().unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // check reading the password.
        let rp1 = store.password().unwrap();
        assert_eq!(p1.expose_secret(), rp1.expose_secret());

        // make sure key is the same after lock/unlock
        store.lock().unwrap();
        store.unlock(&p1).unwrap();
        let key2 = store.device_key().unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // change password
        let p2 = Password::from("other password".to_string());
        store.change_password(&p2).unwrap();

        // make sure key is the same after lock/unlock
        store.lock().unwrap();
        store.unlock(&p2).unwrap();
        let key2 = store.device_key().unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // make sure unlock fails if password is wrong
        let p3 = Password::from("wrong password".to_string());
        store.lock().unwrap();
        assert!(store.unlock(&p3).is_err());
        assert!(store.device_key().is_err());
    }
}
