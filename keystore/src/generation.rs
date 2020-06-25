use crate::error::Error;
use crate::file::{AuthSecretFile, NoiseFile, SecretFile};
use crate::types::{DeviceKey, EncryptedDeviceKey, EncryptedRandomKey, Password, RandomKey, PublicDeviceKey, Mask};
use async_std::path::{Path, PathBuf};

pub struct Generation {
    gen: u32,
    path: PathBuf,
    edk: AuthSecretFile,
    erk: SecretFile,
    noise: NoiseFile,
    pdk: SecretFile,
}

impl Generation {
    /// Creates a generation.
    pub fn new(path: &Path, gen: u32) -> Self {
        let path = path.join(gen.to_string());
        Self {
            gen,
            edk: AuthSecretFile::new(path.join("encrypted_device_key")),
            erk: SecretFile::new(path.join("encrypted_random_key")),
            noise: NoiseFile::new(path.join("noise")),
            pdk: SecretFile::new(path.join("public_device_key")),
            path,
        }
    }

    /// Returns the generation number.
    pub fn gen(&self) -> u32 {
        self.gen
    }

    /// Checks if the keystore is initialized.
    pub async fn is_initialized(&self) -> bool {
        self.edk.exists().await
    }

    /// Initializes the keystore.
    pub async fn initialize(&self, dk: &DeviceKey, pass: &Password) -> Result<(), Error> {
        let path = self.edk.parent().expect("joined a file name on init; qed");
        async_std::fs::create_dir_all(path).await?;

        let rk = RandomKey::generate().await;

        let edk = dk.encrypt(&rk).await;
        self.edk.write(&edk.0).await?;

        let pdk = rk.public(&pass);
        self.pdk.write(&pdk.0).await?;

        self.unlock(pass).await?;

        Ok(())
    }

    /// Unlocking the keystore makes the random key decryptable.
    pub async fn unlock(&self, pass: &Password) -> Result<DeviceKey, Error> {
        let pdk = self.public().await?;
        let rk = pdk.private(pass);

        self.noise.generate().await?;
        let nk = self.noise.read_secret().await?;

        let erk = rk.encrypt(&nk);
        self.erk.write(&erk.0).await?;

        self.device_key().await
    }

    /// Locks the keystore by zeroizing the noise file. This makes the encrypted
    /// random key undecryptable without a password.
    pub async fn lock(&self) -> Result<(), Error> {
        self.noise.zeroize().await?;
        Ok(())
    }

    async fn random_key(&self) -> Result<RandomKey, Error> {
        let nk = self.noise.read_secret().await?;
        let erk = EncryptedRandomKey(self.erk.read().await?);
        Ok(erk.decrypt(&nk))
    }

    /// The random key is used to decrypt the device key.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub async fn device_key(&self) -> Result<DeviceKey, Error> {
        let rk = self.random_key().await?;
        let edk = EncryptedDeviceKey(self.edk.read().await?);
        let dk = edk.decrypt(&rk)?;
        Ok(dk)
    }

    /// The random key is used to recover the password.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub async fn password(&self) -> Result<Password, Error> {
        let rk = self.random_key().await?;
        let pdk = self.public().await?;
        Ok(rk.password(&pdk))
    }

    /// Returns the public device key.
    pub async fn public(&self) -> Result<PublicDeviceKey, Error> {
        Ok(PublicDeviceKey(self.pdk.read().await?))
    }

    /// Change password.
    pub async fn change_password_mask(&self, password: &Password) -> Result<Mask, Error> {
        let old_password = self.password().await?;
        let mask = old_password.mask(password);
        Ok(mask)
    }

    /// Removes a generation.
    pub async fn remove(self) -> Result<(), Error> {
        Ok(async_std::fs::remove_dir_all(&self.path).await?)
    }
}
