use crate::error::Error;
use crate::generation::Generation;
use crate::types::*;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;
use async_std::sync::RwLock;

pub struct KeyStore {
    path: PathBuf,
    gen: RwLock<Generation>,
}

impl KeyStore {
    /// Opens a keystore.
    pub async fn open<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        async_std::fs::create_dir_all(&path).await?;
        let mut gens = vec![];
        let mut dir = async_std::fs::read_dir(&path).await?;
        while let Some(entry) = dir.next().await {
            let gen = entry?
                .file_name()
                .to_str()
                .ok_or(Error::Corrupted)?
                .parse()
                .map_err(|_| Error::Corrupted)?;
            gens.push(Generation::new(&path, gen));
        }
        let gen = match gens.len() {
            0 => Generation::new(&path, 0),
            1 => gens.pop().unwrap(),
            _ => {
                let mut ugen: Option<Generation> = None;
                let mut rgens = vec![];
                for gen in gens {
                    if gen.device_key().await.is_ok() {
                        if let Some(ugen2) = ugen {
                            if ugen2.gen() < gen.gen() {
                                rgens.push(ugen2);
                                ugen = Some(gen);
                            } else {
                                rgens.push(gen);
                                ugen = Some(ugen2);
                            }
                        } else {
                            ugen = Some(gen);
                        }
                    } else {
                        rgens.push(gen);
                    }
                }
                if let Some(ugen) = ugen {
                    for rgen in rgens {
                        rgen.remove().await?;
                    }
                    ugen
                } else {
                    return Err(Error::Corrupted);
                }
            }
        };
        Ok(Self {
            path,
            gen: RwLock::new(gen),
        })
    }

    /// Creates a new generation from a password mask.
    pub async fn apply_mask(&self, mask: &Mask, next_gen: u16) -> Result<(), Error> {
        let mut gen = self.gen.write().await;
        if gen.gen() + 1 != next_gen {
            return Err(Error::GenMissmatch);
        }
        let dk = gen.device_key().await?;
        let pass = gen.password().await?.apply_mask(mask);
        let next_gen = Generation::new(&self.path, next_gen);
        next_gen.initialize(&dk, &pass, true).await?;
        let old_gen = std::mem::replace(&mut *gen, next_gen);
        old_gen.remove().await?;
        Ok(())
    }

    /// Returns the generation number.
    pub async fn gen(&self) -> u16 {
        self.gen.read().await.gen()
    }

    /// Checks if the keystore is initialized.
    pub async fn is_initialized(&self) -> bool {
        self.gen.read().await.is_initialized().await
    }

    /// Initializes the keystore.
    pub async fn initialize(
        &self,
        dk: &DeviceKey,
        pass: &Password,
        force: bool,
    ) -> Result<(), Error> {
        self.gen.write().await.initialize(dk, pass, force).await
    }

    /// Unlocking the keystore makes the random key decryptable.
    pub async fn unlock(&self, pass: &Password) -> Result<DeviceKey, Error> {
        self.gen.write().await.unlock(pass).await
    }

    /// Locks the keystore by zeroizing the noise file. This makes the encrypted
    /// random key undecryptable without a password.
    pub async fn lock(&self) -> Result<(), Error> {
        self.gen.write().await.lock().await
    }

    /// The random key is used to decrypt the device key.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub async fn device_key(&self) -> Result<DeviceKey, Error> {
        self.gen.read().await.device_key().await
    }

    /// The random key is used to recover the password.
    ///
    /// NOTE: Only works if the keystore was unlocked.
    pub async fn password(&self) -> Result<Password, Error> {
        self.gen.read().await.password().await
    }

    /// Returns the public device key.
    pub async fn public(&self) -> Result<PublicDeviceKey, Error> {
        self.gen.read().await.public().await
    }

    /// Change password.
    pub async fn change_password_mask(&self, password: &Password) -> Result<Mask, Error> {
        self.gen.read().await.change_password_mask(password).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceKey, Password};
    use fail::FailScenario;
    use tempdir::TempDir;

    #[async_std::test]
    async fn test_keystore() {
        fail::cfg("edk-write-fail", "off").unwrap();
        fail::cfg("gen-rm-fail", "off").unwrap();
        let tmp = TempDir::new("keystore-").unwrap();
        let mut store = KeyStore::open(tmp.path()).await.unwrap();

        // generate
        let key = DeviceKey::generate().await;
        let p1 = Password::from("password".to_string());
        store.initialize(&key, &p1).await.unwrap();

        // check reading the device key.
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // check reading the password.
        let rp1 = store.password().await.unwrap();
        assert_eq!(p1.expose_secret(), rp1.expose_secret());

        // make sure key is the same after lock/unlock
        store.lock().await.unwrap();
        store.unlock(&p1).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // change password
        let p2 = Password::from("other password".to_string());
        let mask = store.change_password_mask(&p2).await.unwrap();
        store.apply_mask(&mask, store.gen() + 1).await.unwrap();

        // make sure key is the same after lock/unlock
        store.lock().await.unwrap();

        let store = KeyStore::open(tmp.path()).await.unwrap();
        store.unlock(&p2).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // make sure unlock fails if password is wrong
        let p3 = Password::from("wrong password".to_string());
        store.lock().await.unwrap();
        match store.unlock(&p3).await {
            Err(Error::Locked) => {}
            Ok(_) => panic!("should fail"),
            r => {
                r.unwrap();
            }
        }
        match store.device_key().await {
            Err(Error::Locked) => {}
            Ok(_) => panic!("should fail"),
            r => {
                r.unwrap();
            }
        }
    }

    #[async_std::test]
    #[ignore] // Fail tests can not be run in parallel
    async fn test_edk_write_fail_unlock() {
        fail::cfg("edk-write-fail", "off").unwrap();
        fail::cfg("gen-rm-fail", "off").unwrap();
        let tmp = TempDir::new("keystore-").unwrap();
        let mut store = KeyStore::open(tmp.path()).await.unwrap();
        let key = DeviceKey::generate().await;
        let pass = Password::generate().await;
        store.initialize(&key, &pass).await.unwrap();

        let scenario = FailScenario::setup();

        fail::cfg("edk-write-fail", "return(())").unwrap();
        let npass = Password::generate().await;
        let mask = store.change_password_mask(&npass).await.unwrap();
        store.apply_mask(&mask, store.gen() + 1).await.ok();
        store.lock().await.unwrap();
        store.unlock(&pass).await.unwrap();

        scenario.teardown();
    }

    #[async_std::test]
    #[ignore] // Fail tests can not be run in parallel
    async fn test_edk_write_fail_recovery() {
        fail::cfg("edk-write-fail", "off").unwrap();
        fail::cfg("gen-rm-fail", "off").unwrap();
        let tmp = TempDir::new("keystore-").unwrap();
        let mut store = KeyStore::open(tmp.path()).await.unwrap();
        let key = DeviceKey::generate().await;
        let pass = Password::generate().await;
        store.initialize(&key, &pass).await.unwrap();

        let scenario = FailScenario::setup();

        fail::cfg("edk-write-fail", "return(())").unwrap();
        let npass = Password::generate().await;
        let mask = store.change_password_mask(&npass).await.unwrap();
        store.apply_mask(&mask, store.gen() + 1).await.ok();

        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        let store = KeyStore::open(tmp.path()).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        scenario.teardown();
    }

    #[async_std::test]
    #[ignore] // Fail tests can not be run in parallel
    async fn test_gen_remove_fail_recovery() {
        fail::cfg("edk-write-fail", "off").unwrap();
        fail::cfg("gen-rm-fail", "off").unwrap();
        let tmp = TempDir::new("keystore-").unwrap();
        let mut store = KeyStore::open(tmp.path()).await.unwrap();
        let key = DeviceKey::generate().await;
        let pass = Password::generate().await;
        store.initialize(&key, &pass).await.unwrap();

        let scenario = FailScenario::setup();

        fail::cfg("gen-rm-fail", "return(())").unwrap();
        let npass = Password::generate().await;
        let mask = store.change_password_mask(&npass).await.unwrap();
        store.apply_mask(&mask, store.gen() + 1).await.ok();

        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        let store = KeyStore::open(tmp.path()).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        scenario.teardown();
    }
}
