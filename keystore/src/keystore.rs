use crate::error::Error;
use crate::generation::Generation;
use crate::types::Mask;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;

pub struct KeyStore {
    path: PathBuf,
    gen: Generation,
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
        Ok(Self { path, gen })
    }

    /// Creates a new generation from a password mask.
    pub async fn apply_mask(&mut self, mask: &Mask, gen: u32) -> Result<(), Error> {
        if self.gen() + 1 != gen {
            return Err(Error::GenMissmatch);
        }
        let dk = self.device_key().await?;
        let pass = self.password().await?.apply_mask(mask);
        let gen = Generation::new(&self.path, gen);
        gen.initialize(&dk, &pass).await?;
        let gen = std::mem::replace(&mut self.gen, gen);
        gen.remove().await?;
        Ok(())
    }
}

impl core::ops::Deref for KeyStore {
    type Target = Generation;

    fn deref(&self) -> &Self::Target {
        &self.gen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceKey, Password};

    #[async_std::test]
    async fn test_keystore() {
        let mut store = KeyStore::open("/tmp/keystore").await.unwrap();

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
}
