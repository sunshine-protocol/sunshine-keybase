use crate::error::Error;
use crate::generation::Generation;
use crate::types::*;
use async_std::os::unix::fs::symlink;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;
use std::ffi::OsString;

pub struct Keystore {
    path: PathBuf,
}

impl Keystore {
    /// Creates a keystore.
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Creates a new generation and atomically changes the symlink.
    async fn create_gen(&self, dk: &DeviceKey, pass: &Password, gen: u16) -> Result<(), Error> {
        async_std::fs::create_dir_all(&self.path).await?;
        let gen = Generation::new(&self.path, gen);
        gen.initialize(dk, pass).await?;
        let gen_new_link = self.path.join("gen_new");
        symlink(gen.path(), &gen_new_link).await?;
        async_std::fs::rename(&gen_new_link, self.path.join("gen")).await?;
        self.garbage_collect_gens().await.ok();
        Ok(())
    }

    /// Returns the generation.
    async fn read_gen(&self) -> Result<Generation, Error> {
        let gen_link = self.path.join("gen");
        if gen_link.exists().await {
            let gen_dir = async_std::fs::read_link(gen_link).await?;
            let gen: u16 = gen_dir
                .file_name()
                .ok_or(Error::Corrupted)?
                .to_str()
                .ok_or(Error::Corrupted)?
                .parse()
                .map_err(|_| Error::Corrupted)?;
            let gen_path = gen_dir.parent().ok_or(Error::Corrupted)?;
            if gen_path != self.path {
                return Err(Error::Corrupted);
            }
            Ok(Generation::new(&self.path, gen))
        } else {
            Ok(Generation::new(&self.path, 0))
        }
    }

    /// Removes old or failed generations.
    ///
    /// NOTE: since the keystore does not use any file locks this can lead to a race. It is
    /// assumed that a single application uses the keystore and that there is only one application
    /// running.
    async fn garbage_collect_gens(&self) -> Result<(), Error> {
        let gen = self.read_gen().await?;

        let mut dir = async_std::fs::read_dir(&self.path).await?;
        let gen_str = OsString::from(gen.gen().to_string());
        while let Some(entry) = dir.next().await {
            let file_name = entry?.file_name();
            if file_name == "gen" {
                continue;
            }
            if &file_name != gen_str.as_os_str() {
                async_std::fs::remove_dir_all(self.path.join(&file_name)).await?;
            }
        }

        Ok(())
    }

    /// Sets the device key.
    pub async fn set_device_key(
        &self,
        device_key: &DeviceKey,
        password: &Password,
        force: bool,
    ) -> Result<(), Error> {
        if !force && self.read_gen().await?.is_initialized().await {
            return Err(Error::Initialized);
        }
        self.create_gen(device_key, password, 0).await?;
        Ok(())
    }

    /// Provisions the keystore.
    pub async fn provision_device_key(
        &self,
        password: &Password,
        gen: u16,
    ) -> Result<DeviceKey, Error> {
        let device_key = DeviceKey::generate().await;
        self.create_gen(&device_key, password, gen).await?;
        Ok(device_key)
    }

    /// Locks the keystore.
    pub async fn lock(&self) -> Result<(), Error> {
        self.read_gen().await?.lock().await
    }

    /// Unlocks the keystore.
    pub async fn unlock(&self, password: &Password) -> Result<DeviceKey, Error> {
        self.read_gen().await?.unlock(password).await
    }

    /// Gets the device key.
    pub async fn device_key(&self) -> Result<DeviceKey, Error> {
        self.read_gen().await?.device_key().await
    }

    /// Gets the password and gen to send to a device during provisioning.
    pub async fn password(&self) -> Result<(Password, u16), Error> {
        let gen = self.read_gen().await?;
        Ok((gen.password().await?, gen.gen()))
    }

    /// Get current password gen.
    pub async fn gen(&self) -> Result<u16, Error> {
        Ok(self.read_gen().await?.gen())
    }

    /// Change password.
    pub async fn change_password_mask(&self, password: &Password) -> Result<(Mask, u16), Error> {
        let gen = self.read_gen().await?;
        let mask = gen.change_password_mask(password).await?;
        Ok((mask, gen.gen() + 1))
    }

    /// Creates a new generation from a password mask.
    pub async fn apply_mask(&self, mask: &Mask, next_gen: u16) -> Result<(), Error> {
        let gen = self.read_gen().await?;
        if gen.gen() + mask.len() != next_gen {
            return Err(Error::GenMissmatch);
        }
        let dk = gen.device_key().await?;
        let pass = gen.password().await?.apply_mask(mask);
        self.create_gen(&dk, &pass, next_gen).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceKey, Password};
    use tempdir::TempDir;

    #[async_std::test]
    async fn test_keystore() {
        let tmp = TempDir::new("keystore-").unwrap();
        let store = Keystore::new(tmp.path());

        // generate
        let key = DeviceKey::generate().await;
        let p1 = Password::from("password".to_string());
        store.create_gen(&key, &p1, 0).await.unwrap();

        // check reading the device key.
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // check reading the password.
        let (rp1, gen) = store.password().await.unwrap();
        assert_eq!(p1.expose_secret(), rp1.expose_secret());
        assert_eq!(gen, 0);

        // make sure key is the same after lock/unlock
        store.lock().await.unwrap();
        store.unlock(&p1).await.unwrap();
        let key2 = store.device_key().await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // change password
        let p2 = Password::from("other password".to_string());
        let (mask, gen) = store.change_password_mask(&p2).await.unwrap();
        store.apply_mask(&mask, gen).await.unwrap();

        // make sure key is the same after lock/unlock
        store.lock().await.unwrap();

        let store = Keystore::new(tmp.path());
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
