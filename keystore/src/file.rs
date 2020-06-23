use crate::crypto::{AuthSecret, Secret, AUTH_SECRET_LEN, SECRET_LEN};
use async_std::fs::{File, OpenOptions};
use async_std::io::Error;
use async_std::path::{Path, PathBuf};
use async_std::prelude::*;
use core::ops::Deref;
use rand::{thread_rng, Rng};
use strobe_rs::{SecParam, Strobe};

async fn inner_read(path: &Path, buf: &mut [u8]) -> Result<(), Error> {
    let mut file = File::open(path).await?;
    file.read_exact(buf).await?;
    Ok(())
}

async fn inner_write(path: &Path, buf: &[u8]) -> Result<(), Error> {
    let mut file = File::create(path).await?;
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(Permissions::from_mode(0o600)).await?;
    }
    file.write_all(buf).await?;
    file.sync_all().await?;
    Ok(())
}

pub struct SecretFile(PathBuf);

impl SecretFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub async fn read(&self) -> Result<Secret, Error> {
        let mut buf = [0; SECRET_LEN];
        inner_read(&self.0, &mut buf).await?;
        Ok(Secret::new(buf))
    }

    pub async fn write(&self, secret: &Secret) -> Result<(), Error> {
        inner_write(&self.0, secret.expose_secret()).await?;
        Ok(())
    }
}

impl Deref for SecretFile {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct AuthSecretFile(PathBuf);

impl AuthSecretFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub async fn read(&self) -> Result<AuthSecret, Error> {
        let mut buf = [0; AUTH_SECRET_LEN];
        inner_read(&self.0, &mut buf).await?;
        Ok(AuthSecret::new(buf))
    }

    pub async fn write(&self, secret: &AuthSecret) -> Result<(), Error> {
        inner_write(&self.0, secret.expose_secret()).await?;
        Ok(())
    }
}

impl Deref for AuthSecretFile {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct NoiseFile(PathBuf);

impl NoiseFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub async fn generate(&self) -> Result<(), Error> {
        let mut file = File::create(&self.0).await?;
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(Permissions::from_mode(0o600)).await?;
        }
        let mut rng = thread_rng();
        let mut buf = [0; 4096];
        for _ in 0..500 {
            rng.fill(&mut buf);
            file.write_all(&buf).await?;
        }
        file.sync_all().await?;
        Ok(())
    }

    pub async fn read_secret(&self) -> Result<Secret, Error> {
        let mut file = File::open(&self.0).await?;
        let mut s = Strobe::new(b"DiscoHash", SecParam::B128);
        let mut buf = [0; 4096];
        for i in 0..500 {
            file.read_exact(&mut buf).await?;
            s.ad(&buf, i != 0);
        }
        let mut res = [0; SECRET_LEN];
        s.prf(&mut res, false);
        Ok(Secret::new(res))
    }

    pub async fn zeroize(&self) -> Result<(), Error> {
        let mut file = OpenOptions::new().write(true).open(&self.0).await?;
        for _ in 0..500 {
            let buf = [0; 4096];
            file.write_all(&buf).await?;
        }
        file.sync_all().await?;
        Ok(())
    }
}

impl Deref for NoiseFile {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_secret_file() {
        let secret = Secret::generate();
        let file = SecretFile::new("/tmp/secret_file".into());
        file.write(&secret).await.unwrap();
        let secret2 = file.read().await.unwrap();
        assert_eq!(secret.expose_secret(), secret2.expose_secret());
    }

    #[async_std::test]
    async fn test_noise_file() {
        let noise = NoiseFile::new(PathBuf::from("/tmp/noise_file"));
        noise.generate().await.unwrap();
        let n1 = noise.read_secret().await.unwrap();
        let n2 = noise.read_secret().await.unwrap();
        assert_eq!(n1.expose_secret(), n2.expose_secret());
        noise.zeroize().await.unwrap();
        let n2 = noise.read_secret().await.unwrap();
        assert_ne!(n1.expose_secret(), n2.expose_secret());
    }
}
