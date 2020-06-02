use crate::crypto::{AuthSecret, Secret, AUTH_SECRET_LEN, SECRET_LEN};
use core::ops::Deref;
use rand::{thread_rng, Rng};
use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Write};
use std::path::{Path, PathBuf};
use strobe_rs::{SecParam, Strobe};

fn inner_read(path: &Path, buf: &mut [u8]) -> Result<(), Error> {
    let mut file = File::open(path)?;
    file.read_exact(buf)?;
    Ok(())
}

fn inner_write(path: &Path, buf: &[u8]) -> Result<(), Error> {
    let mut file = File::create(path)?;
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(Permissions::from_mode(0o600))?;
    }
    file.write_all(buf)?;
    file.sync_all()?;
    Ok(())
}

pub struct SecretFile(PathBuf);

impl SecretFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn read(&self) -> Result<Secret, Error> {
        let mut buf = [0; SECRET_LEN];
        inner_read(&self.0, &mut buf)?;
        Ok(Secret::new(buf))
    }

    pub fn write(&self, secret: &Secret) -> Result<(), Error> {
        inner_write(&self.0, secret.expose_secret())?;
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

    pub fn read(&self) -> Result<AuthSecret, Error> {
        let mut buf = [0; AUTH_SECRET_LEN];
        inner_read(&self.0, &mut buf)?;
        Ok(AuthSecret::new(buf))
    }

    pub fn write(&self, secret: &AuthSecret) -> Result<(), Error> {
        inner_write(&self.0, secret.expose_secret())?;
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

    pub fn generate(&self) -> Result<(), Error> {
        let mut file = File::create(&self.0)?;
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(Permissions::from_mode(0o600))?;
        }
        let mut rng = thread_rng();
        let mut buf = [0; 4096];
        for _ in 0..500 {
            rng.fill(&mut buf);
            file.write_all(&buf)?;
        }
        file.sync_all()?;
        Ok(())
    }

    pub fn read_secret(&self) -> Result<Secret, Error> {
        let mut file = File::open(&self.0)?;
        let mut s = Strobe::new(b"DiscoHash", SecParam::B128);
        let mut buf = [0; 4096];
        for i in 0..500 {
            file.read_exact(&mut buf)?;
            s.ad(&buf, i != 0);
        }
        let mut res = [0; SECRET_LEN];
        s.prf(&mut res, false);
        Ok(Secret::new(res))
    }

    pub fn zeroize(&self) -> Result<(), Error> {
        let mut file = OpenOptions::new().write(true).open(&self.0)?;
        for _ in 0..500 {
            let buf = [0; 4096];
            file.write_all(&buf)?;
        }
        file.sync_all()?;
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

    #[test]
    fn test_secret_file() {
        let secret = Secret::generate();
        let file = SecretFile::new("/tmp/secret_file".into());
        file.write(&secret).unwrap();
        let secret2 = file.read().unwrap();
        assert_eq!(secret.expose_secret(), secret2.expose_secret());
    }

    #[test]
    fn test_noise_file() {
        let noise = NoiseFile::new(PathBuf::from("/tmp/noise_file"));
        noise.generate().unwrap();
        let n1 = noise.read_secret().unwrap();
        let n2 = noise.read_secret().unwrap();
        assert_eq!(n1.expose_secret(), n2.expose_secret());
        noise.zeroize().unwrap();
        let n2 = noise.read_secret().unwrap();
        assert_ne!(n1.expose_secret(), n2.expose_secret());
    }
}
