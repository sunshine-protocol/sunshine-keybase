use async_std::task;
use rand::{thread_rng, AsByteSliceMut, Rng};
use secrecy::{ExposeSecret, SecretString};
use strobe_rs::{AuthError, SecParam, Strobe};
use zeroize::Zeroize;

pub const SECRET_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const AUTH_SECRET_LEN: usize = TAG_LEN + NONCE_LEN + SECRET_LEN;

#[derive(Clone)]
pub struct Secret([u8; SECRET_LEN]);

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "*****")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl Secret {
    pub fn new(secret: [u8; SECRET_LEN]) -> Self {
        Self(secret)
    }

    pub fn expose_secret(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    pub fn xor(&self, other: &Self) -> Self {
        let mut res = [0; SECRET_LEN];
        let a = self.expose_secret();
        let b = other.expose_secret();
        for i in 0..SECRET_LEN {
            res[i] = a[i] ^ b[i]
        }
        Self::new(res)
    }

    pub async fn generate() -> Self {
        Self::new(random().await)
    }

    pub fn kdf(input: &SecretString) -> Self {
        let mut s = Strobe::new(b"DiscoKDF", SecParam::B128);
        s.ad(input.expose_secret().as_bytes(), false);
        let mut res = [0; SECRET_LEN];
        s.prf(&mut res, false);
        Self::new(res)
    }

    pub fn encrypt(&self, key: &Self) -> Self {
        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        let mut res = [0; SECRET_LEN];
        res.copy_from_slice(self.expose_secret());
        s.ad(key.expose_secret(), false);
        s.send_enc(&mut res, false);
        Self::new(res)
    }

    pub async fn auth_encrypt(&self, key: &Self) -> AuthSecret {
        let mut auth = [0; AUTH_SECRET_LEN];
        let (ct, rest) = auth.split_at_mut(SECRET_LEN);
        let (nonce, tag) = rest.split_at_mut(NONCE_LEN);

        ct.copy_from_slice(self.expose_secret());
        let nonce_buf: [u8; NONCE_LEN] = random().await;
        nonce.copy_from_slice(&nonce_buf);

        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        s.ad(key.expose_secret(), false);
        s.ad(nonce, false);
        s.send_enc(ct, false);
        s.send_mac(tag, false);
        AuthSecret::new(auth)
    }

    pub fn decrypt(&self, key: &Self) -> Self {
        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        let mut res = [0; SECRET_LEN];
        res.copy_from_slice(self.expose_secret());
        s.ad(key.expose_secret(), false);
        s.recv_enc(&mut res, false);
        Self::new(res)
    }
}

#[derive(Clone)]
pub struct AuthSecret([u8; AUTH_SECRET_LEN]);

impl core::fmt::Debug for AuthSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "*****")
    }
}

impl Drop for AuthSecret {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl AuthSecret {
    pub fn new(secret: [u8; AUTH_SECRET_LEN]) -> Self {
        Self(secret)
    }

    pub fn expose_secret(&self) -> &[u8; AUTH_SECRET_LEN] {
        &self.0
    }

    pub fn auth_decrypt(&self, key: &Secret) -> Result<Secret, AuthError> {
        let (ct, rest) = self.expose_secret().split_at(SECRET_LEN);
        let (nonce, mac) = rest.split_at(NONCE_LEN);

        let mut pt = [0; SECRET_LEN];
        pt.copy_from_slice(ct);
        let mut tag = [0; TAG_LEN];
        tag.copy_from_slice(mac);

        let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);
        s.ad(key.expose_secret(), false);
        s.ad(nonce, false);
        s.recv_enc(&mut pt, false);
        s.recv_mac(&mut tag, false)?;
        Ok(Secret::new(pt))
    }
}

pub async fn random<T: Default + AsByteSliceMut + Send + 'static>() -> T {
    task::spawn_blocking(|| {
        let mut buf = T::default();
        thread_rng().fill(&mut buf);
        buf
    }).await
}
