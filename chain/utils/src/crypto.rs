use parity_scale_codec::{Decode, Encode, Input};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::marker::PhantomData;
use std::ops::Deref;
use strobe_rs::{SecParam, Strobe};
use thiserror::Error;

const X25519_LEN: usize = 32;
const TAG_LEN: usize = 16;

pub trait KeyType {
    const KEY_TYPE: u8;
}

pub struct PrivateKey<T: KeyType> {
    _marker: PhantomData<T>,
    key: x25519_dalek::StaticSecret,
}

impl<T: KeyType> PrivateKey<T> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            key: x25519_dalek::StaticSecret::new(&mut OsRng),
        }
    }
}

impl<T: KeyType> Default for PrivateKey<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: KeyType> std::fmt::Debug for PrivateKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PrivateKey")
    }
}

impl<T: KeyType> Clone for PrivateKey<T> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
            key: self.key.clone(),
        }
    }
}

impl<T: KeyType> Deref for PrivateKey<T> {
    type Target = x25519_dalek::StaticSecret;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<T: KeyType> From<[u8; X25519_LEN]> for PrivateKey<T> {
    fn from(bytes: [u8; X25519_LEN]) -> Self {
        Self {
            _marker: PhantomData,
            key: x25519_dalek::StaticSecret::from(bytes),
        }
    }
}

impl<T: KeyType> PartialEq for PrivateKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key.to_bytes() == other.key.to_bytes()
    }
}

impl<T: KeyType> Eq for PrivateKey<T> {}

impl<T: KeyType> Encode for PrivateKey<T> {
    fn size_hint(&self) -> usize {
        X25519_LEN
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        let bytes = self.key.to_bytes();
        f(&bytes)
    }
}

impl<T: KeyType> Decode for PrivateKey<T> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        let mut bytes = [0u8; X25519_LEN];
        value.read(&mut bytes)?;
        Ok(Self::from(bytes))
    }
}

pub struct PublicKey<T: KeyType> {
    _marker: PhantomData<T>,
    key: x25519_dalek::PublicKey,
}

impl<T: KeyType> std::fmt::Debug for PublicKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "PublicKey")
    }
}

impl<T: KeyType> Clone for PublicKey<T> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
            key: self.key,
        }
    }
}

impl<T: KeyType> Deref for PublicKey<T> {
    type Target = x25519_dalek::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<T: KeyType> From<[u8; X25519_LEN]> for PublicKey<T> {
    fn from(bytes: [u8; X25519_LEN]) -> Self {
        Self {
            _marker: PhantomData,
            key: x25519_dalek::PublicKey::from(bytes),
        }
    }
}

impl<'a, T: KeyType> From<&'a PrivateKey<T>> for PublicKey<T> {
    fn from(key: &'a PrivateKey<T>) -> Self {
        Self {
            _marker: PhantomData,
            key: x25519_dalek::PublicKey::from(&key.key),
        }
    }
}

impl<T: KeyType> PartialEq for PublicKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_bytes() == other.key.as_bytes()
    }
}

impl<T: KeyType> Eq for PublicKey<T> {}

impl<T: KeyType> Encode for PublicKey<T> {
    fn size_hint(&self) -> usize {
        X25519_LEN
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(self.key.as_bytes())
    }
}

impl<T: KeyType> Decode for PublicKey<T> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        let mut bytes = [0u8; X25519_LEN];
        value.read(&mut bytes)?;
        Ok(Self::from(bytes))
    }
}

#[derive(Default)]
pub struct KeyChain {
    keys: HashMap<u8, [u8; X25519_LEN]>,
    public: HashMap<u8, HashSet<[u8; X25519_LEN]>>,
}

impl KeyChain {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert<T: KeyType>(&mut self, key: PrivateKey<T>) {
        let public = PublicKey::from(&key);
        self.keys.insert(T::KEY_TYPE, key.to_bytes());
        let group = self.public.entry(T::KEY_TYPE).or_default();
        group.insert(*public.as_bytes());
    }

    pub fn get<T: KeyType>(&self) -> Option<PrivateKey<T>> {
        self.keys
            .get(&T::KEY_TYPE)
            .map(|bytes| PrivateKey::from(*bytes))
    }

    pub fn insert_public<T: KeyType>(&mut self, public: PublicKey<T>) {
        let group = self.public.entry(T::KEY_TYPE).or_default();
        group.insert(*public.as_bytes());
    }

    pub fn get_public<T: KeyType>(&self) -> Vec<PublicKey<T>> {
        if let Some(set) = self.public.get(&T::KEY_TYPE) {
            set.iter().map(|bytes| PublicKey::from(*bytes)).collect()
        } else {
            Default::default()
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct SecretBox<K, T> {
    _marker: PhantomData<(K, T)>,
    secret: Vec<u8>,
}

impl<K, T> Clone for SecretBox<K, T> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
            secret: self.secret.clone(),
        }
    }
}

impl<K, T> std::fmt::Debug for SecretBox<K, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SecretBox")
    }
}

impl<K, T> Encode for SecretBox<K, T> {
    fn size_hint(&self) -> usize {
        self.secret.len()
    }

    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.secret.using_encoded(f)
    }
}

impl<K, T> Decode for SecretBox<K, T> {
    fn decode<R: Input>(value: &mut R) -> Result<Self, parity_scale_codec::Error> {
        Ok(Self {
            _marker: PhantomData,
            secret: Decode::decode(value)?,
        })
    }
}

impl<K: KeyType, T: Decode + Encode> SecretBox<K, T> {
    pub fn encrypt(key_chain: &KeyChain, payload: &T) -> Result<Self, SecretBoxError> {
        let recipients = key_chain.get_public::<K>();
        Self::encrypt_for(payload, &recipients)
    }

    pub fn encrypt_for(payload: &T, recipients: &[PublicKey<K>]) -> Result<Self, SecretBoxError> {
        if recipients.is_empty() {
            return Err(SecretBoxError::NoRecipients);
        }
        if recipients.len() as u8 as usize != recipients.len() {
            return Err(SecretBoxError::TooManyRecipients);
        }
        // Create a buffer.
        let capacity =
            recipients.len() * (X25519_LEN + TAG_LEN) + X25519_LEN + 1 + payload.size_hint();
        let mut buf = Vec::with_capacity(capacity);

        // Create a payload key.
        let mut payload_key = [0u8; 32];
        OsRng.fill_bytes(&mut payload_key);

        // Write the number of recipients to buffer.
        buf.extend_from_slice(&[recipients.len() as u8]);

        // Compute an ephermal public key and write to buffer.
        let secret = x25519_dalek::StaticSecret::new(&mut OsRng);
        let ephemeral = x25519_dalek::PublicKey::from(&secret);
        buf.extend_from_slice(ephemeral.as_bytes());

        // For each recipient encrypt the payload key with the
        // diffie_hellman of the ephermal key and the recipients
        // public key and write to buffer.
        for public in recipients {
            let shared_secret = secret.clone().diffie_hellman(&public);
            let mut payload_key = payload_key;

            let mut s = Strobe::new(b"secret-box-key", SecParam::B128);
            s.ad(shared_secret.as_bytes(), false);
            s.send_enc(&mut payload_key, false);
            buf.extend_from_slice(&payload_key);

            // Add tag to check if we can unlock the payload key.
            let mut mac = [0u8; TAG_LEN];
            s.send_mac(&mut mac, false);
            buf.extend_from_slice(&mac);
        }

        let mut s = Strobe::new(b"secret-box", SecParam::B128);
        // Absorb shared secret.
        s.ad(&payload_key, false);

        let payload_start = buf.len();
        payload.encode_to(&mut buf);
        s.send_enc(&mut buf[payload_start..], false);
        // don't need a tag as this will go into a content addressed block.

        Ok(Self {
            _marker: PhantomData,
            secret: buf,
        })
    }

    pub fn decrypt(&self, key_chain: &KeyChain) -> Result<T, SecretBoxError> {
        let stream = &mut &self.secret[..];

        let mut len = [0];
        stream.read_exact(&mut len)?;
        let len = len[0] as usize;
        if len == 0 {
            return Err(SecretBoxError::NoRecipients);
        }

        let mut public = [0u8; X25519_LEN];
        stream.read_exact(&mut public)?;
        let ephemeral = x25519_dalek::PublicKey::from(public);

        let secret = key_chain
            .get::<K>()
            .ok_or(SecretBoxError::NoDecryptionKey)?;
        let shared_secret = secret.diffie_hellman(&ephemeral);
        let mut payload_key = None;
        for _ in 0..len {
            let mut tmp_payload_key = [0u8; X25519_LEN];
            stream.read_exact(&mut tmp_payload_key)?;
            let mut mac = [0u8; TAG_LEN];
            stream.read_exact(&mut mac)?;

            if payload_key.is_some() {
                continue;
            }

            let mut s = Strobe::new(b"secret-box-key", SecParam::B128);
            s.ad(shared_secret.as_bytes(), false);
            s.recv_enc(&mut tmp_payload_key, false);
            if let Ok(()) = s.recv_mac(&mut mac, false) {
                payload_key = Some(tmp_payload_key);
            }
        }
        let payload_key = payload_key.ok_or(SecretBoxError::NoDecryptionKey)?;

        let payload_start = len * (X25519_LEN + TAG_LEN) + X25519_LEN + 1;
        let payload_slice = &self.secret[payload_start..];
        let mut payload = Vec::with_capacity(payload_slice.len());
        payload.extend_from_slice(payload_slice);

        let mut s = Strobe::new(b"secret-box", SecParam::B128);
        s.ad(&payload_key, false);
        s.recv_enc(&mut payload, false);

        Ok(Decode::decode(&mut &payload[..])?)
    }
}

#[derive(Debug, Error)]
pub enum SecretBoxError {
    #[error("no recipients")]
    NoRecipients,
    #[error("too many recipients")]
    TooManyRecipients,
    #[error("no decryption key")]
    NoDecryptionKey,
    #[error(transparent)]
    Scale(#[from] parity_scale_codec::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct Device;
    impl KeyType for Device {
        const KEY_TYPE: u8 = 0;
    }

    #[derive(Debug, Eq, PartialEq)]
    struct AllDevices;
    impl KeyType for AllDevices {
        const KEY_TYPE: u8 = 1;
    }

    #[test]
    fn test_private_key() {
        let key = PrivateKey::<Device>::new();
        let key2 = PrivateKey::<Device>::from(key.to_bytes());
        assert_eq!(key, key);
        assert_eq!(key, key2);
        let key2 = PrivateKey::<Device>::decode(&mut &key.encode()[..]).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_secret_box() {
        let mut alice = KeyChain::new();
        let mut bob = KeyChain::new();

        let dk = PrivateKey::new();
        let dk_pub = PublicKey::from(&dk);
        alice.insert::<AllDevices>(dk);
        bob.insert_public::<AllDevices>(dk_pub);

        let dk = PrivateKey::new();
        let dk_pub = PublicKey::from(&dk);
        bob.insert::<AllDevices>(dk);
        alice.insert_public::<AllDevices>(dk_pub);

        let value = "hello world".to_string();

        let secret = SecretBox::<AllDevices, String>::encrypt(&alice, &value).unwrap();
        let value2 = secret.decrypt(&alice).unwrap();
        assert_eq!(value, value2);
        let value2 = secret.decrypt(&bob).unwrap();
        assert_eq!(value, value2);

        let secret2: SecretBox<AllDevices, String> =
            Decode::decode(&mut &secret.encode()[..]).unwrap();
        assert_eq!(secret, secret2);
    }
}
