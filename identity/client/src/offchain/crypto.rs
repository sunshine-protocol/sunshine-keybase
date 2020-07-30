pub struct EncryptedBox<K: GetKey, V: Encode + Decode>(V);

impl EncryptedBox

/// Crypto error.
#[derive(Debug, Error)]
pub enum Error {
    /// Key needs to be at least 128 bits (16 bytes).
    #[error("key needs to be at least 128 bits (16 bytes).")]
    KeyTooShort,
    /// Cipher text needs to be larger than nonce + tag.
    #[error("cipher text needs to be larger than nonce + tag.")]
    CipherTooShort,
    /// Mac integrity check failed.
    #[error("mac integrity check failed.")]
    Integrity,
    /// Failed to decode data.
    #[error("failed to decode data: {0}.")]
    Codec(Box<dyn std::error::Error + Send>),
}

/// Encrypts and MACs a plaintext message with a key of any size greater than 128 bits (16 bytes).
pub fn encrypt(key: &Key, codec: Codec, data: &[u8]) -> Result<Box<[u8]>, Error> {
    if key.len() < 16 {
        return Err(Error::KeyTooShort);
    }

    let mut buf = unsigned_varint::encode::u64_buffer();
    let codec = unsigned_varint::encode::u64(codec.into(), &mut buf);

    let mut s = Strobe::new(b"ipld-block-builder", SecParam::B128);

    // Absorb the key
    s.ad(key.deref(), false);

    // Create buffer.
    let mut buf = Vec::with_capacity(NONCE_LEN + codec.len() + data.len() + TAG_LEN);
    buf.resize(buf.capacity(), 0);
    //unsafe { buf.set_len(buf.capacity()) };

    // Generate 192-bit nonce and absorb it
    let nonce = &mut buf[..NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(nonce);
    s.ad(nonce, false);

    // Copy data to buffer and encrypt in place.
    let buf_len = buf.len();
    let ct = &mut buf[NONCE_LEN..(buf_len - TAG_LEN)];
    ct[..codec.len()].copy_from_slice(codec);
    ct[codec.len()..].copy_from_slice(data);
    s.send_enc(ct, false);

    // Add tag to verify message integrity.
    let mac = &mut buf[(buf_len - TAG_LEN)..];
    s.send_mac(mac, false);

    Ok(buf.into_boxed_slice())
}

/// Decrypts and checks the MAC of an encrypted message, given a key of any size greater
/// than 128 bits (16 bytes).
pub fn decrypt(key: &Key, mut buf: Box<[u8]>) -> Result<(Codec, Box<[u8]>), Error> {
    if key.len() < 16 {
        return Err(Error::KeyTooShort);
    }

    if buf.len() < TAG_LEN + NONCE_LEN {
        return Err(Error::CipherTooShort);
    }

    let mut s = Strobe::new(b"ipld-block-builder", SecParam::B128);
    let nonce = &buf[..NONCE_LEN];

    // Absorb the key
    s.ad(key.deref(), false);
    s.ad(nonce, false);

    let buf_len = buf.len();
    let data = &mut buf[NONCE_LEN..(buf_len - TAG_LEN)];
    s.recv_enc(data, false);

    let (raw_codec, data) =
        unsigned_varint::decode::u64(data).map_err(|e| Error::Codec(Box::new(e)))?;
    let codec = Codec::try_from(raw_codec).map_err(|e| Error::Codec(Box::new(e)))?;
    let data = data.to_vec().into_boxed_slice();

    let mac = &mut buf[(buf_len - TAG_LEN)..];
    s.recv_mac(mac, false).map_err(|_| Error::Integrity)?;

    Ok((codec, data))
}
