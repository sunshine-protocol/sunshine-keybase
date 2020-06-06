use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Identity(#[from] client_identity::Error),
    #[error(transparent)]
    Ipfs(#[from] ipfs_embed::Error),
    #[error(transparent)]
    Subxt(#[from] substrate_subxt::Error),
    #[error(transparent)]
    Io(#[from] async_std::io::Error),
    #[error(transparent)]
    Keystore(#[from] keybase_keystore::Error),
    #[error(transparent)]
    Qr(#[from] qr2term::QrError),

    #[error("Failed to find config dir. Use `--path` to supply a suitable directory.")]
    ConfigDirNotFound,
    #[error("Invalid suri encoded key pair.")]
    InvalidSuri,
    #[error("Invalid ss58 encoded account id.")]
    InvalidSs58,
    #[error("Failed to decode transfer event.")]
    TransferEventDecode,
    #[error("Failed to find transfer event.")]
    TransferEventFind,
    #[error("Failed to find an account associated with key.")]
    NoAccount,
}
