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

    #[error("Failed to find config dir. Use `--path` to supply a suitable directory.")]
    ConfigDirNotFound,
    #[error("Invalid account id.")]
    InvalidAccountId,
    #[error("Invalid seqno, run `cli-identity id` for a list of valid sequence numbers.")]
    SeqNoInvalid,
    #[error("Failed to decode transfer event.")]
    TransferEventDecode,
    #[error("Failed to find transfer event.")]
    TransferEventFind,
}
