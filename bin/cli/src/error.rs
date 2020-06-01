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
    #[error("Invalid seqno, run `cli-identity id` for a list of valid sequence numbers.")]
    InvalidSeqNo,
    #[error("Failed to decode transfer event.")]
    FailedToDecodeTransferEvent,
    #[error("Failed to find transfer event.")]
    FailedToFindTransferEvent,
}
