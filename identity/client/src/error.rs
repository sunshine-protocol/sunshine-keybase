use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cbor(#[from] libipld::cbor::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Cid(#[from] libipld::cid::Error),

    #[error("Failed to find account associated with key.")]
    NoAccount,
    #[error("invalid claim {0}")]
    InvalidClaim(&'static str),
    #[error("failed to resolve identity")]
    ResolveFailure,
    #[error("proof not found")]
    ProofNotFound,
    #[error("failed to get block hash")]
    NoBlockHash,
    #[error("runtime invalid")]
    RuntimeInvalid,
}

pub type Result<T> = core::result::Result<T, Error>;
