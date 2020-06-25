use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Cbor(#[from] libipld::cbor::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Scale(#[from] codec::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),
    #[error(transparent)]
    Subxt(#[from] substrate_subxt::Error),
    #[error(transparent)]
    Cid(#[from] libipld::cid::Error),
    #[error(transparent)]
    Keystore(#[from] keystore::Error),

    #[error("keystore already initialized")]
    KeystoreInitialized,
    #[error("account not found")]
    NoAccount,
    #[error("invalid claim {0}")]
    InvalidClaim(&'static str),
    #[error("failed to resolve identity")]
    ResolveFailure,
    #[error("network error: {0}")]
    NetworkError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("proof not found")]
    ProofNotFound,
    #[error("failed to get block hash")]
    NoBlockHash,
    #[error("runtime invalid")]
    RuntimeInvalid,
}

pub type Result<T> = core::result::Result<T, Error>;
