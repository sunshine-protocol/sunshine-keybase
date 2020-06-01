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
    #[error("invalid signature")]
    InvalidSignature,
    #[error("failed to resolve identity")]
    ResolveFailure,
    #[error(transparent)]
    Github(#[from] crate::github::Error),
}
