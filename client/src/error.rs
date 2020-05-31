use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Cbor(#[from] libipld::cbor::Error),
    #[error(transparent)]
    Scale(#[from] codec::Error),
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),
    #[error(transparent)]
    Subxt(#[from] substrate_subxt::Error),
    #[error(transparent)]
    Cid(#[from] libipld::cid::Error),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("claim expired")]
    Expired,
}
