use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Identity(#[from] client_identity::error::Error),
    #[error(transparent)]
    Ipfs(#[from] ipfs_embed::Error),
    #[error(transparent)]
    Subxt(#[from] substrate_subxt::Error),
}
