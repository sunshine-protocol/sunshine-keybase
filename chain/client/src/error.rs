use thiserror::Error;

#[derive(Debug, Error)]
#[error("Couldn't create chain.")]
pub struct CreateChain;

#[derive(Debug, Error)]
#[error("Couldn't author block.")]
pub struct AuthorBlock;

#[derive(Debug, Error)]
#[error("Couldn't add authority.")]
pub struct AddAuthority;

#[derive(Debug, Error)]
#[error("Couldn't remove authority.")]
pub struct RemoveAuthority;
