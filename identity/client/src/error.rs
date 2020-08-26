use thiserror::Error;

#[derive(Debug, Error)]
#[error("Failed to find account associated with key.")]
pub struct NoAccount;

#[derive(Debug, Error)]
#[error("invalid claim {0}")]
pub struct InvalidClaim(pub &'static str);

#[derive(Debug, Error)]
#[error("failed to resolve identity")]
pub struct ResolveFailure;

#[derive(Debug, Error)]
#[error("proof not found")]
pub struct ProofNotFound;

#[derive(Debug, Error)]
#[error("failed to get block hash")]
pub struct NoBlockHash;

#[derive(Debug, Error)]
#[error("runtime invalid")]
pub struct RuntimeInvalid;
