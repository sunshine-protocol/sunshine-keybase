use thiserror::Error;
use strobe_rs::AuthError;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("keystore is corrupted")]
    Corrupted,
    #[error("keystore is locked")]
    Locked,
    #[error("gen missmatch")]
    GenMissmatch,
}

impl From<AuthError> for Error {
    fn from(_err: AuthError) -> Self {
        Self::Locked
    }
}
