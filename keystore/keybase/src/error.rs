use strobe_rs::AuthError;
use thiserror::Error;

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
    #[error("keystore is initialized")]
    Initialized,
}

impl From<AuthError> for Error {
    fn from(_err: AuthError) -> Self {
        Self::Locked
    }
}
