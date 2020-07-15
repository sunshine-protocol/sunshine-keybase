use std::ffi::CString;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error<E: std::error::Error + std::fmt::Debug + 'static> {
    #[error(transparent)]
    Client(E),
    #[error(transparent)]
    Io(#[from] async_std::io::Error),
    #[error("Failed to find config dir. Use `--path` to supply a suitable directory.")]
    ConfigDirNotFound,
    #[error(transparent)]
    InvalidSuri(#[from] sunshine_core::InvalidSuri),
    #[error(transparent)]
    InvalidSs58(#[from] sunshine_core::InvalidSs58),
    #[error(transparent)]
    InvalidService(#[from] sunshine_identity_client::ServiceParseError),
    #[error("Failed to decode transfer event.")]
    TransferEventDecode,
    #[error("Failed to find transfer event.")]
    TransferEventFind,
    #[error("Device key is already configured. Use `--force` if you want to overwrite it.")]
    HasDeviceKey,
    #[error("Password too short.")]
    PasswordTooShort,
    #[error("Passwords don't match.")]
    PasswordMissmatch,
    #[error("Invalid paperkey.")]
    InvalidMnemonic,
    #[error("Failed to mint the account.")]
    FailedToMint,
}

pub type Result<T, E> = core::result::Result<T, Error<E>>;

pub struct LastError {
    e: Option<String>,
}

impl LastError {
    pub const fn new() -> Self {
        Self { e: None }
    }

    pub fn write(&mut self, e: String) {
        let _ = self.e.take();
        self.e.replace(e);
    }

    pub fn read(&self) -> Option<CString> {
        self.e.clone().and_then(|v| CString::new(v).ok())
    }
}
