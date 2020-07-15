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
    InvalidService(#[from] client::ServiceParseError),
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
