use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error<E: std::fmt::Debug + std::error::Error + 'static> {
    #[error(transparent)]
    Client(E),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Qr(#[from] qr2term::QrError),

    #[error("Failed to find config dir. Use `--path` to supply a suitable directory.")]
    ConfigDirNotFound,
    #[error("Device key is already configured. Use `--force` if you want to overwrite it.")]
    HasDeviceKey,

    #[error(transparent)]
    InvalidSuri(#[from] sunshine_core::InvalidSuri),
    #[error(transparent)]
    InvalidSs58(#[from] sunshine_core::InvalidSs58),
    #[error(transparent)]
    InvalidService(#[from] sunshine_identity_client::ServiceParseError),
    #[error(transparent)]
    NotEnoughEntropy(#[from] sunshine_core::NotEnoughEntropyError),

    #[error("Failed to find transfer event.")]
    TransferEventFind,
    #[error("Failed to decode transfer event.")]
    TransferEventDecode,
}

pub type Result<T, E> = core::result::Result<T, Error<E>>;
