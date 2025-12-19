use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("General error: {0}")]
    GeneralError(String),
    #[error("Secret manager error: {0}")]
    SecretManagerError(String),
    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Keyring Error: {0}")]
    KeyringError(#[from] keyring::Error),
    #[error("Invalid key")]
    InvalidKey,
}
