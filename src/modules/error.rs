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
    #[error("Keyring Search Error: {0}")]
    KeyringSearchError(String),
    #[error("Config directory not found")]
    ConfigDirNotFound,
    #[error("Master passwords do not match")]
    MasterPasswordMismatch,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("TOML deserialization error: {0}")]
    TomlDeError(#[from] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    TomlSerError(#[from] toml::ser::Error),
    #[error("Dialoguer error: {0}")]
    DialoguerError(#[from] dialoguer::Error),
}
