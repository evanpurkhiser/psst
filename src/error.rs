use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid 1Password share link: {0}")]
    InvalidLink(String),
    #[error("the share is {0}")]
    Unavailable(String),
    #[error("{0}")]
    Remote(String),
    #[error("1Password returned an unsupported encrypted item")]
    UnsupportedContainer,
    #[error("the shared item could not be decrypted")]
    Decryption,
    #[error("field {0:?} was not found")]
    FieldNotFound(String),
    #[error("field {0:?} does not contain a valid TOTP URI")]
    InvalidTotp(String),
    #[error("refusing to write a secret to a terminal; pipe or redirect stdout")]
    SecretToTerminal,
    #[error("session {0:?} was not found or has expired")]
    SessionNotFound(String),
    #[error("the psst daemon did not start")]
    DaemonUnavailable,
    #[error("$XDG_RUNTIME_DIR is not set")]
    RuntimeDirectory,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
