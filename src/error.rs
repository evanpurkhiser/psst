use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid 1Password share link: {0}")]
    InvalidLink(String),
    #[error("the share is {0}")]
    Unavailable(String),
    #[error("{message}")]
    Remote { code: String, message: String },
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
    #[error("refusing to read a share link from a terminal; pipe or redirect stdin")]
    ShareFromTerminal,
    #[error("session {0:?} was not found or has expired")]
    SessionNotFound(String),
    #[error(
        "the psst daemon did not become available; inspect `systemctl --user status psst-daemon`"
    )]
    DaemonUnavailable,
    #[error("$XDG_RUNTIME_DIR is not set")]
    RuntimeDirectory,
    #[error("$XDG_RUNTIME_DIR is not owned by the current user or has unsafe permissions")]
    UnsafeRuntimeDirectory,
    #[error("the psst socket path is occupied by an unsafe file")]
    UnsafeSocket,
    #[error("{0} exceeded its maximum supported size")]
    InputSizeLimit(&'static str),
    #[error("{0} exceeded its maximum supported size")]
    ResponseSizeLimit(&'static str),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidLink(_) => "invalid_link",
            Self::Unavailable(_) => "share_unavailable",
            Self::Remote { code, .. } => code,
            Self::UnsupportedContainer => "unsupported_container",
            Self::Decryption => "decryption_failed",
            Self::FieldNotFound(_) => "field_not_found",
            Self::InvalidTotp(_) => "invalid_totp",
            Self::SecretToTerminal => "secret_to_terminal",
            Self::ShareFromTerminal => "share_from_terminal",
            Self::SessionNotFound(_) => "session_not_found",
            Self::DaemonUnavailable => "daemon_unavailable",
            Self::RuntimeDirectory => "runtime_directory_missing",
            Self::UnsafeRuntimeDirectory => "runtime_directory_unsafe",
            Self::UnsafeSocket => "socket_unsafe",
            Self::InputSizeLimit(_) => "input_too_large",
            Self::ResponseSizeLimit(_) => "response_too_large",
            Self::Http(_) => "network_error",
            Self::Io(_) => "io_error",
            Self::Json(_) => "invalid_json",
        }
    }

    pub fn exit_status(&self) -> i32 {
        match self.code() {
            "invalid_link" | "share_from_terminal" | "input_too_large" => 10,
            "share_unavailable" | "network_error" => 11,
            "unsupported_container"
            | "decryption_failed"
            | "invalid_json"
            | "response_too_large" => 12,
            "field_not_found" | "invalid_totp" => 20,
            "secret_to_terminal" => 21,
            "session_not_found" => 22,
            _ => 30,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
