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
    #[error("field {0:?} is a file; use `psst download`")]
    FileRequiresDownload(String),
    #[error("field {0:?} is not a file")]
    FieldNotFile(String),
    #[error("field {0:?} does not contain a valid TOTP URI")]
    InvalidTotp(String),
    #[error("the shared item does not contain a passkey")]
    PasskeyUnavailable,
    #[error("the shared item contains an unsupported passkey")]
    UnsupportedPasskey,
    #[error("the passkey private key could not be decoded")]
    PasskeyKey,
    #[error("invalid WebAuthn request: {0}")]
    WebAuthnRequest(String),
    #[error("the browser passkey request has not been handed off to psst")]
    PasskeyHandoffRequired,
    #[error("another browser passkey handoff is already active")]
    PasskeyHandoffBusy,
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
    #[error("$HOME is not set")]
    HomeDirectory,
    #[error("the browser integration path is invalid")]
    BrowserInstallPath,
    #[error("the browser bridge rejected peer UID {0}")]
    BrowserPeer(u32),
    #[error("$XDG_RUNTIME_DIR is not owned by the current user or has unsafe permissions")]
    UnsafeRuntimeDirectory,
    #[error("the psst socket path is occupied by an unsafe file")]
    UnsafeSocket,
    #[error("{0} exceeded its maximum supported size")]
    InputSizeLimit(&'static str),
    #[error("{0} exceeded its maximum supported size")]
    ResponseSizeLimit(&'static str),
    #[error("the share does not provide an attachment download token")]
    AttachmentUnavailable,
    #[error("1Password returned an unsupported attachment")]
    UnsupportedAttachment,
    #[error("the attachment size did not match its metadata")]
    AttachmentSize,
    #[error("the attachment failed its integrity check")]
    AttachmentIntegrity,
    #[error("the attachment could not be decrypted")]
    AttachmentDecryption,
    #[error("1Password returned an invalid attachment download URL")]
    AttachmentUrl,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Systemd(#[from] systemd_zbus::zbus::Error),
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
            Self::FileRequiresDownload(_) => "field_is_file",
            Self::FieldNotFile(_) => "field_not_file",
            Self::InvalidTotp(_) => "invalid_totp",
            Self::PasskeyUnavailable => "passkey_unavailable",
            Self::UnsupportedPasskey => "passkey_unsupported",
            Self::PasskeyKey => "passkey_key_invalid",
            Self::WebAuthnRequest(_) => "webauthn_request_invalid",
            Self::PasskeyHandoffRequired => "passkey_handoff_required",
            Self::PasskeyHandoffBusy => "passkey_handoff_busy",
            Self::SecretToTerminal => "secret_to_terminal",
            Self::ShareFromTerminal => "share_from_terminal",
            Self::SessionNotFound(_) => "session_not_found",
            Self::DaemonUnavailable => "daemon_unavailable",
            Self::RuntimeDirectory => "runtime_directory_missing",
            Self::HomeDirectory => "home_directory_missing",
            Self::BrowserInstallPath => "browser_install_path_invalid",
            Self::BrowserPeer(_) => "browser_peer_unauthorized",
            Self::UnsafeRuntimeDirectory => "runtime_directory_unsafe",
            Self::UnsafeSocket => "socket_unsafe",
            Self::InputSizeLimit(_) => "input_too_large",
            Self::ResponseSizeLimit(_) => "response_too_large",
            Self::AttachmentUnavailable => "attachment_unavailable",
            Self::UnsupportedAttachment => "unsupported_attachment",
            Self::AttachmentSize => "attachment_size_mismatch",
            Self::AttachmentIntegrity => "attachment_integrity_failed",
            Self::AttachmentDecryption => "attachment_decryption_failed",
            Self::AttachmentUrl => "attachment_url_invalid",
            Self::Http(_) => "network_error",
            Self::Io(_) => "io_error",
            Self::Json(_) => "invalid_json",
            Self::Systemd(_) => "systemd_error",
        }
    }

    pub fn exit_status(&self) -> i32 {
        match self.code() {
            "invalid_link" | "share_from_terminal" | "input_too_large" => 10,
            "share_unavailable" | "network_error" => 11,
            "unsupported_container"
            | "decryption_failed"
            | "invalid_json"
            | "response_too_large"
            | "unsupported_attachment"
            | "attachment_size_mismatch"
            | "attachment_integrity_failed"
            | "attachment_decryption_failed"
            | "attachment_url_invalid"
            | "passkey_unsupported"
            | "passkey_key_invalid" => 12,
            "field_not_found"
            | "field_is_file"
            | "field_not_file"
            | "invalid_totp"
            | "passkey_unavailable"
            | "passkey_handoff_busy"
            | "passkey_handoff_required"
            | "webauthn_request_invalid" => 20,
            "secret_to_terminal" => 21,
            "session_not_found" => 22,
            _ => 30,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
