use std::{fs::File, os::fd::AsFd};

use zbus::{DBusError, connection::Builder, interface, proxy, zvariant::Fd};
use zeroize::Zeroizing;

use crate::{
    daemon::service::{Service, SessionSummary},
    domain::item::{FieldSummary, PasskeySummary},
    error::Error,
};

pub const BUS_NAME: &str = "com.evanpurkhiser.Psst1";
pub const OBJECT_PATH: &str = "/com/evanpurkhiser/Psst1";

pub struct PsstInterface {
    service: Service,
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "com.evanpurkhiser.Psst1.Error")]
pub enum ApiError {
    InvalidLink(String),
    ShareUnavailable(String),
    ItemUnsupported(String),
    FieldNotFound(String),
    FieldIsFile(String),
    FieldNotFile(String),
    InvalidTotp(String),
    PasskeyUnavailable(String),
    PasskeyUnsupported(String),
    PasskeyBusy(String),
    PasskeyExpired(String),
    WebAuthnInvalid(String),
    SessionNotFound(String),
    AttachmentUnavailable(String),
    Internal(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

#[proxy(
    interface = "com.evanpurkhiser.Psst1",
    default_service = "com.evanpurkhiser.Psst1",
    default_path = "/com/evanpurkhiser/Psst1"
)]
pub trait Psst {
    fn open(&self, share_url: &str) -> Result<String, ApiError>;
    fn list_sessions(&self) -> Result<Vec<SessionSummary>, ApiError>;
    fn wait_session(&self, known_ids: Vec<String>) -> Result<SessionSummary, ApiError>;
    fn fields(&self, session: &str) -> Result<(Vec<FieldSummary>, Vec<PasskeySummary>), ApiError>;
    fn get(&self, session: &str, field: &str, output: Fd<'_>) -> Result<(), ApiError>;
    fn download(&self, session: &str, field: &str, output: Fd<'_>) -> Result<(), ApiError>;
    fn close(&self, session: &str) -> Result<(), ApiError>;
    fn passkey_handoff(&self, session: &str, request_id: &str) -> Result<(), ApiError>;
}

impl PsstInterface {
    pub fn new(service: Service) -> Self {
        Self { service }
    }
}

#[interface(name = "com.evanpurkhiser.Psst1")]
impl PsstInterface {
    async fn open(&self, share_url: String) -> Result<String, ApiError> {
        let share_url = Zeroizing::new(share_url);
        self.service.open(&share_url).await.map_err(ApiError::from)
    }

    async fn list_sessions(&self) -> Result<Vec<SessionSummary>, ApiError> {
        Ok(self.service.sessions().await)
    }

    async fn wait_session(&self, known_ids: Vec<String>) -> Result<SessionSummary, ApiError> {
        Ok(self.service.wait_session(&known_ids).await)
    }

    async fn fields(
        &self,
        session: &str,
    ) -> Result<(Vec<FieldSummary>, Vec<PasskeySummary>), ApiError> {
        self.service.fields(session).await.map_err(ApiError::from)
    }

    async fn get(&self, session: &str, field: &str, output: Fd<'_>) -> Result<(), ApiError> {
        let descriptor = output
            .as_fd()
            .try_clone_to_owned()
            .map_err(Error::from)
            .map_err(ApiError::from)?;
        let mut output = File::from(descriptor);
        self.service
            .write_field(session, field, &mut output)
            .await
            .map_err(ApiError::from)
    }

    async fn download(&self, session: &str, field: &str, output: Fd<'_>) -> Result<(), ApiError> {
        let descriptor = output
            .as_fd()
            .try_clone_to_owned()
            .map_err(Error::from)
            .map_err(ApiError::from)?;
        let mut output = File::from(descriptor);
        self.service
            .write_attachment(session, field, &mut output)
            .await
            .map_err(ApiError::from)
    }

    async fn close(&self, session: &str) -> Result<(), ApiError> {
        self.service.close(session).await.map_err(ApiError::from)
    }

    async fn passkey_handoff(&self, session: &str, request_id: &str) -> Result<(), ApiError> {
        self.service
            .passkey_handoff(session, request_id)
            .await
            .map_err(ApiError::from)
    }
}

pub async fn serve(service: Service) -> zbus::Result<zbus::Connection> {
    Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, PsstInterface::new(service))?
        .build()
        .await
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        let message = error.to_string();
        match error {
            Error::InvalidLink(_) => Self::InvalidLink(message),
            Error::Unavailable(_) | Error::Http(_) => Self::ShareUnavailable(message),
            Error::UnsupportedContainer | Error::Decryption | Error::Json(_) => {
                Self::ItemUnsupported(message)
            }
            Error::FieldNotFound(_) => Self::FieldNotFound(message),
            Error::FileRequiresDownload(_) => Self::FieldIsFile(message),
            Error::FieldNotFile(_) => Self::FieldNotFile(message),
            Error::InvalidTotp { .. } => Self::InvalidTotp(message),
            Error::PasskeyUnavailable => Self::PasskeyUnavailable(message),
            Error::UnsupportedPasskey | Error::PasskeyKey => Self::PasskeyUnsupported(message),
            Error::BrowserRequestBusy => Self::PasskeyBusy(message),
            Error::PasskeyHandoffExpired => Self::PasskeyExpired(message),
            Error::WebAuthnRequest(_) => Self::WebAuthnInvalid(message),
            Error::SessionNotFound(_) => Self::SessionNotFound(message),
            Error::AttachmentUnavailable => Self::AttachmentUnavailable(message),
            _ => Self::Internal(message),
        }
    }
}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::ZBus(error) => Self::Dbus(error),
            error => Self::Remote {
                code: api_error_code(&error).into(),
                message: error.to_string(),
            },
        }
    }
}

fn api_error_code(error: &ApiError) -> &'static str {
    match error {
        ApiError::InvalidLink(_) => "invalid_link",
        ApiError::ShareUnavailable(_) => "share_unavailable",
        ApiError::ItemUnsupported(_) => "unsupported_item",
        ApiError::FieldNotFound(_) => "field_not_found",
        ApiError::FieldIsFile(_) => "field_is_file",
        ApiError::FieldNotFile(_) => "field_not_file",
        ApiError::InvalidTotp(_) => "invalid_totp",
        ApiError::PasskeyUnavailable(_) => "passkey_unavailable",
        ApiError::PasskeyUnsupported(_) => "passkey_unsupported",
        ApiError::PasskeyBusy(_) => "browser_request_busy",
        ApiError::PasskeyExpired(_) => "passkey_handoff_expired",
        ApiError::WebAuthnInvalid(_) => "webauthn_request_invalid",
        ApiError::SessionNotFound(_) => "session_not_found",
        ApiError::AttachmentUnavailable(_) => "attachment_unavailable",
        ApiError::Internal(_) | ApiError::ZBus(_) => "internal_error",
    }
}
