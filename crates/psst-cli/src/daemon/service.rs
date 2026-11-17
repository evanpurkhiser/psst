use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::Write,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use specta::Type;
use tokio::sync::{Mutex, watch};
use url::Url;
use zbus::zvariant::Type as DbusType;
use zeroize::Zeroizing;

use crate::{
    daemon::{
        browser_protocol::{AssertionRequest, Registration},
        passkey_authorization::{PasskeyRequests, Poll, RequestError},
    },
    domain::{
        attachment,
        client::{self, EncryptedItem},
        crypto::{self, EncryptedContainer},
        item::{self, FieldSummary, PasskeySummary},
        webauthn::Passkey,
    },
    error::{Error, Result},
};

const SESSION_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct Service {
    state: Arc<Mutex<State>>,
    session_changes: watch::Sender<()>,
}

#[derive(Default)]
struct State {
    sessions: HashMap<String, Arc<Session>>,
    passkeys: PasskeyRequests,
}

struct Session {
    key: Zeroizing<[u8; 32]>,
    overview: EncryptedContainer,
    details: EncryptedContainer,
    share_uuid: String,
    file_download: Option<client::FileDownload>,
    summary: SessionSummary,
    expires_at: Instant,
}

#[derive(Clone, Debug, Deserialize, DbusType, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub domains: Vec<String>,
    pub capabilities: Vec<String>,
    pub expires_at: u64,
}

impl Service {
    pub async fn open(&self, url: &str) -> Result<String> {
        let keys = crypto::keys_from_link(url)?;
        let item = client::fetch(&keys).await?;
        let id = session_id();
        let session = Session::new(id.clone(), keys.encryption_key, keys.uuid, item)?;
        self.store_session(id.clone(), session).await;
        Ok(id)
    }

    pub async fn wait_session(&self, known_ids: &[String]) -> SessionSummary {
        let known_ids = known_ids.iter().collect::<HashSet<_>>();
        let mut changes = self.session_changes.subscribe();
        loop {
            if let Some(session) = self
                .sessions()
                .await
                .into_iter()
                .find(|session| !known_ids.contains(&session.id))
            {
                return session;
            }

            changes
                .changed()
                .await
                .expect("the service owns the session change sender");
        }
    }

    pub async fn sessions(&self) -> Vec<SessionSummary> {
        let mut state = self.state.lock().await;
        state.expire();
        let mut sessions = state
            .sessions
            .values()
            .map(|session| session.summary.clone())
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            left.expires_at
                .cmp(&right.expires_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        sessions
    }

    pub async fn expire(&self) {
        self.state.lock().await.expire();
    }

    pub async fn fields(&self, id: &str) -> Result<(Vec<FieldSummary>, Vec<PasskeySummary>)> {
        let session = self.session(id).await?;
        let overview = session.decrypt_overview()?;
        let details = session.decrypt_details()?;
        let passkey = Passkey::describe_item(&overview, &details)?;
        Ok((
            item::list_fields(&details)?,
            passkey.map(PasskeySummary::from).into_iter().collect(),
        ))
    }

    pub async fn write_field(&self, id: &str, field: &str, writer: &mut impl Write) -> Result<()> {
        let session = self.session(id).await?;
        let details = session.decrypt_details()?;
        let value = item::get_field(&details, field)?;
        self.ensure_active(id).await?;
        value.write_to(writer)
    }

    pub async fn write_attachment(
        &self,
        id: &str,
        field: &str,
        writer: &mut impl Write,
    ) -> Result<()> {
        let session = self.session(id).await?;
        let details = session.decrypt_details()?;
        let attachment = item::get_attachment(&details, field)?;
        let download = session
            .file_download
            .as_ref()
            .ok_or(Error::AttachmentUnavailable)?;
        let encrypted =
            client::fetch_attachment(&session.share_uuid, download, &attachment).await?;
        let plaintext = attachment::decrypt(&attachment, encrypted)?;
        self.ensure_active(id).await?;
        writer.write_all(&plaintext)?;
        Ok(())
    }

    pub async fn close(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().await;
        state.expire();
        state
            .sessions
            .remove(id)
            .ok_or_else(|| Error::SessionNotFound(id.into()))?;
        Ok(())
    }

    pub async fn register_passkey(&self, request: AssertionRequest) -> Result<Registration> {
        self.state
            .lock()
            .await
            .passkeys
            .register(request, Instant::now())
            .map_err(request_error)
    }

    pub async fn poll_passkey(&self, request_id: &str, capability: &str) -> Result<Poll> {
        self.state
            .lock()
            .await
            .passkeys
            .poll(request_id, capability, Instant::now())
            .map_err(request_error)
    }

    pub async fn cancel_passkey(&self, request_id: &str, capability: &str) -> Result<()> {
        self.state
            .lock()
            .await
            .passkeys
            .cancel(request_id, capability)
            .map_err(request_error)
    }

    pub async fn passkey_handoff(&self, session_id: &str, request_id: &str) -> Result<()> {
        let session = self.session(session_id).await?;
        let request = self
            .state
            .lock()
            .await
            .passkeys
            .claim(request_id, Instant::now())
            .map_err(request_error)?;
        let result = (|| {
            let overview = session.decrypt_overview()?;
            let details = session.decrypt_details()?;
            Passkey::from_item(&overview, &details)?.assert(&request)
        })();
        let mut state = self.state.lock().await;
        if !state.sessions.contains_key(session_id) {
            state.passkeys.complete(
                request_id,
                Err(("session_not_found".into(), "the session was closed".into())),
            );
            return Err(Error::SessionNotFound(session_id.into()));
        }
        match result {
            Ok(assertion) => {
                state.passkeys.complete(request_id, Ok(assertion));
                Ok(())
            }
            Err(error) => {
                state
                    .passkeys
                    .complete(request_id, Err((error.code().into(), error.to_string())));
                Err(error)
            }
        }
    }

    async fn session(&self, id: &str) -> Result<Arc<Session>> {
        let mut state = self.state.lock().await;
        state.expire();
        state
            .sessions
            .get(id)
            .cloned()
            .ok_or_else(|| Error::SessionNotFound(id.into()))
    }

    async fn ensure_active(&self, id: &str) -> Result<()> {
        self.session(id).await.map(drop)
    }

    async fn store_session(&self, id: String, session: Session) {
        let mut state = self.state.lock().await;
        state.expire();
        state.sessions.insert(id, Arc::new(session));
        drop(state);
        self.session_changes.send_replace(());
    }
}

impl Default for Service {
    fn default() -> Self {
        let (session_changes, _) = watch::channel(());
        Self {
            state: Arc::default(),
            session_changes,
        }
    }
}

impl State {
    fn expire(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| session.expires_at > now);
        self.passkeys.expire(now);
    }
}

impl Session {
    fn new(
        id: String,
        key: Zeroizing<[u8; 32]>,
        share_uuid: String,
        item: EncryptedItem,
    ) -> Result<Self> {
        let overview = crypto::decrypt(&item.overview, &key)?;
        let details = crypto::decrypt(&item.details, &key)?;
        let summary = session_summary(id, &overview, &details)?;

        Ok(Self {
            key,
            overview: item.overview,
            details: item.details,
            share_uuid,
            file_download: item.file_download,
            summary,
            expires_at: Instant::now() + SESSION_TTL,
        })
    }

    fn decrypt_details(&self) -> Result<Zeroizing<Vec<u8>>> {
        crypto::decrypt(&self.details, &self.key)
    }

    fn decrypt_overview(&self) -> Result<Zeroizing<Vec<u8>>> {
        crypto::decrypt(&self.overview, &self.key)
    }
}

fn session_summary(id: String, overview: &[u8], details: &[u8]) -> Result<SessionSummary> {
    let overview_value: Value = serde_json::from_slice(overview)?;
    let title = overview_value
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.is_empty())
        .unwrap_or("Shared item")
        .to_owned();
    let passkey = Passkey::describe_item(overview, details)?;
    let fields = item::list_fields(details)?;
    let mut domains = BTreeSet::new();
    collect_domains(&overview_value, &mut domains);
    if let Some(passkey) = &passkey {
        domains.insert(passkey.rp_id.clone());
    }

    let mut capabilities = BTreeSet::new();
    if fields.iter().any(|field| field.kind != "file") {
        capabilities.insert("fields".into());
    }
    if fields.iter().any(|field| field.kind == "file") {
        capabilities.insert("attachments".into());
    }
    if fields.iter().any(|field| field.kind == "totp") {
        capabilities.insert("totp".into());
    }
    if passkey.is_some() {
        capabilities.insert("passkey".into());
    }

    let expires_at = SystemTime::now()
        .checked_add(SESSION_TTL)
        .ok_or(Error::Clock)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_secs();
    Ok(SessionSummary {
        id,
        title,
        domains: domains.into_iter().collect(),
        capabilities: capabilities.into_iter().collect(),
        expires_at,
    })
}

fn collect_domains(value: &Value, domains: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            if let Ok(url) = Url::parse(value)
                && let Some(domain) = url.domain()
            {
                domains.insert(domain.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_domains(value, domains);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_domains(value, domains);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn session_id() -> String {
    let mut bytes = [0_u8; 10];
    rand::rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
}

fn request_error(error: RequestError) -> Error {
    match error {
        RequestError::Busy => Error::BrowserRequestBusy,
        RequestError::InvalidId => {
            Error::WebAuthnRequest("invalid passkey request identifier".into())
        }
        RequestError::Forbidden => Error::BrowserCapability,
        RequestError::NotFound => Error::PasskeyHandoffExpired,
        RequestError::Full => Error::BrowserRequestLimit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notifies_multiple_session_waiters() {
        let service = Service::default();
        let wait = |service: Service| tokio::spawn(async move { service.wait_session(&[]).await });
        let waiting = [wait(service.clone()), wait(service.clone())];
        tokio::task::yield_now().await;

        let id = "new-session".to_owned();
        service
            .store_session(id.clone(), stub_session(id.clone()))
            .await;

        for waiting in waiting {
            let session = tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .expect("session notification")
                .expect("wait task");
            assert_eq!(session.id, id);
        }
    }

    #[test]
    fn discovers_domains_recursively() {
        let value = serde_json::json!({
            "urls": [{"href": "https://accounts.example.com/login"}],
            "ignored": "not a URL"
        });
        let mut domains = BTreeSet::new();
        collect_domains(&value, &mut domains);

        assert_eq!(
            domains.into_iter().collect::<Vec<_>>(),
            ["accounts.example.com"]
        );
    }

    fn stub_session(id: String) -> Session {
        let container = EncryptedContainer {
            kid: String::new(),
            enc: String::new(),
            cty: String::new(),
            iv: String::new(),
            data: String::new(),
        };
        Session {
            key: Zeroizing::new([0; 32]),
            overview: container.clone(),
            details: container,
            share_uuid: String::new(),
            file_download: None,
            summary: SessionSummary {
                id,
                title: "Shared item".into(),
                domains: Vec::new(),
                capabilities: Vec::new(),
                expires_at: 0,
            },
            expires_at: Instant::now() + SESSION_TTL,
        }
    }
}
