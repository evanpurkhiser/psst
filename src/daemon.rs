use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    attachment, browser,
    client::{self, EncryptedItem},
    crypto::{self, EncryptedContainer},
    error::{Error, Result},
    item,
    protocol::{Request, Response},
    webauthn::AssertionRequest,
};

const SESSION_TTL: Duration = Duration::from_secs(300);
const PASSKEY_ARM_TTL: Duration = Duration::from_secs(60);
const PASSKEY_REQUEST_TTL: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 64 * 1024;

struct Session {
    key: Zeroizing<[u8; 32]>,
    overview: EncryptedContainer,
    details: EncryptedContainer,
    share_uuid: String,
    file_download: Option<client::FileDownload>,
    expires_at: Instant,
}

struct ArmedPasskey {
    session: Zeroizing<String>,
    request_id: Option<String>,
    expires_at: Instant,
}

struct PendingPasskeyRequest {
    id: String,
    expires_at: Instant,
}

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    armed_passkey: Option<ArmedPasskey>,
    pending_passkey_requests: Vec<PendingPasskeyRequest>,
}

impl State {
    fn expire(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| session.expires_at > now);
        if self.armed_passkey.as_ref().is_some_and(|armed| {
            armed.expires_at <= now || !self.sessions.contains_key(armed.session.as_str())
        }) {
            self.armed_passkey = None;
        }
        self.pending_passkey_requests
            .retain(|pending| pending.expires_at > now);
    }
}

impl Session {
    fn new(key: Zeroizing<[u8; 32]>, share_uuid: String, item: EncryptedItem) -> Self {
        Self {
            key,
            overview: item.overview,
            details: item.details,
            share_uuid,
            file_download: item.file_download,
            expires_at: Instant::now() + SESSION_TTL,
        }
    }

    fn decrypt_details(&self) -> Result<Zeroizing<Vec<u8>>> {
        crypto::decrypt(&self.details, &self.key)
    }

    fn decrypt_overview(&self) -> Result<Zeroizing<Vec<u8>>> {
        crypto::decrypt(&self.overview, &self.key)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.overview.data.zeroize();
        self.details.data.zeroize();
    }
}

pub fn run() -> Result<()> {
    let socket_path = socket_path()?;
    remove_stale_socket(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let browser_bridge = browser_bridge()?;

    let mut state = State::default();
    let mut idle_since = Instant::now();

    loop {
        state.expire();
        if state.sessions.is_empty() && idle_since.elapsed() >= SESSION_TTL {
            break;
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                idle_since = Instant::now();
                handle_connection(&mut stream, &mut state);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }

        if let Some((listener, allowed_peer_uids, _)) = browser_bridge.as_ref() {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    idle_since = Instant::now();
                    handle_browser_connection(&mut stream, allowed_peer_uids, &mut state);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fs::remove_file(socket_path)?;
    if let Some((_, _, socket_path)) = browser_bridge {
        fs::remove_file(socket_path)?;
    }
    Ok(())
}

fn browser_bridge() -> Result<Option<(UnixListener, Vec<u32>, PathBuf)>> {
    let config = browser::config()?;
    if config.allowed_peer_uids.is_empty() {
        return Ok(None);
    }

    let socket_path = browser::socket_path()?;
    let directory = socket_path.parent().ok_or(Error::BrowserInstallPath)?;
    match fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() || metadata.uid() != effective_uid() {
        return Err(Error::UnsafeRuntimeDirectory);
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o711))?;
    remove_stale_socket(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666))?;
    listener.set_nonblocking(true)?;

    Ok(Some((listener, config.allowed_peer_uids, socket_path)))
}

pub fn socket_path() -> Result<PathBuf> {
    let runtime = env::var_os("XDG_RUNTIME_DIR").ok_or(Error::RuntimeDirectory)?;
    let metadata = fs::metadata(&runtime)?;
    if metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(Error::UnsafeRuntimeDirectory);
    }

    Ok(PathBuf::from(runtime).join("psst.sock"))
}

fn remove_stale_socket(path: &std::path::Path) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid() {
        return Err(Error::UnsafeSocket);
    }
    if UnixStream::connect(path).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "the psst daemon is already running",
        )
        .into());
    }

    fs::remove_file(path)?;
    Ok(())
}

fn effective_uid() -> u32 {
    // POSIX guarantees geteuid has no failure mode.
    unsafe { libc::geteuid() }
}

fn handle_connection(stream: &mut UnixStream, state: &mut State) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }

    let reply = read_request(stream).and_then(|request| handle(request, state));
    let (response, body) = match reply {
        Ok(reply) => reply,
        Err(error) => (
            Response::Error {
                code: error.code().into(),
                message: error.to_string(),
            },
            None,
        ),
    };
    let Ok(mut encoded) = serde_json::to_vec(&response).map(Zeroizing::new) else {
        return;
    };
    encoded.push(b'\n');
    if stream.write_all(&encoded).is_err() {
        return;
    }
    if let Some(body) = body {
        let _ = stream.write_all(&body);
    }
}

fn handle_browser_connection(
    stream: &mut UnixStream,
    allowed_peer_uids: &[u32],
    state: &mut State,
) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }

    let reply = peer_uid(stream)
        .and_then(|uid| {
            allowed_peer_uids
                .contains(&uid)
                .then_some(())
                .ok_or(Error::BrowserPeer(uid))
        })
        .and_then(|()| read_browser_request(stream))
        .and_then(|request| handle(Request::PasskeyBrowserAssert { request }, state));
    let response = match reply {
        Ok((Response::PasskeyAssertion { assertion }, None)) => serde_json::json!({
            "success": true,
            "assertion": assertion,
        }),
        Ok(_) => serde_json::json!({
            "success": false,
            "code": "browser_response_invalid",
            "error": "the daemon returned an unexpected browser response",
        }),
        Err(error) => serde_json::json!({
            "success": false,
            "code": error.code(),
            "error": error.to_string(),
        }),
    };
    let Ok(mut encoded) = serde_json::to_vec(&response).map(Zeroizing::new) else {
        return;
    };
    encoded.push(b'\n');
    let _ = stream.write_all(&encoded);
}

fn read_browser_request(stream: &UnixStream) -> Result<AssertionRequest> {
    let mut line = Zeroizing::new(Vec::new());
    BufReader::new(stream)
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if line.len() > MAX_REQUEST_BYTES {
        return Err(Error::InputSizeLimit("browser assertion request"));
    }

    Ok(serde_json::from_slice(&line)?)
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;

    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // getsockopt writes a ucred value into the provided initialized storage.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(credentials.uid)
}

fn read_request(stream: &UnixStream) -> Result<Request> {
    let mut line = Zeroizing::new(Vec::new());
    BufReader::new(stream)
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if line.len() > MAX_REQUEST_BYTES {
        return Err(Error::InputSizeLimit("daemon request"));
    }

    Ok(serde_json::from_slice(&line)?)
}

fn handle(request: Request, state: &mut State) -> Result<(Response, Option<Zeroizing<Vec<u8>>>)> {
    match request {
        Request::Open { ref url } => {
            let keys = crypto::keys_from_link(url)?;
            let item = client::fetch(&keys)?;
            let id = session_id();
            state.sessions.insert(
                id.clone(),
                Session::new(keys.encryption_key, keys.uuid, item),
            );
            Ok((Response::Opened { session: id }, None))
        }
        Request::Fields { ref session } => {
            let session = active_session(&state.sessions, session)?;
            let details = session.decrypt_details()?;
            Ok((
                Response::Fields {
                    fields: item::list_fields(&details)?,
                },
                None,
            ))
        }
        Request::Get {
            ref session,
            ref field,
        } => {
            let session = active_session(&state.sessions, session)?;
            let details = session.decrypt_details()?;
            Ok((
                Response::Secret {
                    value: item::get_field(&details, field)?,
                },
                None,
            ))
        }
        Request::Download {
            ref session,
            ref field,
        } => {
            let session = active_session(&state.sessions, session)?;
            let details = session.decrypt_details()?;
            let attachment = item::get_attachment(&details, field)?;
            let download = session
                .file_download
                .as_ref()
                .ok_or(Error::AttachmentUnavailable)?;
            let encrypted = client::fetch_attachment(&session.share_uuid, download, &attachment)?;
            let plaintext = attachment::decrypt(&attachment, encrypted)?;
            let size = plaintext.len() as u64;
            Ok((Response::Attachment { size }, Some(plaintext)))
        }
        Request::PasskeyDescribe { ref session } => {
            let session = active_session(&state.sessions, session)?;
            let overview = session.decrypt_overview()?;
            let details = session.decrypt_details()?;
            let passkey = crate::webauthn::Passkey::from_item(&overview, &details)?;
            Ok((
                Response::PasskeyCredential {
                    credential: passkey.describe(),
                },
                None,
            ))
        }
        Request::PasskeyAssert {
            ref session,
            ref request,
        } => {
            let session = active_session(&state.sessions, session)?;
            let overview = session.decrypt_overview()?;
            let details = session.decrypt_details()?;
            let passkey = crate::webauthn::Passkey::from_item(&overview, &details)?;
            Ok((
                Response::PasskeyAssertion {
                    assertion: passkey.assert(request)?,
                },
                None,
            ))
        }
        Request::PasskeyArm { ref session } => {
            active_session(&state.sessions, session)?;
            state.armed_passkey = Some(ArmedPasskey {
                session: Zeroizing::new(session.clone()),
                request_id: state
                    .pending_passkey_requests
                    .last()
                    .map(|pending| pending.id.clone()),
                expires_at: Instant::now() + PASSKEY_ARM_TTL,
            });
            Ok((Response::PasskeyArmed, None))
        }
        Request::PasskeyBrowserAssert { ref request } => {
            let request_id = request
                .request_id
                .as_deref()
                .filter(|id| !id.is_empty() && id.len() <= 128);
            let matches_arm = state.armed_passkey.as_ref().is_some_and(|armed| {
                armed.expires_at > Instant::now()
                    && armed
                        .request_id
                        .as_deref()
                        .is_none_or(|armed_id| Some(armed_id) == request_id)
            });
            if !matches_arm {
                if let Some(id) = request_id
                    && !state
                        .pending_passkey_requests
                        .iter()
                        .any(|pending| pending.id == id)
                {
                    state.pending_passkey_requests.push(PendingPasskeyRequest {
                        id: id.into(),
                        expires_at: Instant::now() + PASSKEY_REQUEST_TTL,
                    });
                }
                return Err(Error::PasskeyNotArmed);
            }

            let armed = state.armed_passkey.take().ok_or(Error::PasskeyNotArmed)?;
            state
                .pending_passkey_requests
                .retain(|pending| Some(pending.id.as_str()) != request_id);
            let session = active_session(&state.sessions, armed.session.as_str())?;
            let overview = session.decrypt_overview()?;
            let details = session.decrypt_details()?;
            let passkey = crate::webauthn::Passkey::from_item(&overview, &details)?;
            Ok((
                Response::PasskeyAssertion {
                    assertion: passkey.assert(request)?,
                },
                None,
            ))
        }
        Request::Close { ref session } => {
            state
                .sessions
                .remove(session)
                .ok_or_else(|| Error::SessionNotFound(session.clone()))?;
            if state
                .armed_passkey
                .as_ref()
                .is_some_and(|armed| armed.session.as_str() == session)
            {
                state.armed_passkey = None;
            }
            Ok((Response::Closed, None))
        }
    }
}

fn active_session<'a>(sessions: &'a HashMap<String, Session>, id: &str) -> Result<&'a Session> {
    sessions
        .get(id)
        .filter(|session| session.expires_at > Instant::now())
        .ok_or_else(|| Error::SessionNotFound(id.into()))
}

fn session_id() -> String {
    let mut bytes = [0; 10];
    rand::rng().fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion_request() -> crate::webauthn::AssertionRequest {
        crate::webauthn::AssertionRequest {
            request_id: Some("request-1".into()),
            origin: "https://example.com".into(),
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: Some("example.com".into()),
            allow_credentials: Vec::new(),
        }
    }

    #[test]
    fn browser_assertions_require_an_armed_session() {
        let mut state = State::default();
        let result = handle(
            Request::PasskeyBrowserAssert {
                request: assertion_request(),
            },
            &mut state,
        );

        assert!(matches!(result, Err(Error::PasskeyNotArmed)));
        assert_eq!(state.pending_passkey_requests[0].id, "request-1");
    }

    #[test]
    fn polling_does_not_reorder_pending_browser_requests() {
        let mut state = State::default();
        let mut first = assertion_request();
        first.request_id = Some("first".into());
        let mut second = assertion_request();
        second.request_id = Some("second".into());

        for request in [first.clone(), second, first] {
            let _ = handle(Request::PasskeyBrowserAssert { request }, &mut state);
        }

        assert_eq!(state.pending_passkey_requests.len(), 2);
        assert_eq!(state.pending_passkey_requests[0].id, "first");
        assert_eq!(state.pending_passkey_requests[1].id, "second");
    }

    #[test]
    fn arming_requires_an_active_session() {
        let result = handle(
            Request::PasskeyArm {
                session: "missing".into(),
            },
            &mut State::default(),
        );

        assert!(matches!(result, Err(Error::SessionNotFound(_))));
    }
}
