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
    client::{self, EncryptedItem},
    crypto::{self, EncryptedContainer},
    error::{Error, Result},
    item,
    protocol::{Request, Response},
};

const SESSION_TTL: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 64 * 1024;

struct Session {
    key: Zeroizing<[u8; 32]>,
    overview: EncryptedContainer,
    details: EncryptedContainer,
    expires_at: Instant,
}

impl Session {
    fn new(key: Zeroizing<[u8; 32]>, item: EncryptedItem) -> Self {
        Self {
            key,
            overview: item.overview,
            details: item.details,
            expires_at: Instant::now() + SESSION_TTL,
        }
    }

    fn decrypt_details(&self) -> Result<Zeroizing<Vec<u8>>> {
        crypto::decrypt(&self.details, &self.key)
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

    let mut sessions = HashMap::<String, Session>::new();
    let mut idle_since = Instant::now();

    loop {
        sessions.retain(|_, session| session.expires_at > Instant::now());
        if sessions.is_empty() && idle_since.elapsed() >= SESSION_TTL {
            break;
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                idle_since = Instant::now();
                handle_connection(&mut stream, &mut sessions);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }

    fs::remove_file(socket_path)?;
    Ok(())
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

fn handle_connection(stream: &mut UnixStream, sessions: &mut HashMap<String, Session>) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }

    let response = read_request(stream)
        .and_then(|request| handle(request, sessions))
        .unwrap_or_else(|error| Response::Error {
            code: error.code().into(),
            message: error.to_string(),
        });
    let Ok(mut encoded) = serde_json::to_vec(&response).map(Zeroizing::new) else {
        return;
    };
    encoded.push(b'\n');
    let _ = stream.write_all(&encoded);
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

fn handle(request: Request, sessions: &mut HashMap<String, Session>) -> Result<Response> {
    match request {
        Request::Open { ref url } => {
            let keys = crypto::keys_from_link(url)?;
            let item = client::fetch(&keys)?;
            let id = session_id();
            sessions.insert(id.clone(), Session::new(keys.encryption_key, item));
            Ok(Response::Opened { session: id })
        }
        Request::Fields { ref session } => {
            let session = active_session(sessions, session)?;
            let details = session.decrypt_details()?;
            Ok(Response::Fields {
                fields: item::list_fields(&details)?,
            })
        }
        Request::Get {
            ref session,
            ref field,
        } => {
            let session = active_session(sessions, session)?;
            let details = session.decrypt_details()?;
            Ok(Response::Secret {
                value: item::get_field(&details, field)?,
            })
        }
        Request::Close { ref session } => {
            sessions
                .remove(session)
                .ok_or_else(|| Error::SessionNotFound(session.clone()))?;
            Ok(Response::Closed)
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
