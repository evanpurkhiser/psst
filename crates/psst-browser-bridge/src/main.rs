use std::{
    env,
    error::Error,
    fmt,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use psst::{AssertionRequest, EXTENSION_ORIGIN};
use zeroize::Zeroizing;

const MAX_JSON_REQUEST_BYTES: usize = 64 * 1024;
const DAEMON_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_READ_TIMEOUT: Duration = Duration::from_secs(20);
const PASSKEY_HANDOFF_TIMEOUT: Duration = Duration::from_secs(60);
const PASSKEY_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug)]
enum ProxyError {
    InputSizeLimit,
    ResponseSizeLimit,
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputSizeLimit => {
                write!(formatter, "Chrome native message exceeded its maximum size")
            }
            Self::ResponseSizeLimit => {
                write!(formatter, "bridge response exceeded its maximum size")
            }
            Self::Io(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
        }
    }
}

impl Error for ProxyError {}

impl From<std::io::Error> for ProxyError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ProxyError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

type Result<T> = std::result::Result<T, ProxyError>;

fn main() {
    if let Err(error) = disable_core_dumps().and_then(|()| run()) {
        eprintln!("error browser_bridge_unavailable: {error}");
        std::process::exit(30);
    }
}

fn run() -> Result<()> {
    let origin = env::args().nth(1);
    let response = if origin.as_deref().is_some_and(is_extension_origin) {
        match read_native_message().and_then(wait_for_bridge_assertion) {
            Ok(response) => response,
            Err(error) => bridge_error(error.to_string()),
        }
    } else {
        bridge_error("unexpected extension origin")
    };

    write_native_message(&response)
}

fn is_extension_origin(value: &str) -> bool {
    value == EXTENSION_ORIGIN || value == EXTENSION_ORIGIN.trim_end_matches('/')
}

fn bridge_error(message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "code": "browser_bridge_unavailable",
        "error": message.into(),
    })
}

fn read_native_message() -> Result<AssertionRequest> {
    let mut length = [0_u8; 4];
    std::io::stdin().read_exact(&mut length)?;
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_JSON_REQUEST_BYTES {
        return Err(ProxyError::InputSizeLimit);
    }

    let mut input = Zeroizing::new(vec![0_u8; length]);
    std::io::stdin().read_exact(&mut input)?;
    Ok(serde_json::from_slice(&input)?)
}

fn write_native_message(response: &serde_json::Value) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_vec(response)?);
    let length = u32::try_from(encoded.len()).map_err(|_| ProxyError::ResponseSizeLimit)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&length.to_ne_bytes())?;
    stdout.write_all(&encoded)?;
    stdout.flush()?;
    Ok(())
}

fn wait_for_bridge_assertion(request: AssertionRequest) -> Result<serde_json::Value> {
    let deadline = Instant::now() + PASSKEY_HANDOFF_TIMEOUT;
    loop {
        let response = request_bridge_assertion(&request)?;
        if response.get("code").and_then(serde_json::Value::as_str)
            != Some("passkey_handoff_required")
        {
            return Ok(response);
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining <= PASSKEY_POLL_INTERVAL {
            thread::sleep(remaining);
            return Ok(response);
        }

        thread::sleep(PASSKEY_POLL_INTERVAL);
    }
}

fn request_bridge_assertion(request: &AssertionRequest) -> Result<serde_json::Value> {
    let socket = env::var_os("PSST_BROWSER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/psst/bridge.sock"));
    request_bridge_assertion_at(request, &socket)
}

fn request_bridge_assertion_at(
    request: &AssertionRequest,
    socket: &Path,
) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(DAEMON_WRITE_TIMEOUT))?;
    stream.set_read_timeout(Some(DAEMON_READ_TIMEOUT))?;

    let mut encoded = Zeroizing::new(serde_json::to_vec(request)?);
    encoded.push(b'\n');
    stream.write_all(&encoded)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = Zeroizing::new(Vec::new());
    BufReader::new(stream)
        .take(MAX_JSON_REQUEST_BYTES as u64 + 1)
        .read_until(b'\n', &mut response)?;
    if response.len() > MAX_JSON_REQUEST_BYTES {
        return Err(ProxyError::ResponseSizeLimit);
    }

    Ok(serde_json::from_slice(&response)?)
}

fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` points to an initialized `rlimit` for the duration of the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0 {
        return Ok(());
    }

    Err(std::io::Error::last_os_error().into())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn accepts_the_extension_origin_with_or_without_a_trailing_slash() {
        assert!(is_extension_origin(EXTENSION_ORIGIN));
        assert!(is_extension_origin(EXTENSION_ORIGIN.trim_end_matches('/')));
        assert!(!is_extension_origin("chrome-extension://unexpected/"));
    }

    #[test]
    fn uses_the_restricted_bridge_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("bridge.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            let request: AssertionRequest = serde_json::from_str(&request).unwrap();
            assert_eq!(request.origin, "https://example.com");
            stream
                .write_all(b"{\"success\":false,\"code\":\"fixture\"}\n")
                .unwrap();
        });
        let request = AssertionRequest {
            request_id: Some("fixture".into()),
            origin: "https://example.com".into(),
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: Some("example.com".into()),
            allow_credentials: Vec::new(),
        };

        let response = request_bridge_assertion_at(&request, &socket).unwrap();

        assert_eq!(response["code"], "fixture");
        server.join().unwrap();
    }
}
