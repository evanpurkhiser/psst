mod attachment;
mod browser;
mod client;
mod crypto;
mod daemon;
mod error;
mod item;
mod passkey_authorization;
mod plugin;
mod protocol;
mod skill;
mod webauthn;

use std::{
    env,
    io::{BufRead, BufReader, IsTerminal, Read, Write},
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use systemd_zbus::zbus::{blocking::Connection, zvariant::Value};
use systemd_zbus::{ManagerProxyBlocking, Mode};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    protocol::{Request, Response},
};

const MAX_SHARE_LINK_BYTES: usize = 4 * 1024;
const MAX_JSON_REQUEST_BYTES: usize = 64 * 1024;
const MAX_DAEMON_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const DAEMON_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_READ_TIMEOUT: Duration = Duration::from_secs(20);
const PASSKEY_HANDOFF_TIMEOUT: Duration = Duration::from_secs(60);
const PASSKEY_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read a 1Password share link from stdin and create a five-minute session.
    Open,
    /// List populated fields without their values.
    Fields {
        /// Opaque identifier returned by `psst open`.
        session: String,
    },
    /// Write one field value to stdout.
    Get {
        /// Opaque identifier returned by `psst open`.
        session: String,
        /// Exact selector returned by `psst fields`.
        #[arg(allow_hyphen_values = true)]
        field: String,
    },
    /// Decrypt an attached file and write its bytes to stdout.
    Download {
        /// Opaque identifier returned by `psst open`.
        session: String,
        /// Exact file selector returned by `psst fields`.
        #[arg(allow_hyphen_values = true)]
        field: String,
    },
    /// Inspect or use a passkey without exporting its private key.
    Passkey {
        #[command(subcommand)]
        command: PasskeyCommand,
    },
    /// Install the Chrome passkey extension and native messaging host.
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    /// Print the version-matched usage skill for agents and automation.
    Skill,
    /// Destroy a session immediately.
    Close {
        /// Opaque identifier returned by `psst open`.
        session: String,
    },
    /// Serve the Agent Browser plugin protocol over standard input and output.
    #[command(hide = true)]
    AgentBrowserPlugin,
    #[command(hide = true)]
    Daemon,
}

#[derive(Subcommand)]
enum PasskeyCommand {
    /// Write the passkey's relying-party and credential identifiers as JSON.
    Describe {
        /// Opaque identifier returned by `psst open`.
        session: String,
    },
    /// Read a WebAuthn request from stdin and write a signed assertion as JSON.
    Assert {
        /// Opaque identifier returned by `psst open`.
        session: String,
    },
    /// Authorize one browser passkey request for up to one minute.
    Handoff {
        /// Opaque identifier returned by `psst open`.
        session: String,
        /// Identifier displayed by the PSST browser prompt.
        request_id: String,
    },
}

#[derive(Subcommand)]
enum BrowserCommand {
    /// Install or refresh the bundled Chrome integration.
    Install {
        /// Host UID permitted to use the container browser bridge.
        #[arg(long = "peer-uid", value_name = "UID")]
        allowed_peer_uids: Vec<u32>,
    },
    /// Report installed browser paths and container peer authorization.
    Status,
    /// Clear all container browser peer authorization.
    Reset,
}

fn main() {
    if env::args()
        .nth(1)
        .as_deref()
        .is_some_and(browser::is_extension_origin)
    {
        if let Err(error) = disable_core_dumps().and_then(|()| run_native_host()) {
            write_error(error.code(), &error.to_string());
            std::process::exit(error.exit_status());
        }
        return;
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) if error.use_stderr() => {
            let message = error.to_string();
            let message = message.strip_prefix("error: ").unwrap_or(&message);
            write_error("cli_usage", message);
            std::process::exit(error.exit_code());
        }
        Err(error) => error.exit(),
    };
    if let Err(error) = disable_core_dumps().and_then(|()| run(cli.command)) {
        write_error(error.code(), &error.to_string());
        std::process::exit(error.exit_status());
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Daemon => daemon::run(),
        Command::AgentBrowserPlugin => run_agent_browser_plugin(),
        Command::Open => {
            let stdin = std::io::stdin();
            refuse_share_terminal(stdin.is_terminal())?;
            let mut url = Zeroizing::new(String::new());
            stdin
                .take(MAX_SHARE_LINK_BYTES as u64 + 1)
                .read_to_string(&mut url)?;
            if url.len() > MAX_SHARE_LINK_BYTES {
                return Err(Error::InputSizeLimit("share link"));
            }
            if url.trim().is_empty() {
                return Err(Error::InvalidLink("stdin was empty".into()));
            }

            match request(Request::Open {
                url: std::mem::take(&mut *url),
            })? {
                Response::Opened { session } => {
                    let stdout = std::io::stdout();
                    if let Err(error) = writeln!(stdout.lock(), "{session}") {
                        let _ = request(Request::Close {
                            session: session.clone(),
                        });
                        return Err(error.into());
                    }
                }
                response => return unexpected(response),
            }
            Ok(())
        }
        Command::Fields { session } => match request(Request::Fields { session })? {
            Response::Fields { fields } => {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                serde_json::to_writer_pretty(&mut stdout, &fields)?;
                writeln!(stdout)?;
                Ok(())
            }
            response => unexpected(response),
        },
        Command::Get { session, field } => {
            let mut stdout = std::io::stdout();
            refuse_terminal(stdout.is_terminal())?;

            match request(Request::Get { session, field })? {
                Response::Secret { value } => {
                    value.write_to(&mut stdout)?;
                    Ok(())
                }
                response => unexpected(response),
            }
        }
        Command::Download { session, field } => {
            let mut stdout = std::io::stdout();
            refuse_terminal(stdout.is_terminal())?;
            request_attachment(Request::Download { session, field }, &mut stdout)
        }
        Command::Passkey { command } => run_passkey(command),
        Command::Browser { command } => run_browser(command),
        Command::Skill => skill::write(std::io::stdout().lock()),
        Command::Close { session } => match request(Request::Close { session })? {
            Response::Closed => Ok(()),
            response => unexpected(response),
        },
    }
}

fn run_passkey(command: PasskeyCommand) -> Result<()> {
    match command {
        PasskeyCommand::Describe { session } => {
            match request(Request::PasskeyDescribe { session })? {
                Response::PasskeyCredential { credential } => {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    serde_json::to_writer_pretty(&mut stdout, &credential)?;
                    writeln!(stdout)?;
                    Ok(())
                }
                response => unexpected(response),
            }
        }
        PasskeyCommand::Assert { session } => {
            let mut input = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(MAX_JSON_REQUEST_BYTES as u64 + 1)
                .read_to_end(&mut input)?;
            if input.len() > MAX_JSON_REQUEST_BYTES {
                return Err(Error::InputSizeLimit("passkey assertion request"));
            }
            let assertion_request = serde_json::from_slice(&input)?;

            match request(Request::PasskeyAssert {
                session,
                request: assertion_request,
            })? {
                Response::PasskeyAssertion { assertion } => {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    serde_json::to_writer(&mut stdout, &assertion)?;
                    writeln!(stdout)?;
                    Ok(())
                }
                response => unexpected(response),
            }
        }
        PasskeyCommand::Handoff {
            session,
            request_id,
        } => match request(Request::PasskeyHandoff {
            session,
            request_id,
        })? {
            Response::PasskeyHandoffReady => Ok(()),
            response => unexpected(response),
        },
    }
}

fn run_browser(command: BrowserCommand) -> Result<()> {
    match command {
        BrowserCommand::Install { allowed_peer_uids } => {
            let peer_configuration = if allowed_peer_uids.is_empty() {
                browser::PeerConfiguration::Preserve
            } else {
                browser::PeerConfiguration::Replace(&allowed_peer_uids)
            };
            let installation = browser::install(peer_configuration)?;
            println!("{}", installation.extension.display());
            Ok(())
        }
        BrowserCommand::Status => {
            serde_json::to_writer_pretty(std::io::stdout().lock(), &browser::status()?)?;
            println!();
            Ok(())
        }
        BrowserCommand::Reset => browser::reset_peers(),
    }
}

fn run_agent_browser_plugin() -> Result<()> {
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(MAX_JSON_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)?;
    if input.len() > MAX_JSON_REQUEST_BYTES {
        return Err(Error::InputSizeLimit("plugin request"));
    }

    let response = match plugin::parse(&input) {
        Ok(plugin::Action::Manifest) => plugin::manifest_response(),
        Ok(plugin::Action::Launch) => {
            match browser::install(browser::PeerConfiguration::Preserve) {
                Ok(installation) => plugin::launch_response(&installation.extension),
                Err(error) => plugin::error_response(&error),
            }
        }
        Err(error) => plugin::error_response(&error),
    };

    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}

fn run_native_host() -> Result<()> {
    let mut length = [0_u8; 4];
    std::io::stdin().read_exact(&mut length)?;
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_JSON_REQUEST_BYTES {
        return Err(Error::InputSizeLimit("native messaging request"));
    }

    let mut input = Zeroizing::new(vec![0_u8; length]);
    std::io::stdin().read_exact(&mut input)?;
    let response = match serde_json::from_slice(&input) {
        Ok(assertion_request) => wait_for_browser_assertion(assertion_request)?,
        Err(error) => serde_json::json!({
            "success": false,
            "code": "invalid_json",
            "error": error.to_string(),
        }),
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&response)?);
    let length = u32::try_from(encoded.len())
        .map_err(|_| Error::ResponseSizeLimit("native messaging response"))?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&length.to_ne_bytes())?;
    stdout.write_all(&encoded)?;
    stdout.flush()?;
    Ok(())
}

fn wait_for_browser_assertion(
    assertion_request: webauthn::AssertionRequest,
) -> Result<serde_json::Value> {
    let deadline = Instant::now() + PASSKEY_HANDOFF_TIMEOUT;
    loop {
        match request(Request::PasskeyBrowserAssert {
            request: assertion_request.clone(),
        }) {
            Ok(Response::PasskeyAssertion { assertion }) => {
                return Ok(serde_json::json!({
                    "success": true,
                    "assertion": assertion,
                }));
            }
            Ok(response) => return unexpected(response),
            Err(Error::Remote { code, message }) if code == "passkey_handoff_required" => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining <= PASSKEY_POLL_INTERVAL {
                    thread::sleep(remaining);
                    return Ok(serde_json::json!({
                        "success": false,
                        "code": code,
                        "error": message,
                    }));
                }

                thread::sleep(PASSKEY_POLL_INTERVAL);
            }
            Err(error) => {
                return Ok(serde_json::json!({
                    "success": false,
                    "code": error.code(),
                    "error": error.to_string(),
                }));
            }
        }
    }
}

fn request_attachment(request: Request, writer: &mut impl Write) -> Result<()> {
    let mut stream = send_request(request)?;
    let mut response = Zeroizing::new(Vec::new());
    let mut reader = BufReader::new(&mut stream);
    reader
        .by_ref()
        .take(MAX_DAEMON_RESPONSE_BYTES as u64 + 1)
        .read_until(b'\n', &mut response)?;
    if response.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(Error::ResponseSizeLimit("daemon response"));
    }
    match serde_json::from_slice(&response)? {
        Response::Attachment { size } => {
            let copied = std::io::copy(&mut reader.by_ref().take(size), writer)?;
            if copied != size {
                return Err(Error::AttachmentSize);
            }
            Ok(())
        }
        Response::Error { code, message } => Err(Error::Remote { code, message }),
        response => unexpected(response),
    }
}

fn request(request: Request) -> Result<Response> {
    let stream = send_request(request)?;
    let mut response = Zeroizing::new(Vec::new());
    BufReader::new(stream)
        .take(MAX_DAEMON_RESPONSE_BYTES as u64 + 1)
        .read_until(b'\n', &mut response)?;
    if response.len() > MAX_DAEMON_RESPONSE_BYTES {
        return Err(Error::ResponseSizeLimit("daemon response"));
    }
    let response: Response = serde_json::from_slice(&response)?;
    match response {
        Response::Error { code, message } => Err(Error::Remote { code, message }),
        response => Ok(response),
    }
}

fn send_request(request: Request) -> Result<UnixStream> {
    let mut stream = connect()?;
    stream.set_write_timeout(Some(DAEMON_WRITE_TIMEOUT))?;
    stream.set_read_timeout(Some(DAEMON_READ_TIMEOUT))?;
    let mut encoded = Zeroizing::new(serde_json::to_vec(&request)?);
    encoded.push(b'\n');
    stream.write_all(&encoded)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    Ok(stream)
}

fn connect() -> Result<UnixStream> {
    let socket = daemon::socket_path()?;
    if let Ok(stream) = UnixStream::connect(&socket) {
        return Ok(stream);
    }

    let start_error = start_daemon().err();
    for _ in 0..100 {
        if let Ok(stream) = UnixStream::connect(&socket) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(50));
    }

    match start_error {
        Some(error) => Err(error),
        None => Err(Error::DaemonUnavailable),
    }
}

fn start_daemon() -> Result<()> {
    let executable = env::current_exe()?
        .into_os_string()
        .into_string()
        .map_err(|_| std::io::Error::other("psst executable path is not valid UTF-8"))?;
    let command = vec![(executable.clone(), vec![executable, "daemon".into()], false)];
    let properties = vec![
        (
            "Description",
            Value::from("1Password handoff session daemon"),
        ),
        ("ExecStart", Value::from(command)),
        ("CollectMode", Value::from("inactive-or-failed")),
        ("RuntimeMaxUSec", Value::from(3_600_000_000_u64)),
        ("LimitCORE", Value::from(0_u64)),
        ("LimitCORESoft", Value::from(0_u64)),
        ("NoNewPrivileges", Value::from(true)),
        ("PrivateTmp", Value::from(true)),
        ("UMask", Value::from(0o077_u32)),
        ("StandardInput", Value::from("null")),
        ("StandardOutput", Value::from("null")),
        ("StandardError", Value::from("null")),
    ];
    let connection = Connection::session()?;
    let manager = ManagerProxyBlocking::new(&connection)?;
    manager.start_transient_unit("psst-daemon.service", Mode::Fail, &properties, &[])?;
    Ok(())
}

fn unexpected<T>(response: Response) -> Result<T> {
    Err(Error::Unavailable(match response {
        Response::Error { message, .. } => message,
        _ => "daemon returned an unexpected response".into(),
    }))
}

fn refuse_terminal(is_terminal: bool) -> Result<()> {
    if is_terminal {
        return Err(Error::SecretToTerminal);
    }

    Ok(())
}

fn refuse_share_terminal(is_terminal: bool) -> Result<()> {
    if is_terminal {
        return Err(Error::ShareFromTerminal);
    }

    Ok(())
}

fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // setrlimit only reads this value for the duration of the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0 {
        return Ok(());
    }

    Err(std::io::Error::last_os_error().into())
}

fn write_error(code: &str, message: &str) {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = writeln!(stderr, "error {code}: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_secret_output_to_a_terminal() {
        assert!(matches!(
            refuse_terminal(true),
            Err(Error::SecretToTerminal)
        ));
        assert!(refuse_terminal(false).is_ok());
    }

    #[test]
    fn refuses_share_input_from_a_terminal() {
        assert!(matches!(
            refuse_share_terminal(true),
            Err(Error::ShareFromTerminal)
        ));
        assert!(refuse_share_terminal(false).is_ok());
    }

    #[test]
    fn runtime_and_usage_errors_have_stable_codes() {
        assert_eq!(
            format!(
                "error {}: {}",
                Error::SecretToTerminal.code(),
                Error::SecretToTerminal
            ),
            "error secret_to_terminal: refusing to write a secret to a terminal; pipe or redirect stdout"
        );

        let usage = match Cli::try_parse_from(["psst", "unknown"]) {
            Ok(_) => panic!("unknown command was accepted"),
            Err(error) => error,
        };
        assert!(usage.use_stderr());
        assert_eq!(usage.exit_code(), 2);
        let message = usage.to_string();
        let message = message.strip_prefix("error: ").unwrap_or(&message);
        assert!(
            format!("error cli_usage: {message}")
                .starts_with("error cli_usage: unrecognized subcommand")
        );
    }
}
