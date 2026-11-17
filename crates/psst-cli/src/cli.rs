use std::{
    collections::HashSet,
    io::{IsTerminal, Read, Write},
    net::SocketAddr,
    os::fd::AsFd,
};

use crate::daemon::dbus::PsstProxyBlocking;
use clap::{Parser, Subcommand};
use zbus::{blocking::Connection, zvariant::Fd};
use zeroize::Zeroizing;

use crate::{
    browser, daemon,
    domain::item::ItemSummary,
    error::{Error, Result},
    skill,
};

const MAX_SHARE_LINK_BYTES: usize = 4 * 1024;
const DEFAULT_SHARING_ADDRESS: &str = "127.0.0.1:7337";
const DEFAULT_BROWSER_ADDRESS: &str = "127.0.0.1:7338";

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
    /// List active sessions without secret values.
    Sessions {
        /// Follow active and newly created sessions until interrupted.
        #[arg(long)]
        live: bool,
    },
    /// List available fields and passkey metadata without secret values.
    Fields {
        /// Opaque identifier returned by `psst open` or `psst sessions`.
        session: String,
    },
    /// Write one field value to stdout.
    Get {
        /// Opaque session identifier.
        session: String,
        /// Exact selector returned by `psst fields`.
        #[arg(allow_hyphen_values = true)]
        field: String,
    },
    /// Decrypt an attached file and write its bytes to stdout.
    Download {
        /// Opaque session identifier.
        session: String,
        /// Exact file selector returned by `psst fields`.
        #[arg(allow_hyphen_values = true)]
        field: String,
    },
    /// Complete a browser passkey request.
    Passkey {
        #[command(subcommand)]
        command: PasskeyCommand,
    },
    /// Install the signed Chrome integration for a container browser.
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    /// Print the version-matched usage skill for agents and automation.
    Skill,
    /// Destroy a session immediately.
    Close {
        /// Opaque session identifier.
        session: String,
    },
    #[command(hide = true)]
    Daemon {
        #[arg(long, default_value = DEFAULT_SHARING_ADDRESS)]
        sharing_listen: SocketAddr,
        #[arg(long, default_value = DEFAULT_BROWSER_ADDRESS)]
        browser_listen: SocketAddr,
    },
}

#[derive(Subcommand)]
enum PasskeyCommand {
    /// Complete one browser passkey request.
    Handoff {
        /// Opaque session identifier.
        session: String,
        /// Browser request ID displayed by the psst prompt.
        request_id: String,
    },
}

#[derive(Subcommand)]
enum BrowserCommand {
    /// Install or refresh the signed container browser integration.
    Install,
    /// Report generated browser artifacts.
    Status,
    #[command(hide = true)]
    Schema,
}

pub fn main() {
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
        Command::Daemon {
            sharing_listen,
            browser_listen,
        } => tokio::runtime::Runtime::new()?.block_on(daemon::run(sharing_listen, browser_listen)),
        Command::Open => open(),
        Command::Sessions { live: true } => live_sessions(),
        Command::Sessions { live: false } => {
            with_proxy(|proxy| write_json(&proxy.list_sessions().map_err(Error::from)?))
        }
        Command::Fields { session } => with_proxy(|proxy| {
            let (fields, passkeys) = proxy.fields(&session).map_err(Error::from)?;
            let items = fields
                .into_iter()
                .map(ItemSummary::Field)
                .chain(passkeys.into_iter().map(ItemSummary::Passkey))
                .collect::<Vec<_>>();
            write_json(&items)
        }),
        Command::Get { session, field } => write_secret(|proxy, output| {
            proxy
                .get(&session, &field, Fd::from(output.as_fd()))
                .map_err(Error::from)
        }),
        Command::Download { session, field } => write_secret(|proxy, output| {
            proxy
                .download(&session, &field, Fd::from(output.as_fd()))
                .map_err(Error::from)
        }),
        Command::Passkey { command } => run_passkey(command),
        Command::Browser { command } => run_browser(command),
        Command::Skill => skill::write(std::io::stdout().lock()),
        Command::Close { session } => {
            with_proxy(|proxy| proxy.close(&session).map_err(Error::from))
        }
    }
}

fn live_sessions() -> Result<()> {
    with_proxy(|proxy| {
        let mut output = std::io::stdout().lock();
        let mut seen = HashSet::new();
        for session in proxy.list_sessions().map_err(Error::from)? {
            write_json_line(&mut output, &session)?;
            seen.insert(session.id);
        }
        loop {
            let known_ids = seen.iter().cloned().collect();
            let session = proxy.wait_session(known_ids).map_err(Error::from)?;
            write_json_line(&mut output, &session)?;
            seen.insert(session.id);
        }
    })
}

fn write_json_line(mut output: impl Write, value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}

fn open() -> Result<()> {
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

    with_proxy(|proxy| {
        let session = proxy.open(url.trim()).map_err(Error::from)?;
        writeln!(std::io::stdout().lock(), "{session}")?;
        Ok(())
    })
}

fn run_passkey(command: PasskeyCommand) -> Result<()> {
    match command {
        PasskeyCommand::Handoff {
            session,
            request_id,
        } => with_proxy(|proxy| {
            proxy
                .passkey_handoff(&session, &request_id)
                .map_err(Error::from)
        }),
    }
}

fn run_browser(command: BrowserCommand) -> Result<()> {
    match command {
        BrowserCommand::Install => browser::install(),
        BrowserCommand::Status => write_json(&browser::status()?),
        BrowserCommand::Schema => {
            let schemas = daemon::browser_protocol::zod()
                .map_err(|error| Error::BrowserSchema(error.to_string()))?;
            print!("{schemas}");
            Ok(())
        }
    }
}

fn write_secret(
    operation: impl FnOnce(&PsstProxyBlocking<'_>, &std::io::Stdout) -> Result<()>,
) -> Result<()> {
    let output = std::io::stdout();
    refuse_terminal(output.is_terminal())?;
    with_proxy(|proxy| operation(proxy, &output))
}

fn with_proxy<T>(operation: impl FnOnce(&PsstProxyBlocking<'_>) -> Result<T>) -> Result<T> {
    let connection = Connection::system()?;
    let proxy = PsstProxyBlocking::new(&connection)?;
    operation(&proxy)
}

fn write_json(value: &impl serde::Serialize) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
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
}
