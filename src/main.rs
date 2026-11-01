mod client;
mod crypto;
mod daemon;
mod error;
mod item;
mod protocol;

use std::{
    env,
    io::{BufRead, BufReader, IsTerminal, Read, Write},
    os::unix::net::UnixStream,
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::Duration,
};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    protocol::{Request, Response},
};

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
    Fields { session: String },
    /// Write one field value to stdout.
    Get { session: String, field: String },
    /// Destroy a session immediately.
    Close { session: String },
    #[command(hide = true)]
    Daemon,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("psst: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Daemon => daemon::run(),
        Command::Open => {
            let mut url = String::new();
            std::io::stdin().read_to_string(&mut url)?;
            if url.trim().is_empty() {
                return Err(Error::InvalidLink("stdin was empty".into()));
            }

            match request(Request::Open { url })? {
                Response::Opened { session } => println!("{session}"),
                response => return unexpected(response),
            }
            Ok(())
        }
        Command::Fields { session } => match request(Request::Fields { session })? {
            Response::Fields { fields } => {
                serde_json::to_writer_pretty(std::io::stdout(), &fields)?;
                println!();
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
        Command::Close { session } => match request(Request::Close { session })? {
            Response::Closed => Ok(()),
            response => unexpected(response),
        },
    }
}

fn request(request: Request) -> Result<Response> {
    let mut stream = connect()?;
    let mut encoded = Zeroizing::new(serde_json::to_vec(&request)?);
    encoded.push(b'\n');
    stream.write_all(&encoded)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = Zeroizing::new(Vec::new());
    BufReader::new(stream).read_until(b'\n', &mut response)?;
    let response: Response = serde_json::from_slice(&response)?;
    match response {
        Response::Error { message } => Err(Error::Remote(message)),
        response => Ok(response),
    }
}

fn connect() -> Result<UnixStream> {
    let socket = daemon::socket_path()?;
    if let Ok(stream) = UnixStream::connect(&socket) {
        return Ok(stream);
    }

    start_daemon()?;
    for _ in 0..50 {
        if let Ok(stream) = UnixStream::connect(&socket) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(50));
    }

    Err(Error::DaemonUnavailable)
}

fn start_daemon() -> Result<()> {
    let executable = env::current_exe()?;
    let status = ProcessCommand::new("systemd-run")
        .args([
            "--user",
            "--collect",
            "--quiet",
            "--unit=psst-daemon",
            "--description=1Password handoff session daemon",
            "--property=RuntimeMaxSec=1h",
            "--property=LimitCORE=0",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--property=UMask=0077",
        ])
        .arg(executable)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(Error::DaemonUnavailable)
    }
}

fn unexpected<T>(response: Response) -> Result<T> {
    Err(Error::Unavailable(match response {
        Response::Error { message } => message,
        _ => "daemon returned an unexpected response".into(),
    }))
}

fn refuse_terminal(is_terminal: bool) -> Result<()> {
    if is_terminal {
        return Err(Error::SecretToTerminal);
    }

    Ok(())
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
