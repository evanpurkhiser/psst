use std::io::{Read, Write};

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const PROTOCOL: &str = "agent-browser.plugin.v1";
const CREDENTIAL_CAPABILITY: &str = "credential.read";

pub struct Request {
    pub session: String,
}

#[derive(Deserialize)]
struct Envelope {
    protocol: String,
    #[serde(rename = "type")]
    kind: String,
    capability: String,
    request: CredentialRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialRequest {
    item_ref: Option<String>,
}

#[derive(Serialize)]
struct CredentialResponse<'a> {
    protocol: &'static str,
    success: bool,
    credential: Credential<'a>,
}

#[derive(Serialize)]
struct Credential<'a> {
    username: &'a str,
    password: &'a str,
}

pub fn read(input: impl Read) -> Result<Request> {
    let mut envelope: Envelope = serde_json::from_reader(input)?;

    if envelope.protocol != PROTOCOL {
        return Err(Error::Unavailable("unsupported plugin protocol".into()));
    }

    if envelope.kind != "credential.resolve" || envelope.capability != CREDENTIAL_CAPABILITY {
        return Err(Error::Unavailable("unsupported plugin request".into()));
    }

    let session = envelope
        .request
        .item_ref
        .take()
        .filter(|session| !session.is_empty())
        .ok_or_else(|| Error::Unavailable("credential request is missing itemRef".into()))?;

    Ok(Request { session })
}

pub fn write_credential(mut output: impl Write, username: &str, password: &str) -> Result<()> {
    serde_json::to_writer(
        &mut output,
        &CredentialResponse {
            protocol: PROTOCOL,
            success: true,
            credential: Credential { username, password },
        },
    )?;

    Ok(())
}

pub fn error_response(error: &Error) -> Value {
    json!({
        "protocol": PROTOCOL,
        "success": false,
        "error": "credential resolution failed",
        "code": error.code()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_credential_request() {
        let request = read(
            &br#"{
                "protocol":"agent-browser.plugin.v1",
                "type":"credential.resolve",
                "capability":"credential.read",
                "request":{"itemRef":"opaque-session","url":"https://example.com/login"}
            }"#[..],
        )
        .unwrap();

        assert_eq!(request.session, "opaque-session");
    }

    #[test]
    fn writes_credentials() {
        let mut output = Vec::new();

        write_credential(&mut output, "user@example.com", "secret").unwrap();

        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            json!({
                "protocol": PROTOCOL,
                "success": true,
                "credential": {
                    "username": "user@example.com",
                    "password": "secret"
                }
            })
        );
    }
}
