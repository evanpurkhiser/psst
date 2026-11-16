use std::io::Write;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{Error, Result},
    item::SecretValue,
};

const PROTOCOL: &str = "agent-browser.plugin.v1";
const CAPABILITY: &str = "credential.read";

pub struct Request {
    pub session: Zeroizing<String>,
    pub url: Option<String>,
}

#[derive(Deserialize)]
struct Envelope {
    protocol: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    capability: String,
    #[serde(default)]
    request: CredentialRequest,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialRequest {
    item_ref: Option<String>,
    url: Option<String>,
}

#[derive(Serialize)]
struct CredentialResponse<'a> {
    protocol: &'static str,
    success: bool,
    credential: Credential<'a>,
}

#[derive(Serialize)]
struct Credential<'a> {
    username: &'a SecretValue,
    password: &'a SecretValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
}

impl Drop for CredentialRequest {
    fn drop(&mut self) {
        self.item_ref.zeroize();
    }
}

pub fn parse(input: &[u8]) -> Result<Request> {
    let mut envelope: Envelope = serde_json::from_slice(input)?;
    if envelope.protocol != PROTOCOL {
        return Err(Error::Unavailable("unsupported plugin protocol".into()));
    }
    if envelope.capability != CAPABILITY || envelope.kind != "credential.resolve" {
        return Err(Error::Unavailable("unsupported plugin request".into()));
    }

    let session = envelope
        .request
        .item_ref
        .take()
        .filter(|session| !session.is_empty())
        .ok_or_else(|| Error::Unavailable("credential request is missing itemRef".into()))?;

    Ok(Request {
        session: Zeroizing::new(session),
        url: envelope.request.url.take(),
    })
}

pub fn write_credential_response(
    mut output: impl Write,
    username: &SecretValue,
    password: &SecretValue,
    url: Option<&str>,
) -> Result<()> {
    serde_json::to_writer(
        &mut output,
        &CredentialResponse {
            protocol: PROTOCOL,
            success: true,
            credential: Credential {
                username,
                password,
                url,
            },
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
    fn resolves_a_session_reference_and_url() {
        let request = parse(
            br#"{
                "protocol":"agent-browser.plugin.v1",
                "type":"credential.resolve",
                "capability":"credential.read",
                "request":{
                    "profileName":"work",
                    "itemRef":"opaque-session",
                    "url":"https://example.com/login"
                }
            }"#,
        )
        .expect("valid request");

        assert_eq!(request.session.as_str(), "opaque-session");
        assert_eq!(request.url.as_deref(), Some("https://example.com/login"));
    }

    #[test]
    fn rejects_requests_without_a_session_reference() {
        let input = br#"{
            "protocol":"agent-browser.plugin.v1",
            "type":"credential.resolve",
            "capability":"credential.read",
            "request":{"profileName":"work"}
        }"#;

        assert!(matches!(parse(input), Err(Error::Unavailable(_))));
    }

    #[test]
    fn writes_agent_browser_credentials() {
        let username = serde_json::from_value(json!("user@example.com")).expect("username");
        let password = serde_json::from_value(json!("secret")).expect("password");
        let mut output = Vec::new();

        write_credential_response(
            &mut output,
            &username,
            &password,
            Some("https://example.com/login"),
        )
        .expect("response");

        assert_eq!(
            serde_json::from_slice::<Value>(&output).expect("valid JSON"),
            json!({
                "protocol": "agent-browser.plugin.v1",
                "success": true,
                "credential": {
                    "username": "user@example.com",
                    "password": "secret",
                    "url": "https://example.com/login"
                }
            })
        );
    }
}
