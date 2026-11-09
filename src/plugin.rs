use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const PROTOCOL: &str = "agent-browser.plugin.v1";
pub const CAPABILITY: &str = "launch.mutate";

#[derive(Debug)]
pub enum Action {
    Manifest,
    Launch,
}

#[derive(Deserialize)]
struct Envelope {
    protocol: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    capability: String,
    #[serde(default)]
    request: Value,
}

impl Drop for Envelope {
    fn drop(&mut self) {
        self.protocol.zeroize();
        self.kind.zeroize();
        self.capability.zeroize();
        zeroize_value(&mut self.request);
    }
}

pub fn parse(input: &[u8]) -> Result<Action> {
    let envelope: Envelope = serde_json::from_slice(input)?;
    if envelope.protocol != PROTOCOL {
        return Err(Error::WebAuthnRequest("unsupported plugin protocol".into()));
    }
    if envelope.kind == "plugin.manifest" {
        return Ok(Action::Manifest);
    }
    if envelope.capability != CAPABILITY {
        return Err(Error::WebAuthnRequest(
            "unsupported plugin capability".into(),
        ));
    }
    if envelope.kind != "launch.mutate" {
        return Err(Error::WebAuthnRequest(
            "unsupported plugin request type".into(),
        ));
    }

    Ok(Action::Launch)
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_value),
        Value::Object(values) => {
            let values = std::mem::take(values);
            for (mut key, mut value) in values {
                key.zeroize();
                zeroize_value(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub fn manifest_response() -> Value {
    json!({
        "protocol": PROTOCOL,
        "success": true,
        "manifest": {
            "name": "psst",
            "description": "Load the PSST passkey extension in local Chrome sessions",
            "capabilities": [CAPABILITY]
        }
    })
}

pub fn launch_response(extension: &Path) -> Value {
    json!({
        "protocol": PROTOCOL,
        "success": true,
        "launch": {
            "extensions": [extension]
        }
    })
}

pub fn error_response(error: &Error) -> Value {
    json!({
        "protocol": PROTOCOL,
        "success": false,
        "error": error.to_string(),
        "code": error.code()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_only_the_launch_mutator_capability() {
        assert_eq!(
            manifest_response()["manifest"]["capabilities"],
            json!(["launch.mutate"])
        );
    }

    #[test]
    fn accepts_launch_mutation_requests() {
        let input = br#"{
            "protocol":"agent-browser.plugin.v1",
            "type":"launch.mutate",
            "capability":"launch.mutate",
            "request":{}
        }"#;

        assert!(matches!(parse(input), Ok(Action::Launch)));
    }

    #[test]
    fn rejects_the_generic_command_capability() {
        let input = br#"{
            "protocol":"agent-browser.plugin.v1",
            "type":"launch.mutate",
            "capability":"command.run",
            "request":{}
        }"#;

        assert!(matches!(parse(input), Err(Error::WebAuthnRequest(_))));
    }
}
