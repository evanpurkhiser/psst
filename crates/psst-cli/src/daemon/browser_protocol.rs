use serde::{Deserialize, Serialize};
use specta::{Type, Types};
use specta_zod::Zod;

use crate::domain::webauthn::Assertion;

pub const EXTENSION_ID: &str = "ldeghfipmipljkcmpjceopakklcfdcnf";
pub const EXTENSION_ORIGIN: &str = "chrome-extension://ldeghfipmipljkcmpjceopakklcfdcnf";

#[derive(Clone, Debug, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct AssertionRequest {
    pub request_id: String,
    pub origin: String,
    pub challenge: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub allow_credentials: Vec<String>,
}

#[derive(Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub capability: String,
}

#[derive(Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Type)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PasskeyResult {
    Complete { assertion: Assertion },
    Failed { code: String, message: String },
    Expired,
}

pub fn zod() -> Result<String, specta_zod::Error> {
    let types = Types::default()
        .register::<AssertionRequest>()
        .register::<Registration>()
        .register::<ErrorResponse>()
        .register::<PasskeyResult>();
    Zod::default()
        .framework_prelude(
            "import {z} from 'zod';\n// Generated from the Rust browser protocol. Do not edit.",
        )
        .export(&types, specta_serde::Format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_requests_use_the_browser_wire_format() {
        let request: AssertionRequest = serde_json::from_value(serde_json::json!({
            "requestId": "410e26bd-7701-4481-8b7e-9f4215edbd8d",
            "origin": "https://example.com",
            "challenge": "challenge",
            "rpId": "example.com",
            "allowCredentials": ["credential"],
        }))
        .unwrap();

        assert_eq!(request.rp_id.as_deref(), Some("example.com"));
        assert_eq!(request.allow_credentials, ["credential"]);
    }
}
