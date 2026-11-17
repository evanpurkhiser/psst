use serde::{Deserialize, Serialize};

pub const EXTENSION_ID: &str = "ldeghfipmipljkcmpjceopakklcfdcnf";
pub const EXTENSION_ORIGIN: &str = "chrome-extension://ldeghfipmipljkcmpjceopakklcfdcnf/";
pub const NATIVE_HOST: &str = "com.evanpurkhiser.psst";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionRequest {
    #[serde(default)]
    pub request_id: Option<String>,
    pub origin: String,
    pub challenge: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub allow_credentials: Vec<String>,
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;

    #[test]
    fn assertion_requests_use_the_browser_wire_format() {
        let request: AssertionRequest = serde_json::from_value(serde_json::json!({
            "requestId": "request",
            "origin": "https://example.com",
            "challenge": "challenge",
            "rpId": "example.com",
            "allowCredentials": ["credential"],
        }))
        .unwrap();

        assert_eq!(request.request_id.as_deref(), Some("request"));
        assert_eq!(request.rp_id.as_deref(), Some("example.com"));
        assert_eq!(request.allow_credentials, ["credential"]);
    }
}
