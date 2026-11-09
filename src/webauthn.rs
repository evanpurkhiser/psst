use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

const ASSERTION_FLAGS: u8 = 0x01 | 0x04 | 0x08 | 0x10;

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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSummary {
    pub credential_id: String,
    pub rp_id: String,
    pub credential_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub authenticator_attachment: String,
    pub response: AssertionResponse,
    pub client_extension_results: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

#[derive(Deserialize)]
struct Overview {
    passkey: Option<PasskeyOverview>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyOverview {
    credential_id: String,
    rp_id: Option<String>,
}

impl Drop for PasskeyOverview {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.rp_id.zeroize();
    }
}

#[derive(Deserialize)]
struct Details {
    passkey: Option<PasskeyDetails>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyDetails {
    #[serde(rename = "type")]
    kind: String,
    private_key: String,
    user_handle: String,
}

#[derive(Deserialize)]
struct JsonWebKey {
    kty: String,
    crv: String,
    d: String,
}

impl Drop for JsonWebKey {
    fn drop(&mut self) {
        self.kty.zeroize();
        self.crv.zeroize();
        self.d.zeroize();
    }
}

impl Drop for PasskeyDetails {
    fn drop(&mut self) {
        self.kind.zeroize();
        self.private_key.zeroize();
        self.user_handle.zeroize();
    }
}

pub struct Passkey {
    credential_id: String,
    rp_id: String,
    private_key: String,
    user_handle: String,
}

impl Passkey {
    pub fn from_item(overview: &[u8], details: &[u8]) -> Result<Self> {
        let overview: Overview = serde_json::from_slice(overview)?;
        let details: Details = serde_json::from_slice(details)?;
        let mut overview = overview.passkey.ok_or(Error::PasskeyUnavailable)?;
        let mut details = details.passkey.ok_or(Error::PasskeyUnavailable)?;

        if details.kind != "webauthn" {
            return Err(Error::UnsupportedPasskey);
        }

        let rp_id = overview
            .rp_id
            .take()
            .ok_or(Error::UnsupportedPasskey)?
            .to_ascii_lowercase();
        validate_rp_id(&rp_id)?;
        if decode_base64url(&overview.credential_id).is_none() {
            return Err(Error::UnsupportedPasskey);
        }
        let user_handle = decode_base64url(&details.user_handle)
            .filter(|value| value.len() <= 64)
            .ok_or(Error::UnsupportedPasskey)?;
        drop(user_handle);

        Ok(Self {
            credential_id: std::mem::take(&mut overview.credential_id),
            rp_id,
            private_key: std::mem::take(&mut details.private_key),
            user_handle: std::mem::take(&mut details.user_handle),
        })
    }

    pub fn describe(&self) -> CredentialSummary {
        CredentialSummary {
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            credential_type: "public-key".into(),
        }
    }

    pub fn assert(&self, request: &AssertionRequest) -> Result<Assertion> {
        let origin = validate_origin(&request.origin, &self.rp_id)?;
        validate_request(request, &self.credential_id, &self.rp_id)?;

        let client_data = Zeroizing::new(serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": request.challenge,
            "origin": origin,
            "crossOrigin": false,
        }))?);
        let mut authenticator_data = Zeroizing::new(Vec::with_capacity(37));
        authenticator_data.extend_from_slice(&Sha256::digest(self.rp_id.as_bytes()));
        authenticator_data.push(ASSERTION_FLAGS);
        authenticator_data.extend_from_slice(&0_u32.to_be_bytes());

        let client_data_hash = Sha256::digest(client_data.as_slice());
        let mut signed_data = Zeroizing::new(Vec::with_capacity(69));
        signed_data.extend_from_slice(&authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        let signing_key = decode_signing_key(&self.private_key)?;
        let signature: Signature = signing_key.sign(&signed_data);
        let signature = Zeroizing::new(signature.to_der().as_bytes().to_vec());

        Ok(Assertion {
            id: self.credential_id.clone(),
            raw_id: self.credential_id.clone(),
            kind: "public-key".into(),
            authenticator_attachment: "platform".into(),
            response: AssertionResponse {
                client_data_json: URL_SAFE_NO_PAD.encode(&client_data),
                authenticator_data: URL_SAFE_NO_PAD.encode(&authenticator_data),
                signature: URL_SAFE_NO_PAD.encode(&signature),
                user_handle: self.user_handle.clone(),
            },
            client_extension_results: json!({}),
        })
    }
}

impl Drop for Passkey {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        self.rp_id.zeroize();
        self.private_key.zeroize();
        self.user_handle.zeroize();
    }
}

fn validate_request(request: &AssertionRequest, credential_id: &str, rp_id: &str) -> Result<()> {
    decode_base64url(&request.challenge)
        .filter(|challenge| !challenge.is_empty())
        .ok_or_else(|| Error::WebAuthnRequest("challenge is not valid base64url".into()))?;

    if request
        .rp_id
        .as_deref()
        .is_some_and(|requested| requested.to_ascii_lowercase() != rp_id)
    {
        return Err(Error::WebAuthnRequest(
            "relying party does not match the passkey".into(),
        ));
    }

    if !request.allow_credentials.is_empty()
        && !request
            .allow_credentials
            .iter()
            .any(|allowed| allowed == credential_id)
    {
        return Err(Error::WebAuthnRequest(
            "the passkey is not allowed by this request".into(),
        ));
    }

    Ok(())
}

fn validate_rp_id(rp_id: &str) -> Result<()> {
    if rp_id.is_empty() || rp_id.starts_with('.') || rp_id.ends_with('.') {
        return Err(Error::UnsupportedPasskey);
    }
    let url = Url::parse(&format!("https://{rp_id}/")).map_err(|_| Error::UnsupportedPasskey)?;
    if url.host_str() != Some(rp_id) || url.port().is_some() {
        return Err(Error::UnsupportedPasskey);
    }

    Ok(())
}

fn validate_origin(origin: &str, rp_id: &str) -> Result<String> {
    let url = Url::parse(origin)
        .map_err(|_| Error::WebAuthnRequest("origin is not a valid URL".into()))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::WebAuthnRequest(
            "origin must be an HTTPS origin without a path".into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| Error::WebAuthnRequest("origin does not contain a host".into()))?
        .to_ascii_lowercase();
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return Err(Error::WebAuthnRequest(
            "origin is outside the passkey relying party".into(),
        ));
    }

    Ok(url.origin().ascii_serialization())
}

fn decode_signing_key(value: &str) -> Result<SigningKey> {
    let value = value.trim();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let bytes = Zeroizing::new(
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let text = std::str::from_utf8(pair).map_err(|_| Error::PasskeyKey)?;
                    u8::from_str_radix(text, 16).map_err(|_| Error::PasskeyKey)
                })
                .collect::<Result<Vec<_>>>()?,
        );
        return SigningKey::from_slice(&bytes).map_err(|_| Error::PasskeyKey);
    }

    let encoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| Error::PasskeyKey)?,
    );
    let key = serde_json::from_slice(encoded.as_slice()).map_err(|_| Error::PasskeyKey)?;
    decode_json_web_key(key)
}

fn decode_json_web_key(key: JsonWebKey) -> Result<SigningKey> {
    if key.kty != "EC" || key.crv != "P-256" {
        return Err(Error::PasskeyKey);
    }

    let scalar = Zeroizing::new(
        decode_base64url(&key.d)
            .filter(|value| value.len() == 32)
            .ok_or(Error::PasskeyKey)?,
    );
    SigningKey::from_slice(&scalar).map_err(|_| Error::PasskeyKey)
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .or_else(|_| URL_SAFE.decode(value.as_bytes()))
        .ok()
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use serde_json::Value;

    use super::*;

    fn passkey() -> Passkey {
        Passkey {
            credential_id: "Y3JlZGVudGlhbA".into(),
            rp_id: "example.com".into(),
            private_key: "07".repeat(32),
            user_handle: "dXNlcg".into(),
        }
    }

    fn request() -> AssertionRequest {
        AssertionRequest {
            request_id: None,
            origin: "https://login.example.com".into(),
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: Some("example.com".into()),
            allow_credentials: vec!["Y3JlZGVudGlhbA".into()],
        }
    }

    #[test]
    fn parses_passkeys_outside_normal_item_fields() {
        let overview = br#"{"passkey":{"credentialId":"Y3JlZGVudGlhbA","rpId":"example.com"}}"#;
        let details = br#"{"passkey":{"type":"webauthn","createdAt":1,"privateKey":"key","userHandle":"dXNlcg"},"sections":[]}"#;
        let passkey = Passkey::from_item(overview, details).expect("valid passkey item");

        assert_eq!(passkey.describe().credential_id, "Y3JlZGVudGlhbA");
        assert_eq!(passkey.describe().rp_id, "example.com");
    }

    #[test]
    fn creates_a_verifiable_assertion() {
        let passkey = passkey();
        let assertion = passkey.assert(&request()).expect("valid assertion");
        let client_data = decode_base64url(&assertion.response.client_data_json).unwrap();
        let authenticator_data = decode_base64url(&assertion.response.authenticator_data).unwrap();
        let signature = Signature::from_der(
            &decode_base64url(&assertion.response.signature).expect("encoded signature"),
        )
        .expect("DER signature");
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&Sha256::digest(&client_data));
        let verifying_key = VerifyingKey::from(&decode_signing_key(&passkey.private_key).unwrap());

        verifying_key
            .verify(&signed_data, &signature)
            .expect("valid signature");
        assert_eq!(authenticator_data[32], ASSERTION_FLAGS);
        let client_data: Value = serde_json::from_slice(&client_data).unwrap();
        assert_eq!(client_data["origin"], "https://login.example.com");

        let serialized = serde_json::to_value(&assertion).unwrap();
        assert!(serialized["response"]["clientDataJSON"].is_string());
        assert!(serialized["response"].get("clientDataJson").is_none());
    }

    #[test]
    fn decodes_hex_scalar_keys() {
        let value = "07".repeat(32);

        decode_signing_key(&value).expect("hex scalar key");
    }

    #[test]
    fn decodes_base64url_json_web_keys() {
        let value = format!(
            r#"{{"kty":"EC","crv":"P-256","d":"{}"}}"#,
            URL_SAFE_NO_PAD.encode([7; 32])
        );
        let encoded = URL_SAFE_NO_PAD.encode(value);

        decode_signing_key(&encoded).expect("base64url P-256 JSON Web Key");
    }

    #[test]
    fn rejects_origins_outside_the_relying_party() {
        let mut request = request();
        request.origin = "https://example.net".into();

        assert!(matches!(
            passkey().assert(&request),
            Err(Error::WebAuthnRequest(message)) if message.contains("outside")
        ));
    }

    #[test]
    fn rejects_unlisted_credentials() {
        let mut request = request();
        request.allow_credentials = vec!["different".into()];

        assert!(matches!(
            passkey().assert(&request),
            Err(Error::WebAuthnRequest(message)) if message.contains("not allowed")
        ));
    }
}
