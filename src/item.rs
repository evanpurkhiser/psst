use std::{
    collections::{HashMap, HashSet},
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use totp_rs::{Totp, TotpError as ProtocolError};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    attachment::Attachment,
    error::{Error, Result, TotpError},
};

#[derive(Debug, Deserialize, Serialize)]
pub struct FieldSummary {
    pub selector: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Deserialize)]
struct Details {
    #[serde(default)]
    fields: Vec<Field>,
    #[serde(default)]
    sections: Vec<Section>,
}

#[derive(Deserialize)]
struct Section {
    #[serde(default)]
    fields: Vec<Field>,
}

#[derive(Deserialize)]
struct Field {
    #[serde(default, rename = "n", alias = "name")]
    name: String,
    #[serde(default, rename = "t", alias = "title")]
    label: String,
    #[serde(default, rename = "k", alias = "type")]
    kind: String,
    #[serde(default, rename = "v", alias = "value")]
    value: Option<Value>,
    #[serde(default)]
    designation: String,
}

impl Drop for Field {
    fn drop(&mut self) {
        self.name.zeroize();
        self.label.zeroize();
        self.kind.zeroize();
        self.designation.zeroize();
        if let Some(value) = &mut self.value {
            zeroize_value(value);
        }
    }
}

pub struct SecretValue(Value);

impl SecretValue {
    pub fn write_to(self, writer: &mut impl Write) -> Result<()> {
        match &self.0 {
            Value::String(value) => writer.write_all(value.as_bytes())?,
            value => serde_json::to_writer(writer, value)?,
        }
        Ok(())
    }
}

impl Serialize for SecretValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self)
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        zeroize_value(&mut self.0);
    }
}

pub fn list_fields(json: &[u8]) -> Result<Vec<FieldSummary>> {
    let details: Details = serde_json::from_slice(json)?;
    Ok(project_fields(details)
        .into_iter()
        .map(|field| {
            let attachment = attachment_from_field(&field.field).ok();
            FieldSummary {
                selector: field.selector,
                label: field_label(&field.field).into(),
                kind: field_kind(&field.field).into(),
                filename: attachment.as_ref().map(|file| file.file_name.clone()),
                size: attachment.as_ref().map(|file| file.unencrypted_size),
            }
        })
        .collect())
}

pub fn get_field(json: &[u8], selector: &str) -> Result<SecretValue> {
    let details: Details = serde_json::from_slice(json)?;
    let mut field = project_fields(details)
        .into_iter()
        .find(|field| field.selector == selector)
        .ok_or_else(|| Error::FieldNotFound(selector.into()))?;
    if field.field.kind == "file" {
        return Err(Error::FileRequiresDownload(selector.into()));
    }
    let value = field
        .field
        .value
        .take()
        .ok_or_else(|| Error::FieldNotFound(selector.into()))?;

    Ok(SecretValue(format_value(&field.field, value)?))
}

pub fn get_attachment(json: &[u8], selector: &str) -> Result<Attachment> {
    let details: Details = serde_json::from_slice(json)?;
    let field = project_fields(details)
        .into_iter()
        .find(|field| field.selector == selector)
        .ok_or_else(|| Error::FieldNotFound(selector.into()))?;
    if field.field.kind != "file" {
        return Err(Error::FieldNotFile(selector.into()));
    }

    attachment_from_field(&field.field).map_err(|_| Error::UnsupportedAttachment)
}

fn attachment_from_field(field: &Field) -> Result<Attachment> {
    let value = field.value.as_ref().ok_or(Error::UnsupportedAttachment)?;
    Ok(serde_json::from_value(value.clone())?)
}

struct ProjectedField {
    selector: String,
    field: Field,
}

fn project_fields(details: Details) -> Vec<ProjectedField> {
    let mut used = HashSet::new();
    let mut next_suffix = HashMap::<String, usize>::new();

    details
        .fields
        .into_iter()
        .chain(
            details
                .sections
                .into_iter()
                .flat_map(|section| section.fields),
        )
        .filter(|field| field.value.as_ref().is_some_and(is_populated))
        .map(|field| {
            let base = selector_base(&field);
            let mut suffix = *next_suffix.entry(base.clone()).or_insert(1);
            let selector = loop {
                let candidate = if suffix == 1 {
                    base.clone()
                } else {
                    format!("{base}-{suffix}")
                };
                suffix += 1;
                if used.insert(candidate.clone()) {
                    break candidate;
                }
            };
            next_suffix.insert(base, suffix);

            ProjectedField { selector, field }
        })
        .collect()
}

fn selector_base(field: &Field) -> String {
    if !field.designation.is_empty() {
        return field.designation.clone();
    }

    if !field.name.is_empty() {
        return field.name.clone();
    }

    match slug(&field.label) {
        slug if slug.is_empty() => "field".into(),
        slug => slug,
    }
}

fn field_label(field: &Field) -> &str {
    if !field.label.is_empty() {
        return &field.label;
    }
    if !field.designation.is_empty() {
        return &field.designation;
    }
    &field.name
}

fn field_kind(field: &Field) -> &str {
    match field.kind.as_str() {
        "P" => "concealed",
        "T" | "E" => "string",
        kind => kind,
    }
}

fn format_value(field: &Field, value: Value) -> Result<Value> {
    if field.kind == "totp" || (field.kind == "concealed" && field.name.starts_with("TOTP_")) {
        let uri = value.as_str().ok_or_else(|| Error::InvalidTotp {
            field: field.label.clone(),
            reason: TotpError::ValueType,
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidTotp {
                field: field.label.clone(),
                reason: TotpError::Clock,
            })?
            .as_secs();
        return totp_at(uri, now)
            .map(Value::String)
            .map_err(|reason| Error::InvalidTotp {
                field: field.label.clone(),
                reason,
            });
    }

    if field.kind != "monthYear" {
        return Ok(value);
    }
    let Some(month_year) = value.as_u64() else {
        return Ok(value);
    };
    let year = month_year / 100;
    let month = month_year % 100;
    Ok(Value::String(format!("{month:02}/{year:04}")))
}

fn totp_at(uri: &str, timestamp: u64) -> std::result::Result<String, TotpError> {
    let totp = parse_totp(uri)?;

    Ok(totp.generate(timestamp).to_string())
}

fn parse_totp(value: &str) -> std::result::Result<Totp, ProtocolError> {
    let uri = normalized_totp_uri(value)?;
    let totp = Totp::from_url_unchecked(uri.as_str())?;
    if !(6..=8).contains(&totp.digits()) {
        return Err(ProtocolError::InvalidDigits {
            digits: totp.digits(),
        });
    }
    if totp.step() == 0 {
        return Err(ProtocolError::InvalidStepZero);
    }

    Ok(totp)
}

fn normalized_totp_uri(value: &str) -> std::result::Result<Url, ProtocolError> {
    let (mut uri, bare_secret) = if value.contains("://") {
        (Url::parse(value).map_err(ProtocolError::UrlParse)?, None)
    } else {
        (
            Url::parse("otpauth://totp/").map_err(ProtocolError::UrlParse)?,
            Some(Zeroizing::new(value.to_owned())),
        )
    };
    let mut query_secret = None;
    let parameters = uri
        .query_pairs()
        .filter_map(|(key, value)| {
            if key == "secret" {
                query_secret = Some(Zeroizing::new(value.into_owned()));

                return None;
            }

            Some((key.into_owned(), value.into_owned()))
        })
        .collect::<Vec<_>>();
    let secret_in_path = bare_secret.is_none() && query_secret.is_none();
    let secret = bare_secret
        .or(query_secret)
        .or_else(|| {
            uri.path_segments()
                .and_then(|mut segments| segments.find(|segment| !segment.is_empty()))
                .map(|secret| Zeroizing::new(secret.to_owned()))
        })
        .ok_or(ProtocolError::SecretNotSet)
        .map(normalized_secret)?;
    if secret.is_empty() {
        return Err(ProtocolError::InvalidSecret);
    }

    if secret_in_path {
        uri.set_path("");
    }
    uri.set_query(None);
    uri.query_pairs_mut()
        .extend_pairs(parameters)
        .append_pair("secret", &secret);

    Ok(uri)
}

fn normalized_secret(mut secret: Zeroizing<String>) -> Zeroizing<String> {
    secret.retain(|character| !matches!(character, ' ' | '='));
    secret.make_ascii_uppercase();

    secret
}

fn is_populated(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn slug(value: &str) -> String {
    let slug = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    slug.split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
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

#[cfg(test)]
mod tests {
    use super::*;

    const DETAILS: &[u8] = br#"{
        "sections": [{
            "fields": [
                {"n":"username","t":"username","k":"string","v":"evan"},
                {"n":"password","t":"password","k":"concealed","v":"secret"},
                {"n":"unused","t":"unused","k":"string"},
                {"n":"expiry","t":"expiry date","k":"monthYear","v":202810}
            ]
        }]
    }"#;

    #[test]
    fn lists_only_populated_fields_without_values() {
        let fields = list_fields(DETAILS).expect("valid item details");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].selector, "username");
        assert_eq!(fields[1].kind, "concealed");
        assert_eq!(fields[2].label, "expiry date");
        assert_eq!(
            serde_json::to_value(&fields[0]).expect("serializable summary"),
            serde_json::json!({
                "selector": "username",
                "label": "username",
                "type": "string"
            })
        );
    }

    #[test]
    fn lists_login_fields_from_legacy_details() {
        let details = br#"{
            "fields": [
                {
                    "designation":"username",
                    "name":"email",
                    "type":"T",
                    "value":"evan@example.com"
                },
                {
                    "designation":"password",
                    "name":"password",
                    "type":"P",
                    "value":"secret"
                }
            ]
        }"#;
        let fields = list_fields(details).expect("valid login details");

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].selector, "username");
        assert_eq!(fields[0].label, "username");
        assert_eq!(fields[0].kind, "string");
        assert_eq!(fields[1].selector, "password");
        assert_eq!(fields[1].label, "password");
        assert_eq!(fields[1].kind, "concealed");
        assert_secret(details, "username", b"evan@example.com");
        assert_secret(details, "password", b"secret");
    }

    #[test]
    fn lists_file_metadata_and_reserves_file_values_for_download() {
        let details = br#"{
            "sections": [{
                "fields": [{
                    "n":"receipt",
                    "t":"receipt",
                    "k":"file",
                    "v":{
                        "documentId":"document",
                        "encryptedSize":23,
                        "encryptionKey":{"alg":"A256GCM","k":"key"},
                        "fileName":"receipt.pdf",
                        "integrityHash":"hash",
                        "nonce":"nonce",
                        "unencryptedSize":7
                    }
                }]
            }]
        }"#;
        let fields = list_fields(details).expect("valid item details");

        assert_eq!(
            serde_json::to_value(&fields[0]).expect("serializable summary"),
            serde_json::json!({
                "selector": "receipt",
                "label": "receipt",
                "type": "file",
                "filename": "receipt.pdf",
                "size": 7
            })
        );
        assert!(matches!(
            get_field(details, "receipt"),
            Err(Error::FileRequiresDownload(field)) if field == "receipt"
        ));
        assert_eq!(
            get_attachment(details, "receipt")
                .expect("file attachment")
                .file_name,
            "receipt.pdf"
        );
    }

    #[test]
    fn formats_month_year_values() {
        let value = get_field(DETAILS, "expiry").expect("existing field");
        let mut output = Vec::new();
        value.write_to(&mut output).expect("write value");
        assert_eq!(output, b"10/2028");
    }

    #[test]
    fn generates_totp_codes() {
        let uri = concat!(
            "otpauth://totp/example?",
            "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30"
        );
        assert_eq!(totp_at(uri, 59).as_deref(), Ok("94287082"));
    }

    #[test]
    fn generates_totp_codes_from_legacy_secret_paths() {
        let uri = concat!(
            "otpauth://totp/GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ?",
            "algorithm=SHA1&digits=8&period=30"
        );
        assert_eq!(totp_at(uri, 59).as_deref(), Ok("94287082"));
    }

    #[test]
    fn generates_totp_codes_from_short_legacy_secrets() {
        let uri = "otpauth://totp/gezdgnbvgy3tqojq====?digits=8&period=30";
        let code = totp_at(uri, 59).expect("legacy 80-bit secret");

        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|character| character.is_ascii_digit()));
    }

    #[test]
    fn generates_totp_codes_from_normalized_query_secrets() {
        let uri = "otpauth://totp/example?secret=gezdgnbvgy3tqojq====&digits=8&period=30";
        let code = totp_at(uri, 59).expect("padded lowercase secret");

        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|character| character.is_ascii_digit()));
    }

    #[test]
    fn generates_totp_codes_from_bare_secrets() {
        let code = totp_at("e4dw4xrdq34wd3qw3", 59).expect("bare secret");

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|character| character.is_ascii_digit()));
    }

    #[test]
    fn reports_safe_totp_validation_reasons() {
        assert!(matches!(
            totp_at("otpauth://totp/?digits=6", 59),
            Err(TotpError::Protocol(ProtocolError::SecretNotSet))
        ));
        assert!(matches!(
            totp_at("otpauth://totp/account?secret=not-base32!", 59),
            Err(TotpError::Protocol(ProtocolError::InvalidSecret))
        ));
        assert!(matches!(
            totp_at(
                "otpauth://totp/account?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
                59
            ),
            Err(TotpError::Protocol(ProtocolError::InvalidAlgorithm { .. }))
        ));
        assert_eq!(
            totp_at(
                "otpauth://totp/account?secret=GEZDGNBVGY3TQOJQ&period=0",
                59
            ),
            Err(TotpError::Protocol(ProtocolError::InvalidStepZero))
        );
        assert_eq!(
            totp_at(
                "otpauth://totp/account?secret=GEZDGNBVGY3TQOJQ&digits=9",
                59
            ),
            Err(TotpError::Protocol(ProtocolError::InvalidDigits {
                digits: 9
            }))
        );
        assert_eq!(
            totp_at("otpauth://totp/account?secret====", 59),
            Err(TotpError::Protocol(ProtocolError::InvalidSecret))
        );
    }

    #[test]
    fn uses_the_same_selectors_for_listing_and_retrieval() {
        let details = br#"{
            "sections": [{
                "fields": [
                    {"n":"duplicate","t":"empty","k":"string"},
                    {"n":"duplicate","t":"first","k":"string","v":"one"},
                    {"n":"duplicate","t":"second","k":"string","v":"two"}
                ]
            }]
        }"#;
        let fields = list_fields(details).expect("valid item details");

        assert_eq!(fields[0].selector, "duplicate");
        assert_eq!(fields[1].selector, "duplicate-2");
        assert_secret(details, "duplicate", b"one");
        assert_secret(details, "duplicate-2", b"two");
    }

    #[test]
    fn selectors_are_globally_unique() {
        let details = br#"{
            "sections": [{
                "fields": [
                    {"n":"foo","t":"first","k":"string","v":"one"},
                    {"n":"foo-2","t":"second","k":"string","v":"two"},
                    {"n":"foo","t":"third","k":"string","v":"three"}
                ]
            }]
        }"#;
        let fields = list_fields(details).expect("valid item details");
        let selectors = fields
            .iter()
            .map(|field| field.selector.as_str())
            .collect::<Vec<_>>();

        assert_eq!(selectors, ["foo", "foo-2", "foo-3"]);
        assert_secret(details, "foo-3", b"three");
    }

    #[test]
    fn labels_do_not_shadow_exact_selectors() {
        let details = br#"{
            "sections": [{
                "fields": [
                    {"n":"username","t":"password","k":"string","v":"wrong"},
                    {"n":"password","t":"password","k":"concealed","v":"right"}
                ]
            }]
        }"#;

        assert_secret(details, "password", b"right");
    }

    fn assert_secret(details: &[u8], selector: &str, expected: &[u8]) {
        let value = get_field(details, selector).expect("existing field");
        let mut output = Vec::new();
        value.write_to(&mut output).expect("write value");
        assert_eq!(output, expected);
    }
}
