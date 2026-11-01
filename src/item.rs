use std::{
    collections::{HashMap, HashSet},
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    attachment::Attachment,
    error::{Error, Result},
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
        let uri = value
            .as_str()
            .ok_or_else(|| Error::InvalidTotp(field.label.clone()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidTotp(field.label.clone()))?
            .as_secs();
        return totp_at(uri, now)
            .map(Value::String)
            .ok_or_else(|| Error::InvalidTotp(field.label.clone()));
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

fn totp_at(uri: &str, timestamp: u64) -> Option<String> {
    let uri = Url::parse(uri).ok()?;
    if uri.scheme() != "otpauth" || uri.host_str() != Some("totp") {
        return None;
    }

    let parameters = uri.query_pairs().collect::<HashMap<_, _>>();
    let encoded_secret = Zeroizing::new(parameters.get("secret")?.replace([' ', '='], ""));
    let upper_secret = Zeroizing::new(encoded_secret.to_ascii_uppercase());
    let secret = Zeroizing::new(BASE32_NOPAD.decode(upper_secret.as_bytes()).ok()?);
    let period = parameters
        .get("period")
        .map(|value| value.parse::<u64>().ok())
        .unwrap_or(Some(30))?;
    let digits = parameters
        .get("digits")
        .map(|value| value.parse::<u32>().ok())
        .unwrap_or(Some(6))?;
    if period == 0 || !(6..=10).contains(&digits) {
        return None;
    }

    let counter = (timestamp / period).to_be_bytes();
    let digest = Zeroizing::new(match parameters
        .get("algorithm")
        .map(|value| value.to_ascii_uppercase())
        .as_deref()
        .unwrap_or("SHA1")
    {
        "SHA1" => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&secret).ok()?;
            mac.update(&counter);
            Some(mac.finalize().into_bytes().to_vec())
        }
        "SHA256" => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).ok()?;
            mac.update(&counter);
            Some(mac.finalize().into_bytes().to_vec())
        }
        "SHA512" => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&secret).ok()?;
            mac.update(&counter);
            Some(mac.finalize().into_bytes().to_vec())
        }
        _ => return None,
    }?);
    let offset = usize::from(digest.last()? & 0x0f);
    let bytes: [u8; 4] = digest.get(offset..offset + 4)?.try_into().ok()?;
    let binary = u32::from_be_bytes(bytes) & 0x7fff_ffff;
    let code = u64::from(binary) % 10_u64.pow(digits);
    Some(format!("{code:0width$}", width = digits as usize))
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
        assert_eq!(totp_at(uri, 59).as_deref(), Some("94287082"));
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
