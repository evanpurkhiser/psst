use std::{
    collections::HashMap,
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
use zeroize::Zeroize;

use crate::error::{Error, Result};

#[derive(Debug, Deserialize, Serialize)]
pub struct FieldSummary {
    pub selector: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Deserialize)]
struct Details {
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
    #[serde(default, rename = "n")]
    name: String,
    #[serde(default, rename = "t")]
    label: String,
    #[serde(default, rename = "k")]
    kind: String,
    #[serde(default, rename = "v")]
    value: Option<Value>,
}

impl Drop for Field {
    fn drop(&mut self) {
        self.name.zeroize();
        self.label.zeroize();
        self.kind.zeroize();
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
    let mut selectors = HashMap::<String, usize>::new();
    let mut fields = Vec::new();

    for field in details.sections.iter().flat_map(|section| &section.fields) {
        if !field.value.as_ref().is_some_and(is_populated) {
            continue;
        }

        let selector = selector_for(field, &mut selectors);
        fields.push(FieldSummary {
            selector,
            label: field.label.clone(),
            kind: field.kind.clone(),
        });
    }

    Ok(fields)
}

pub fn get_field(json: &[u8], selector: &str) -> Result<SecretValue> {
    let details: Details = serde_json::from_slice(json)?;
    let mut selectors = HashMap::<String, usize>::new();

    for mut field in details
        .sections
        .into_iter()
        .flat_map(|section| section.fields)
    {
        let field_selector = selector_for(&field, &mut selectors);
        let Some(value) = field.value.take().filter(is_populated) else {
            continue;
        };

        if selector == field_selector || selector.eq_ignore_ascii_case(&field.label) {
            return Ok(SecretValue(format_value(&field, value)?));
        }
    }

    Err(Error::FieldNotFound(selector.into()))
}

fn selector_for(field: &Field, selectors: &mut HashMap<String, usize>) -> String {
    let base = if field.name.is_empty() {
        slug(&field.label)
    } else {
        field.name.clone()
    };
    let count = selectors.entry(base.clone()).or_default();
    *count += 1;

    match *count {
        1 => base,
        occurrence => format!("{base}-{occurrence}"),
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
    let secret = parameters.get("secret")?.replace([' ', '='], "");
    let secret = BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())
        .ok()?;
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
    let digest = match parameters
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
    }?;
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
        Value::Object(values) => values.values_mut().for_each(zeroize_value),
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
}
