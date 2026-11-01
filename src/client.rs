use reqwest::{StatusCode, blocking::Client};
use serde::Deserialize;

use crate::{
    crypto::{EncryptedContainer, ShareKeys},
    error::{Error, Result},
};

const SHARE_ORIGIN: &str = "https://share.1password.com";

#[derive(Debug, Deserialize)]
struct ShareResponse {
    #[serde(rename = "encOverview")]
    overview: EncryptedContainer,
    #[serde(rename = "encDetails")]
    details: EncryptedContainer,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    reason: Option<String>,
}

pub struct EncryptedItem {
    pub overview: EncryptedContainer,
    pub details: EncryptedContainer,
}

pub fn fetch(keys: &ShareKeys) -> Result<EncryptedItem> {
    let response = Client::builder()
        .user_agent(concat!("psst/", env!("CARGO_PKG_VERSION")))
        .build()?
        .get(format!("{SHARE_ORIGIN}/api/v1/share/{}", keys.uuid))
        .header("OP-Share-Token", keys.token.as_str())
        .header("OP-Language", "en")
        .send()?;

    if response.status() == StatusCode::OK {
        let response: ShareResponse = response.json()?;
        return Ok(EncryptedItem {
            overview: response.overview,
            details: response.details,
        });
    }

    let status = response.status();
    let reason = response
        .json::<ErrorResponse>()
        .ok()
        .and_then(|error| error.reason)
        .unwrap_or_else(|| status.to_string());
    Err(Error::Unavailable(reason.replace('_', " ")))
}
