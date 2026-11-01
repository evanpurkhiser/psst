use std::{io::Read, time::Duration};

use reqwest::{
    StatusCode,
    blocking::{Client, Response},
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    crypto::{EncryptedContainer, ShareKeys},
    error::{Error, Result},
};

const SHARE_ORIGIN: &str = "https://share.1password.com";
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;

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
        .timeout(HTTP_TIMEOUT)
        .build()?
        .get(format!("{SHARE_ORIGIN}/api/v1/share/{}", keys.uuid))
        .header("OP-Share-Token", keys.token.as_str())
        .header("OP-Language", "en")
        .send()?;

    let status = response.status();
    let body = read_body(response)?;

    if status == StatusCode::OK {
        let response: ShareResponse = serde_json::from_slice(&body)?;
        return Ok(EncryptedItem {
            overview: response.overview,
            details: response.details,
        });
    }

    let reason = serde_json::from_slice::<ErrorResponse>(&body)
        .ok()
        .and_then(|error| error.reason)
        .unwrap_or_else(|| status.to_string());
    Err(Error::Unavailable(reason.replace('_', " ")))
}

fn read_body(response: Response) -> Result<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_BODY as u64)
    {
        return Err(Error::ResponseSizeLimit("1Password response"));
    }

    let mut body = Zeroizing::new(Vec::new());
    response
        .take(MAX_HTTP_BODY as u64 + 1)
        .read_to_end(&mut body)?;
    if body.len() > MAX_HTTP_BODY {
        return Err(Error::ResponseSizeLimit("1Password response"));
    }

    Ok(body)
}
