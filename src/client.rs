use std::{io::Read, time::Duration};

use reqwest::{
    StatusCode,
    blocking::{Client, Response},
};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::{
    attachment::Attachment,
    crypto::{EncryptedContainer, ShareKeys},
    error::{Error, Result},
};

const SHARE_ORIGIN: &str = "https://share.1password.com";
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;
const MAX_ATTACHMENT_BODY: usize = 64 * 1024 * 1024;
const MAX_DOWNLOAD_URL_BODY: usize = 16 * 1024;

#[derive(Deserialize)]
struct ShareResponse {
    #[serde(rename = "encOverview")]
    overview: EncryptedContainer,
    #[serde(rename = "encDetails")]
    details: EncryptedContainer,
    #[serde(rename = "fileDownload")]
    file_download: Option<FileDownload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDownload {
    pub token: String,
}

impl Drop for FileDownload {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadUrlResponse {
    download_url: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    reason: Option<String>,
}

pub struct EncryptedItem {
    pub overview: EncryptedContainer,
    pub details: EncryptedContainer,
    pub file_download: Option<FileDownload>,
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
            file_download: response.file_download,
        });
    }

    let reason = serde_json::from_slice::<ErrorResponse>(&body)
        .ok()
        .and_then(|error| error.reason)
        .unwrap_or_else(|| status.to_string());
    Err(Error::Unavailable(reason.replace('_', " ")))
}

pub fn fetch_attachment(
    share_uuid: &str,
    download: &FileDownload,
    attachment: &Attachment,
) -> Result<Zeroizing<Vec<u8>>> {
    if attachment.encrypted_size > MAX_ATTACHMENT_BODY as u64 {
        return Err(Error::ResponseSizeLimit("attachment"));
    }

    let client = Client::builder()
        .user_agent(concat!("psst/", env!("CARGO_PKG_VERSION")))
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client
        .get(format!(
            "{SHARE_ORIGIN}/api/v1/file/{share_uuid}/{}",
            attachment.document_id
        ))
        .header("OP-File-Download-Token", download.token.as_str())
        .send()?;
    let status = response.status();
    let body = read_limited(response, MAX_DOWNLOAD_URL_BODY, "attachment URL response")?;
    if status != StatusCode::OK {
        return Err(Error::Unavailable(status.to_string()));
    }
    let mut response: DownloadUrlResponse = serde_json::from_slice(&body)?;
    let url = validate_download_url(&response.download_url)?;
    response.download_url.zeroize();

    let response = client.get(url).send()?;
    if response.status() != StatusCode::OK {
        return Err(Error::Unavailable(response.status().to_string()));
    }
    let body = read_limited(response, MAX_ATTACHMENT_BODY, "attachment")?;
    if body.len() as u64 != attachment.encrypted_size {
        return Err(Error::AttachmentSize);
    }

    Ok(body)
}

fn validate_download_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| Error::AttachmentUrl)?;
    let valid_host = matches!(
        url.host_str(),
        Some(
            "f.share.1passwordusercontent.com"
                | "f.share.1passwordusercontent.ca"
                | "f.share.1passwordusercontent.eu"
        )
    );
    if url.scheme() != "https"
        || !valid_host
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::AttachmentUrl);
    }

    Ok(url)
}

fn read_body(response: Response) -> Result<Zeroizing<Vec<u8>>> {
    read_limited(response, MAX_HTTP_BODY, "1Password response")
}

fn read_limited(
    response: Response,
    limit: usize,
    description: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::ResponseSizeLimit(description));
    }

    let mut body = Zeroizing::new(Vec::new());
    response.take(limit as u64 + 1).read_to_end(&mut body)?;
    if body.len() > limit {
        return Err(Error::ResponseSizeLimit(description));
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_1password_attachment_hosts() {
        assert!(
            validate_download_url(
                "https://f.share.1passwordusercontent.com/path?Signature=fixture"
            )
            .is_ok()
        );
        assert!(validate_download_url("http://f.share.1passwordusercontent.com/path").is_err());
        assert!(
            validate_download_url("https://f.share.1passwordusercontent.com.evil.test/path")
                .is_err()
        );
        assert!(
            validate_download_url("https://f.share.1passwordusercontent.com:444/path").is_err()
        );
    }
}
