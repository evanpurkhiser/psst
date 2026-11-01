use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const SHARE_PREFIX: &str = "https://share.1password.com/s#";

pub struct ShareKeys {
    pub uuid: String,
    pub token: Zeroizing<String>,
    pub encryption_key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedContainer {
    pub kid: String,
    pub enc: String,
    pub cty: String,
    pub iv: String,
    pub data: String,
}

pub fn keys_from_link(input: &str) -> Result<ShareKeys> {
    let fragment = input
        .trim()
        .strip_prefix(SHARE_PREFIX)
        .filter(|fragment| !fragment.is_empty() && !fragment.contains(['#', '?']))
        .ok_or_else(|| Error::InvalidLink(format!("expected {SHARE_PREFIX}…")))?;
    let secret = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(fragment.as_bytes())
            .map_err(|_| Error::InvalidLink("share secret is not valid base64url".into()))?,
    );
    if secret.len() != 32 {
        return Err(Error::InvalidLink("share secret must be 32 bytes".into()));
    }

    let hkdf = Hkdf::<Sha256>::new(None, secret.as_slice());
    let uuid = derive::<16>(&hkdf, b"share_item_uuid")?;
    let token = derive::<16>(&hkdf, b"share_item_token")?;
    let encryption_key = derive::<32>(&hkdf, b"share_item_encryption_key")?;

    Ok(ShareKeys {
        uuid: encode_identifier(&uuid),
        token: Zeroizing::new(encode_identifier(&token)),
        encryption_key: Zeroizing::new(encryption_key),
    })
}

pub fn decrypt(container: &EncryptedContainer, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    if container.enc != "A256GCM" || container.cty != "b5+jwk+json" {
        return Err(Error::UnsupportedContainer);
    }

    let iv = URL_SAFE_NO_PAD
        .decode(container.iv.as_bytes())
        .map_err(|_| Error::Decryption)?;
    let ciphertext = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(container.data.as_bytes())
            .map_err(|_| Error::Decryption)?,
    );
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Decryption)?;
    let nonce: [u8; 12] = iv.try_into().map_err(|_| Error::Decryption)?;
    let plaintext = cipher
        .decrypt((&nonce).into(), ciphertext.as_slice())
        .map_err(|_| Error::Decryption)?;
    Ok(Zeroizing::new(plaintext))
}

fn derive<const N: usize>(hkdf: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; N]> {
    let mut output = [0; N];
    hkdf.expand(info, &mut output)
        .map_err(|_| Error::InvalidLink("could not derive share keys".into()))?;
    Ok(output)
}

fn encode_identifier(value: &[u8]) -> String {
    BASE32_NOPAD.encode(value).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_share_primitives() {
        let secret: Vec<u8> = (0..32).collect();
        let fragment = URL_SAFE_NO_PAD.encode(&secret);
        let keys = keys_from_link(&format!("https://share.1password.com/s#{fragment}"))
            .expect("valid share link");

        assert_eq!(keys.uuid, "jwd63ixpizjpwibrxj5iwnilii");
        assert_eq!(&**keys.token, "zcalvvebhmp6av6yty7d6tnnpa");
        assert_eq!(
            hex(&*keys.encryption_key),
            "da58624551f0a061711d2f1bc367f1361da6e86dfb74ea7c32096cd58a364661"
        );
    }

    #[test]
    fn rejects_links_outside_the_share_origin() {
        assert!(matches!(
            keys_from_link("https://example.com/s#abc"),
            Err(Error::InvalidLink(_))
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
