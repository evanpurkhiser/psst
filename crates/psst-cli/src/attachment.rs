use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub document_id: String,
    pub encrypted_size: u64,
    pub encryption_key: EncryptionKey,
    pub file_name: String,
    pub integrity_hash: String,
    pub nonce: String,
    pub unencrypted_size: u64,
}

#[derive(Deserialize)]
pub struct EncryptionKey {
    alg: String,
    k: String,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.document_id.zeroize();
        self.file_name.zeroize();
        self.integrity_hash.zeroize();
        self.nonce.zeroize();
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.alg.zeroize();
        self.k.zeroize();
    }
}

pub fn decrypt(
    attachment: &Attachment,
    encrypted: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if attachment.encryption_key.alg != "A256GCM" {
        return Err(Error::UnsupportedAttachment);
    }
    if encrypted.len() as u64 != attachment.encrypted_size {
        return Err(Error::AttachmentSize);
    }

    let expected_hash = URL_SAFE_NO_PAD
        .decode(attachment.integrity_hash.as_bytes())
        .map_err(|_| Error::AttachmentIntegrity)?;
    let actual_hash = Sha256::digest(&encrypted);
    if actual_hash.as_slice() != expected_hash {
        return Err(Error::AttachmentIntegrity);
    }

    let key = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(attachment.encryption_key.k.as_bytes())
            .map_err(|_| Error::AttachmentDecryption)?,
    );
    let nonce = URL_SAFE_NO_PAD
        .decode(attachment.nonce.as_bytes())
        .map_err(|_| Error::AttachmentDecryption)?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| Error::AttachmentDecryption)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::AttachmentDecryption)?;
    let plaintext = cipher
        .decrypt((&nonce).into(), encrypted.as_slice())
        .map_err(|_| Error::AttachmentDecryption)?;
    if plaintext.len() as u64 != attachment.unencrypted_size {
        return Err(Error::AttachmentSize);
    }

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use aes_gcm::{AeadCore, aead::OsRng};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    #[test]
    fn verifies_and_decrypts_an_attachment() {
        let key = [7_u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let plaintext = b"attachment contents";
        let encrypted = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .expect("encrypt fixture");
        let attachment = Attachment {
            document_id: "document".into(),
            encrypted_size: encrypted.len() as u64,
            encryption_key: EncryptionKey {
                alg: "A256GCM".into(),
                k: URL_SAFE_NO_PAD.encode(key),
            },
            file_name: "fixture.txt".into(),
            integrity_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(&encrypted)),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            unencrypted_size: plaintext.len() as u64,
        };

        let decrypted = decrypt(&attachment, Zeroizing::new(encrypted)).expect("decrypt fixture");
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
