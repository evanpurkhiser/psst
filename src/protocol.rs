use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::item::{FieldSummary, SecretValue};

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Open { url: String },
    Fields { session: String },
    Get { session: String, field: String },
    Download { session: String, field: String },
    Close { session: String },
}

impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::Open { url } => url.zeroize(),
            Self::Fields { session } | Self::Close { session } => session.zeroize(),
            Self::Get { session, field } | Self::Download { session, field } => {
                session.zeroize();
                field.zeroize();
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Opened { session: String },
    Fields { fields: Vec<FieldSummary> },
    Secret { value: SecretValue },
    Attachment { size: u64 },
    Closed,
    Error { code: String, message: String },
}
