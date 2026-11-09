use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    item::{FieldSummary, SecretValue},
    webauthn::{Assertion, AssertionRequest, CredentialSummary},
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Open {
        url: String,
    },
    Fields {
        session: String,
    },
    Get {
        session: String,
        field: String,
    },
    Download {
        session: String,
        field: String,
    },
    PasskeyDescribe {
        session: String,
    },
    PasskeyAssert {
        session: String,
        request: AssertionRequest,
    },
    PasskeyHandoff {
        session: String,
        request_id: String,
    },
    PasskeyBrowserAssert {
        request: AssertionRequest,
    },
    Close {
        session: String,
    },
}

impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::Open { url } => url.zeroize(),
            Self::Fields { session }
            | Self::PasskeyDescribe { session }
            | Self::Close { session } => session.zeroize(),
            Self::Get { session, field } | Self::Download { session, field } => {
                session.zeroize();
                field.zeroize();
            }
            Self::PasskeyAssert { session, .. } | Self::PasskeyHandoff { session, .. } => {
                session.zeroize()
            }
            Self::PasskeyBrowserAssert { .. } => {}
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
    PasskeyCredential { credential: CredentialSummary },
    PasskeyAssertion { assertion: Assertion },
    PasskeyHandoffReady,
    Closed,
    Error { code: String, message: String },
}
