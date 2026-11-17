use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::{
    daemon::browser_protocol::{AssertionRequest, PasskeyResult, Registration},
    domain::webauthn::Assertion,
};

const REQUEST_TTL: Duration = Duration::from_secs(60);
const MAX_REQUESTS: usize = 32;

#[derive(Default)]
pub struct PasskeyRequests {
    requests: HashMap<String, PasskeyRequest>,
}

struct PasskeyRequest {
    capability: Zeroizing<String>,
    request: AssertionRequest,
    expires_at: Instant,
    state: RequestState,
    changed: Arc<Notify>,
}

enum RequestState {
    Waiting,
    Running,
    Complete(Assertion),
    Failed { code: String, message: String },
}

pub enum Poll {
    Pending(Arc<Notify>),
    Ready(PasskeyResult),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    Busy,
    Forbidden,
    InvalidId,
    NotFound,
    Full,
}

impl PasskeyRequests {
    pub fn register(
        &mut self,
        request: AssertionRequest,
        now: Instant,
    ) -> Result<Registration, RequestError> {
        validate_request_id(&request.request_id)?;
        self.expire(now);
        if self.requests.len() >= MAX_REQUESTS {
            return Err(RequestError::Full);
        }
        if self.requests.contains_key(&request.request_id) {
            return Err(RequestError::Busy);
        }

        let capability = capability();
        self.requests.insert(
            request.request_id.clone(),
            PasskeyRequest {
                capability: Zeroizing::new(capability.clone()),
                request,
                expires_at: now + REQUEST_TTL,
                state: RequestState::Waiting,
                changed: Arc::new(Notify::new()),
            },
        );

        Ok(Registration { capability })
    }

    pub fn claim(
        &mut self,
        request_id: &str,
        now: Instant,
    ) -> Result<AssertionRequest, RequestError> {
        validate_request_id(request_id)?;
        self.expire(now);
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or(RequestError::NotFound)?;
        if !matches!(request.state, RequestState::Waiting) {
            return Err(RequestError::Busy);
        }

        request.state = RequestState::Running;
        Ok(request.request.clone())
    }

    pub fn complete(&mut self, request_id: &str, result: Result<Assertion, (String, String)>) {
        let Some(request) = self.requests.get_mut(request_id) else {
            return;
        };
        if !matches!(request.state, RequestState::Running) {
            return;
        }

        request.state = match result {
            Ok(assertion) => RequestState::Complete(assertion),
            Err((code, message)) => RequestState::Failed { code, message },
        };
        request.changed.notify_one();
    }

    pub fn poll(
        &mut self,
        request_id: &str,
        capability: &str,
        now: Instant,
    ) -> Result<Poll, RequestError> {
        validate_request_id(request_id)?;
        self.expire(now);
        let request = self
            .requests
            .get(request_id)
            .ok_or(RequestError::NotFound)?;
        if request.capability.as_str() != capability {
            return Err(RequestError::Forbidden);
        }

        Ok(match &request.state {
            RequestState::Waiting | RequestState::Running => Poll::Pending(request.changed.clone()),
            RequestState::Complete(assertion) => Poll::Ready(PasskeyResult::Complete {
                assertion: assertion.clone(),
            }),
            RequestState::Failed { code, message } => Poll::Ready(PasskeyResult::Failed {
                code: code.clone(),
                message: message.clone(),
            }),
        })
    }

    pub fn cancel(&mut self, request_id: &str, capability: &str) -> Result<(), RequestError> {
        validate_request_id(request_id)?;
        let request = self
            .requests
            .get(request_id)
            .ok_or(RequestError::NotFound)?;
        if request.capability.as_str() != capability {
            return Err(RequestError::Forbidden);
        }

        let request = self.requests.remove(request_id).expect("request exists");
        request.changed.notify_one();
        Ok(())
    }

    pub fn expire(&mut self, now: Instant) {
        self.requests.retain(|_, request| {
            let keep = request.expires_at > now;
            if !keep {
                request.changed.notify_one();
            }
            keep
        });
    }
}

fn capability() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_request_id(value: &str) -> Result<(), RequestError> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');

    valid.then_some(()).ok_or(RequestError::InvalidId)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "410e26bd-7701-4481-8b7e-9f4215edbd8d";

    fn request() -> AssertionRequest {
        AssertionRequest {
            request_id: REQUEST_ID.into(),
            origin: "https://example.com".into(),
            challenge: "challenge".into(),
            rp_id: Some("example.com".into()),
            allow_credentials: Vec::new(),
        }
    }

    #[test]
    fn capability_protects_polling_and_cancelation() {
        let now = Instant::now();
        let mut requests = PasskeyRequests::default();
        let registration = requests.register(request(), now).unwrap();

        assert!(matches!(
            requests.poll(REQUEST_ID, &registration.capability, now),
            Ok(Poll::Pending(_))
        ));
        assert!(matches!(
            requests.poll(REQUEST_ID, "wrong", now),
            Err(RequestError::Forbidden)
        ));
        assert!(matches!(
            requests.cancel(REQUEST_ID, "wrong"),
            Err(RequestError::Forbidden)
        ));
    }

    #[test]
    fn each_request_can_be_claimed_once() {
        let now = Instant::now();
        let mut requests = PasskeyRequests::default();
        requests.register(request(), now).unwrap();

        assert!(requests.claim(REQUEST_ID, now).is_ok());
        assert!(matches!(
            requests.claim(REQUEST_ID, now),
            Err(RequestError::Busy)
        ));
    }
}
