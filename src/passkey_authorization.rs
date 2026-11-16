use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

const HANDOFF_TTL: Duration = Duration::from_secs(60);

struct Handoff {
    session: Zeroizing<String>,
    expires_at: Instant,
    state: HandoffState,
}

enum HandoffState {
    Pending,
    Running,
    Complete,
    Failed(HandoffFailure),
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct RequestId(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandoffStatus {
    Pending,
    Complete,
    Failed(HandoffFailure),
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandoffError {
    Busy,
    InvalidRequestId,
    NotFound,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidRequestId,
}

pub enum AuthorizationOutcome {
    Authorized {
        session: Zeroizing<String>,
        request_id: String,
    },
    Required,
}

#[derive(Default)]
pub struct PasskeyAuthorization {
    handoffs: HashMap<RequestId, Handoff>,
}

impl PasskeyAuthorization {
    pub fn expire(&mut self, now: Instant, session_is_active: impl Fn(&str) -> bool) {
        self.handoffs.retain(|_, handoff| {
            handoff.expires_at > now && session_is_active(handoff.session.as_str())
        });
    }

    pub fn handoff(
        &mut self,
        session: &str,
        request_id: &str,
        now: Instant,
    ) -> Result<(), HandoffError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| HandoffError::InvalidRequestId)?;
        if let Some(handoff) = self.handoffs.get(&request_id) {
            if handoff.session.as_str() == session {
                return Ok(());
            }

            return Err(HandoffError::Busy);
        }

        self.handoffs.insert(
            request_id,
            Handoff {
                session: Zeroizing::new(session.into()),
                expires_at: now + HANDOFF_TTL,
                state: HandoffState::Pending,
            },
        );
        Ok(())
    }

    pub fn status(&self, session: &str, request_id: &str) -> Result<HandoffStatus, HandoffError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| HandoffError::InvalidRequestId)?;
        let handoff = self
            .handoffs
            .get(&request_id)
            .ok_or(HandoffError::NotFound)?;
        if handoff.session.as_str() != session {
            return Err(HandoffError::NotFound);
        }

        Ok(match &handoff.state {
            HandoffState::Pending | HandoffState::Running => HandoffStatus::Pending,
            HandoffState::Complete => HandoffStatus::Complete,
            HandoffState::Failed(failure) => HandoffStatus::Failed(failure.clone()),
        })
    }

    pub fn authorize(
        &mut self,
        request_id: Option<&str>,
        now: Instant,
    ) -> Result<AuthorizationOutcome, AuthorizationError> {
        let request_id = RequestId::parse(request_id.ok_or(AuthorizationError::InvalidRequestId)?)?;
        let Some(handoff) = self.handoffs.get_mut(&request_id) else {
            return Ok(AuthorizationOutcome::Required);
        };
        if handoff.expires_at <= now || !matches!(handoff.state, HandoffState::Pending) {
            return Ok(AuthorizationOutcome::Required);
        }

        handoff.state = HandoffState::Running;
        Ok(AuthorizationOutcome::Authorized {
            session: Zeroizing::new(handoff.session.to_string()),
            request_id: request_id.0,
        })
    }

    pub fn complete(&mut self, request_id: &str, failure: Option<HandoffFailure>) {
        let Ok(request_id) = RequestId::parse(request_id) else {
            return;
        };
        let Some(handoff) = self.handoffs.get_mut(&request_id) else {
            return;
        };
        if !matches!(handoff.state, HandoffState::Running) {
            return;
        }

        handoff.state = match failure {
            Some(failure) => HandoffState::Failed(failure),
            None => HandoffState::Complete,
        };
    }

    pub fn remove_session(&mut self, session: &str) {
        self.handoffs
            .retain(|_, handoff| handoff.session.as_str() != session);
    }
}

impl RequestId {
    fn parse(value: &str) -> Result<Self, AuthorizationError> {
        let bytes = value.as_bytes();
        let valid = bytes.len() == 36
            && bytes.iter().enumerate().all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
            })
            && bytes[14] == b'4'
            && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');

        valid
            .then(|| Self(value.into()))
            .ok_or(AuthorizationError::InvalidRequestId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "410e26bd-7701-4481-8b7e-9f4215edbd8d";

    #[test]
    fn handoff_authorizes_its_request_once() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        assert_eq!(authorization.handoff("session", REQUEST_ID, now), Ok(()));

        let AuthorizationOutcome::Authorized {
            session,
            request_id,
        } = authorization.authorize(Some(REQUEST_ID), now).unwrap()
        else {
            panic!("expected authorization");
        };
        assert_eq!(session.as_str(), "session");
        assert_eq!(request_id, REQUEST_ID);
        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now),
            Ok(AuthorizationOutcome::Required)
        ));
    }

    #[test]
    fn handoff_does_not_authorize_another_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();

        assert!(matches!(
            authorization.authorize(Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), now),
            Ok(AuthorizationOutcome::Required)
        ));
    }

    #[test]
    fn handoff_can_arrive_before_the_browser_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();

        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now),
            Ok(AuthorizationOutcome::Authorized { .. })
        ));
    }

    #[test]
    fn expired_handoff_cannot_authorize_a_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();

        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now + HANDOFF_TTL),
            Ok(AuthorizationOutcome::Required)
        ));
    }

    #[test]
    fn invalid_request_identifiers_are_rejected() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        assert_eq!(
            authorization.handoff("session", "request", now),
            Err(HandoffError::InvalidRequestId)
        );
        assert_eq!(
            authorization.handoff("session", "410e26bd-7701-3481-8b7e-9f4215edbd8d", now),
            Err(HandoffError::InvalidRequestId)
        );
        assert_eq!(
            authorization.handoff("session", "410e26bd-7701-4481-7b7e-9f4215edbd8d", now),
            Err(HandoffError::InvalidRequestId)
        );
    }

    #[test]
    fn identical_handoff_is_idempotent() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();

        assert_eq!(authorization.handoff("session", REQUEST_ID, now), Ok(()));
    }

    #[test]
    fn distinct_handoffs_can_run_in_parallel() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();
        let other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

        authorization.handoff("session", REQUEST_ID, now).unwrap();
        authorization.handoff("other-session", other, now).unwrap();

        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now),
            Ok(AuthorizationOutcome::Authorized { .. })
        ));
        assert!(matches!(
            authorization.authorize(Some(other), now),
            Ok(AuthorizationOutcome::Authorized { .. })
        ));
    }

    #[test]
    fn one_browser_request_cannot_be_claimed_by_another_session() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();

        assert_eq!(
            authorization.handoff("other-session", REQUEST_ID, now),
            Err(HandoffError::Busy)
        );
    }

    #[test]
    fn reports_browser_completion_and_failure() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();
        let other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let failure = HandoffFailure {
            code: "webauthn_request_invalid".into(),
            message: "request failed".into(),
        };

        authorization.handoff("session", REQUEST_ID, now).unwrap();
        authorization.authorize(Some(REQUEST_ID), now).unwrap();
        assert_eq!(
            authorization.status("session", REQUEST_ID),
            Ok(HandoffStatus::Pending)
        );

        authorization.complete(REQUEST_ID, Some(failure.clone()));
        assert_eq!(
            authorization.status("session", REQUEST_ID),
            Ok(HandoffStatus::Failed(failure))
        );

        authorization.handoff("session", other, now).unwrap();
        authorization.authorize(Some(other), now).unwrap();
        authorization.complete(other, None);
        assert_eq!(
            authorization.status("session", other),
            Ok(HandoffStatus::Complete)
        );
    }

    #[test]
    fn malformed_browser_request_is_rejected() {
        let mut authorization = PasskeyAuthorization::default();

        assert!(matches!(
            authorization.authorize(None, Instant::now()),
            Err(AuthorizationError::InvalidRequestId)
        ));
    }

    #[test]
    fn removing_a_session_cancels_its_handoff() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();
        authorization.remove_session("session");

        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now),
            Ok(AuthorizationOutcome::Required)
        ));
    }

    #[test]
    fn expiration_cancels_a_handoff_for_an_inactive_session() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now).unwrap();
        authorization.expire(now, |_| false);

        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now),
            Ok(AuthorizationOutcome::Required)
        ));
    }
}
