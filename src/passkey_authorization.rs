use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const HANDOFF_TTL: Duration = Duration::from_secs(60);

struct Handoff {
    session: Zeroizing<String>,
    request_id: RequestId,
    expires_at: Instant,
}

#[derive(PartialEq, Eq)]
struct RequestId(String);

#[derive(Debug, PartialEq, Eq)]
pub enum HandoffError {
    Busy,
    InvalidRequestId,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidRequestId,
}

pub enum AuthorizationOutcome {
    Authorized(Zeroizing<String>),
    Required,
}

#[derive(Default)]
pub struct PasskeyAuthorization {
    handoff: Option<Handoff>,
}

impl PasskeyAuthorization {
    pub fn expire(&mut self, now: Instant, session_is_active: impl Fn(&str) -> bool) {
        if self.handoff.as_ref().is_some_and(|handoff| {
            handoff.expires_at <= now || !session_is_active(handoff.session.as_str())
        }) {
            self.handoff = None;
        }
    }

    pub fn handoff(
        &mut self,
        session: &str,
        request_id: &str,
        now: Instant,
    ) -> Result<(), HandoffError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| HandoffError::InvalidRequestId)?;
        if let Some(handoff) = self.handoff.as_ref() {
            if handoff.session.as_str() == session && handoff.request_id == request_id {
                return Ok(());
            }

            return Err(HandoffError::Busy);
        }

        self.handoff = Some(Handoff {
            session: Zeroizing::new(session.into()),
            request_id,
            expires_at: now + HANDOFF_TTL,
        });
        Ok(())
    }

    pub fn authorize(
        &mut self,
        request_id: Option<&str>,
        now: Instant,
    ) -> Result<AuthorizationOutcome, AuthorizationError> {
        let request_id = RequestId::parse(request_id.ok_or(AuthorizationError::InvalidRequestId)?)?;
        let Some(handoff) = self.handoff.take() else {
            return Ok(AuthorizationOutcome::Required);
        };
        if handoff.expires_at <= now || handoff.request_id != request_id {
            self.handoff = Some(handoff);

            return Ok(AuthorizationOutcome::Required);
        }

        Ok(AuthorizationOutcome::Authorized(handoff.session))
    }

    pub fn remove_session(&mut self, session: &str) {
        if self
            .handoff
            .as_ref()
            .is_some_and(|handoff| handoff.session.as_str() == session)
        {
            self.handoff = None;
        }
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

        let AuthorizationOutcome::Authorized(session) =
            authorization.authorize(Some(REQUEST_ID), now).unwrap()
        else {
            panic!("expected authorization");
        };
        assert_eq!(session.as_str(), "session");
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
            Ok(AuthorizationOutcome::Authorized(_))
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
    fn competing_handoff_is_busy_without_replacing_the_first() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();
        let other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

        authorization.handoff("session", REQUEST_ID, now).unwrap();

        assert_eq!(
            authorization.handoff("session", other, now),
            Err(HandoffError::Busy)
        );
        assert!(matches!(
            authorization.authorize(Some(REQUEST_ID), now),
            Ok(AuthorizationOutcome::Authorized(_))
        ));
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
