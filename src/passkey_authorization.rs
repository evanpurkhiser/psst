use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const HANDOFF_TTL: Duration = Duration::from_secs(60);

struct Handoff {
    session: Zeroizing<String>,
    request_id: String,
    expires_at: Instant,
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

    pub fn handoff(&mut self, session: &str, request_id: &str, now: Instant) -> bool {
        if valid_request_id(request_id).is_none() {
            return false;
        }

        self.handoff = Some(Handoff {
            session: Zeroizing::new(session.into()),
            request_id: request_id.into(),
            expires_at: now + HANDOFF_TTL,
        });
        true
    }

    pub fn authorize(
        &mut self,
        request_id: Option<&str>,
        now: Instant,
    ) -> Option<Zeroizing<String>> {
        let request_id = request_id.and_then(valid_request_id);
        let matches_handoff = self.handoff.as_ref().is_some_and(|handoff| {
            handoff.expires_at > now && Some(handoff.request_id.as_str()) == request_id
        });
        if !matches_handoff {
            return None;
        }

        self.handoff.take().map(|handoff| handoff.session)
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

fn valid_request_id(request_id: &str) -> Option<&str> {
    let bytes = request_id.as_bytes();
    let valid = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');

    valid.then_some(request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "410e26bd-7701-4481-8b7e-9f4215edbd8d";

    #[test]
    fn handoff_authorizes_its_request_once() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        assert!(authorization.handoff("session", REQUEST_ID, now));

        assert_eq!(
            authorization
                .authorize(Some(REQUEST_ID), now)
                .as_ref()
                .map(|session| session.as_str()),
            Some("session")
        );
        assert!(authorization.authorize(Some(REQUEST_ID), now).is_none());
    }

    #[test]
    fn handoff_does_not_authorize_another_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now);

        assert!(
            authorization
                .authorize(Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), now)
                .is_none()
        );
    }

    #[test]
    fn handoff_can_arrive_before_the_browser_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now);

        assert_eq!(
            authorization
                .authorize(Some(REQUEST_ID), now)
                .as_ref()
                .map(|session| session.as_str()),
            Some("session")
        );
    }

    #[test]
    fn expired_handoff_cannot_authorize_a_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now);

        assert!(
            authorization
                .authorize(Some(REQUEST_ID), now + HANDOFF_TTL)
                .is_none()
        );
    }

    #[test]
    fn invalid_request_identifiers_are_rejected() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        assert!(!authorization.handoff("session", "request", now));
        assert!(!authorization.handoff("session", "410e26bd-7701-3481-8b7e-9f4215edbd8d", now));
        assert!(!authorization.handoff("session", "410e26bd-7701-4481-7b7e-9f4215edbd8d", now));
    }

    #[test]
    fn removing_a_session_cancels_its_handoff() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now);
        authorization.remove_session("session");

        assert!(authorization.authorize(Some(REQUEST_ID), now).is_none());
    }

    #[test]
    fn expiration_cancels_a_handoff_for_an_inactive_session() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.handoff("session", REQUEST_ID, now);
        authorization.expire(now, |_| false);

        assert!(authorization.authorize(Some(REQUEST_ID), now).is_none());
    }
}
