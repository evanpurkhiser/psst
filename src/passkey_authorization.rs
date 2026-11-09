use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const ARM_TTL: Duration = Duration::from_secs(60);
const REQUEST_TTL: Duration = Duration::from_secs(60);
const MAX_REQUEST_ID_BYTES: usize = 128;

struct ArmedPasskey {
    session: Zeroizing<String>,
    request_id: Option<String>,
    expires_at: Instant,
}

struct PendingRequest {
    id: String,
    expires_at: Instant,
}

#[derive(Default)]
pub struct PasskeyAuthorization {
    armed: Option<ArmedPasskey>,
    pending_requests: Vec<PendingRequest>,
}

impl PasskeyAuthorization {
    pub fn expire(&mut self, now: Instant, session_is_active: impl Fn(&str) -> bool) {
        if self.armed.as_ref().is_some_and(|armed| {
            armed.expires_at <= now || !session_is_active(armed.session.as_str())
        }) {
            self.armed = None;
        }

        self.pending_requests
            .retain(|pending| pending.expires_at > now);
    }

    pub fn arm(&mut self, session: &str, now: Instant) {
        self.armed = Some(ArmedPasskey {
            session: Zeroizing::new(session.into()),
            request_id: self
                .pending_requests
                .last()
                .map(|pending| pending.id.clone()),
            expires_at: now + ARM_TTL,
        });
    }

    pub fn authorize(
        &mut self,
        request_id: Option<&str>,
        now: Instant,
    ) -> Option<Zeroizing<String>> {
        let request_id = valid_request_id(request_id);
        let matches_arm = self.armed.as_ref().is_some_and(|armed| {
            armed.expires_at > now
                && armed
                    .request_id
                    .as_deref()
                    .is_none_or(|armed_id| Some(armed_id) == request_id)
        });
        if !matches_arm {
            self.register(request_id, now);
            return None;
        }

        let armed = self.armed.take()?;
        self.pending_requests
            .retain(|pending| Some(pending.id.as_str()) != request_id);

        Some(armed.session)
    }

    pub fn remove_session(&mut self, session: &str) {
        if self
            .armed
            .as_ref()
            .is_some_and(|armed| armed.session.as_str() == session)
        {
            self.armed = None;
        }
    }

    fn register(&mut self, request_id: Option<&str>, now: Instant) {
        let Some(id) = request_id else {
            return;
        };
        if self.pending_requests.iter().any(|pending| pending.id == id) {
            return;
        }

        self.pending_requests.push(PendingRequest {
            id: id.into(),
            expires_at: now + REQUEST_TTL,
        });
    }
}

fn valid_request_id(request_id: Option<&str>) -> Option<&str> {
    request_id.filter(|id| !id.is_empty() && id.len() <= MAX_REQUEST_ID_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_request_is_authorized_once() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        assert!(authorization.authorize(Some("request"), now).is_none());
        authorization.arm("session", now);

        assert_eq!(
            authorization
                .authorize(Some("request"), now)
                .as_ref()
                .map(|session| session.as_str()),
            Some("session")
        );
        assert!(authorization.authorize(Some("request"), now).is_none());
    }

    #[test]
    fn arm_applies_to_the_next_request_when_none_is_pending() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.arm("session", now);

        assert_eq!(
            authorization
                .authorize(Some("request"), now)
                .as_ref()
                .map(|session| session.as_str()),
            Some("session")
        );
    }

    #[test]
    fn arm_binds_to_the_newest_distinct_pending_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.authorize(Some("first"), now);
        authorization.authorize(Some("second"), now);
        authorization.authorize(Some("first"), now);
        authorization.arm("session", now);

        assert!(authorization.authorize(Some("first"), now).is_none());
        assert_eq!(
            authorization
                .authorize(Some("second"), now)
                .as_ref()
                .map(|session| session.as_str()),
            Some("session")
        );
    }

    #[test]
    fn expired_arm_cannot_authorize_a_request() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.arm("session", now);

        assert!(
            authorization
                .authorize(Some("request"), now + ARM_TTL)
                .is_none()
        );
    }

    #[test]
    fn expired_requests_are_not_selected_for_an_arm() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.authorize(Some("expired"), now);
        authorization.expire(now + REQUEST_TTL, |_| true);
        authorization.arm("session", now + REQUEST_TTL);

        assert_eq!(
            authorization
                .authorize(Some("next"), now + REQUEST_TTL)
                .as_ref()
                .map(|session| session.as_str()),
            Some("session")
        );
    }

    #[test]
    fn removing_a_session_cancels_its_arm() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.arm("session", now);
        authorization.remove_session("session");

        assert!(authorization.authorize(Some("request"), now).is_none());
    }

    #[test]
    fn expiration_cancels_an_arm_for_an_inactive_session() {
        let now = Instant::now();
        let mut authorization = PasskeyAuthorization::default();

        authorization.arm("session", now);
        authorization.expire(now, |_| false);

        assert!(authorization.authorize(Some("request"), now).is_none());
    }
}
