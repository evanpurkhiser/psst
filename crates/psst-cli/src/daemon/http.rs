use std::{net::SocketAddr, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tokio::{net::TcpListener, time::timeout};
use tower_http::cors::CorsLayer;
use zeroize::Zeroize;

use crate::{
    daemon::{
        browser_protocol::{AssertionRequest, EXTENSION_ORIGIN, ErrorResponse, PasskeyResult},
        passkey_authorization::Poll,
        service::Service,
    },
    error::Error,
};

const MAX_SHARE_REQUEST_BYTES: usize = 4 * 1024;
const MAX_BROWSER_REQUEST_BYTES: usize = 64 * 1024;
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenRequest {
    share_url: String,
}

impl Drop for OpenRequest {
    fn drop(&mut self) {
        self.share_url.zeroize();
    }
}

pub async fn serve(
    service: Service,
    sharing_address: SocketAddr,
    browser_address: SocketAddr,
) -> std::io::Result<()> {
    let sharing_listener = TcpListener::bind(sharing_address).await?;
    let browser_listener = TcpListener::bind(browser_address).await?;
    let sharing = axum::serve(sharing_listener, sharing_router(service.clone()));
    let browser = axum::serve(browser_listener, browser_router(service));

    tokio::try_join!(sharing, browser)?;
    Ok(())
}

fn sharing_router(service: Service) -> Router {
    Router::new()
        .route("/sessions", post(open_session))
        .layer(DefaultBodyLimit::max(MAX_SHARE_REQUEST_BYTES))
        .with_state(service)
}

fn browser_router(service: Service) -> Router {
    let origin = HeaderValue::from_static(EXTENSION_ORIGIN);
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::POST, Method::GET, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    Router::new()
        .route("/passkey-requests", post(register_passkey))
        .route(
            "/passkey-requests/{request_id}",
            get(poll_passkey).delete(cancel_passkey),
        )
        .layer(DefaultBodyLimit::max(MAX_BROWSER_REQUEST_BYTES))
        .layer(cors)
        .with_state(service)
}

async fn open_session(
    State(service): State<Service>,
    Json(request): Json<OpenRequest>,
) -> Response {
    match service.open(&request.share_url).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(error) => api_error(error),
    }
}

async fn register_passkey(
    State(service): State<Service>,
    Json(request): Json<AssertionRequest>,
) -> Response {
    match service.register_passkey(request).await {
        Ok(registration) => (StatusCode::CREATED, Json(registration)).into_response(),
        Err(error) => api_error(error),
    }
}

async fn poll_passkey(
    State(service): State<Service>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(capability) = capability(&headers) else {
        return capability_error();
    };
    let poll = match service.poll_passkey(&request_id, capability).await {
        Ok(poll) => poll,
        Err(Error::PasskeyHandoffExpired) => {
            return (StatusCode::GONE, Json(PasskeyResult::Expired)).into_response();
        }
        Err(error) => return api_error(error),
    };
    let Poll::Pending(changed) = poll else {
        return ready(poll);
    };

    if timeout(LONG_POLL_TIMEOUT, changed.notified())
        .await
        .is_err()
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    match service.poll_passkey(&request_id, capability).await {
        Ok(poll) => ready(poll),
        Err(Error::PasskeyHandoffExpired) => {
            (StatusCode::GONE, Json(PasskeyResult::Expired)).into_response()
        }
        Err(error) => api_error(error),
    }
}

async fn cancel_passkey(
    State(service): State<Service>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(capability) = capability(&headers) else {
        return capability_error();
    };
    match service.cancel_passkey(&request_id, capability).await {
        Ok(()) | Err(Error::PasskeyHandoffExpired) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => api_error(error),
    }
}

fn ready(poll: Poll) -> Response {
    match poll {
        Poll::Ready(result) => (StatusCode::OK, Json(result)).into_response(),
        Poll::Pending(_) => StatusCode::NO_CONTENT.into_response(),
    }
}

fn capability(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
}

fn capability_error() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            code: "browser_capability_invalid".into(),
            message: "the browser passkey capability is invalid".into(),
        }),
    )
        .into_response()
}

fn api_error(error: Error) -> Response {
    let status = match error {
        Error::InvalidLink(_) | Error::WebAuthnRequest(_) => StatusCode::BAD_REQUEST,
        Error::BrowserCapability => StatusCode::FORBIDDEN,
        Error::BrowserRequestBusy => StatusCode::CONFLICT,
        Error::BrowserRequestLimit => StatusCode::TOO_MANY_REQUESTS,
        Error::PasskeyHandoffExpired => StatusCode::GONE,
        Error::InputSizeLimit(_) | Error::ResponseSizeLimit(_) => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::BAD_GATEWAY,
    };
    let body = ErrorResponse {
        code: error.code().into(),
        message: error.to_string(),
    };
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_capabilities_are_required() {
        let mut headers = HeaderMap::new();
        assert!(capability(&headers).is_none());

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert_eq!(capability(&headers), Some("token"));
    }
}
