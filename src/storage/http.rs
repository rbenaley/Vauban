//! Machine-readable HTTP status mapping for storage-backed surfaces.

use topcoat::{
    Result,
    context::Cx,
    router::{
        Body, StatusCode,
        error::service_unavailable,
        header,
        response::{IntoResponse, Response},
    },
};

/// `Retry-After` for helper-down / integrity / busy 503s (not login lockout).
pub const STORE_RETRY_AFTER_SECS: u64 = 30;

/// Plain-text machine response. 503s use Topcoat `service_unavailable` then
/// swap the body so callers still see VCP codes (`integrity mismatch`, …).
pub fn machine_plain_response(cx: &Cx, status: StatusCode, body: &str) -> Result<Response> {
    if status == StatusCode::SERVICE_UNAVAILABLE {
        let mut resp = service_unavailable(STORE_RETRY_AFTER_SECS).into_response(cx)?;
        *resp.body_mut() = Body::from(body.to_owned());
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return Ok(resp);
    }
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body.to_owned()))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn store_unavailable_is_503_retry_after_and_exact_body() {
        let resp = machine_plain_response(
            &Cx::default(),
            StatusCode::SERVICE_UNAVAILABLE,
            "integrity mismatch",
        )
        .expect("resp");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&bytes[..], b"integrity mismatch");
    }

    #[tokio::test]
    async fn non_503_stays_bare_status_without_retry_after() {
        let resp =
            machine_plain_response(&Cx::default(), StatusCode::BAD_REQUEST, "digest mismatch")
                .expect("resp");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&bytes[..], b"digest mismatch");
    }
}
