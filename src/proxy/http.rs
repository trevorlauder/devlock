use crate::proxy::error::ProxyError;
use http_body_util::combinators::{BoxBody, UnsyncBoxBody};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::pin::Pin;
use std::task::{Context, Poll};

pub const REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;
pub const RESPONSE_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Response body type: streamed from upstream or buffered from the proxy.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Client request body type: streamed from the agent through to upstream.
pub type ClientBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

pub fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn streaming_body(body: Incoming) -> ProxyBody {
    body.boxed()
}

pub fn full_client_body(data: impl Into<Bytes>) -> ClientBody {
    Full::new(data.into())
        .map_err(
            |never: std::convert::Infallible| -> Box<dyn std::error::Error + Send + Sync> {
                match never {}
            },
        )
        .boxed_unsync()
}

pub async fn collect_limited(mut body: Incoming, limit: usize) -> Result<Bytes, ProxyError> {
    let mut out = Vec::new();

    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|e| ProxyError::Upstream(e.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > limit {
                return Err(ProxyError::BodyTooLarge { limit });
            }
            out.extend_from_slice(data);
        }
    }

    Ok(Bytes::from(out))
}

/// Body wrapper that aborts the stream with an error once cumulative bytes
/// exceed `limit`. A size breach means a partial body has already been sent
/// upstream, so the client connection is torn down rather than answered 413.
pub struct LimitedBody<B> {
    inner: B,
    seen: usize,
    limit: usize,
}

impl<B> LimitedBody<B> {
    pub fn new(inner: B, limit: usize) -> Self {
        Self {
            inner,
            seen: 0,
            limit,
        }
    }
}

impl<B> Body for LimitedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(
                Box::new(e) as Box<dyn std::error::Error + Send + Sync>
            ))),
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.seen = this.seen.saturating_add(data.len());
                    if this.seen > this.limit {
                        let limit = this.limit;
                        return Poll::Ready(Some(Err(format!(
                            "request body exceeds {limit} bytes"
                        )
                        .into())));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

pub fn response_with_status(status: StatusCode, body: impl Into<Bytes>) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(full_body(body.into()))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::from_static(b"response build error"))))
}

pub fn bad_gateway(err: impl std::fmt::Display) -> Response<ProxyBody> {
    let _ = err;
    response_with_status(StatusCode::BAD_GATEWAY, Bytes::from_static(b"bad gateway"))
}

pub fn proxy_auth_required() -> Response<ProxyBody> {
    response_with_status(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        Bytes::from_static(b"invalid session token"),
    )
}

pub fn forbidden_host() -> Response<ProxyBody> {
    response_with_status(
        StatusCode::FORBIDDEN,
        Bytes::from_static(b"host not allowed"),
    )
}

pub fn payload_too_large() -> Response<ProxyBody> {
    response_with_status(
        StatusCode::PAYLOAD_TOO_LARGE,
        Bytes::from_static(b"payload too large"),
    )
}

pub fn method_not_allowed() -> Response<ProxyBody> {
    response_with_status(
        StatusCode::METHOD_NOT_ALLOWED,
        Bytes::from_static(b"method not allowed"),
    )
}

pub fn internal_error() -> Response<ProxyBody> {
    response_with_status(
        StatusCode::INTERNAL_SERVER_ERROR,
        Bytes::from_static(b"internal server error"),
    )
}

pub fn build_request(
    method: hyper::Method,
    uri: &str,
    headers: &hyper::HeaderMap,
    body: ClientBody,
    access_token: &str,
    inject_headers: &std::collections::BTreeMap<String, String>,
) -> Result<Request<ClientBody>, ProxyError> {
    let mut builder = Request::builder().method(method).uri(uri);

    let mut forwarded: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();

    for (key, value) in headers {
        let name = key.as_str();
        if name == "host"
            || name == "x-api-key"
            || name == "authorization"
            || name == "proxy-authorization"
        {
            continue;
        }
        let v = value.to_str().unwrap_or("").to_string();
        forwarded.insert(name.to_string(), v);
    }

    for (inj_key, inj_value) in inject_headers {
        let key = inj_key.to_ascii_lowercase();
        match forwarded.get(&key) {
            Some(existing) if existing.split(',').any(|part| part.trim() == inj_value) => {}
            Some(existing) => {
                forwarded.insert(key, format!("{existing},{inj_value}"));
            }
            None => {
                forwarded.insert(key, inj_value.clone());
            }
        }
    }

    for (k, v) in forwarded {
        builder = builder.header(k, v);
    }

    Ok(builder
        .header("authorization", format!("Bearer {access_token}"))
        .body(body)?)
}

/// Convert an upstream response into a streaming proxy response.
pub fn stream_response(resp: Response<Incoming>) -> Response<ProxyBody> {
    let (parts, body) = resp.into_parts();
    Response::from_parts(parts, streaming_body(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
    use std::collections::BTreeMap;

    fn header(req: &Request<ClientBody>, name: &str) -> String {
        req.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    }

    fn empty_body() -> ClientBody {
        full_client_body(Bytes::new())
    }

    #[test]
    fn inject_headers_adds_when_absent() {
        let mut inject = BTreeMap::new();
        inject.insert("anthropic-beta".into(), "oauth-2025-04-20".into());
        let req = build_request(
            hyper::Method::POST,
            "https://example.test/v1/x",
            &HeaderMap::new(),
            empty_body(),
            "tok",
            &inject,
        )
        .unwrap();
        assert_eq!(header(&req, "anthropic-beta"), "oauth-2025-04-20");
    }

    #[test]
    fn inject_headers_appends_when_value_missing() {
        let mut in_headers = HeaderMap::new();
        in_headers.insert("anthropic-beta", "existing-flag".parse().unwrap());
        let mut inject = BTreeMap::new();
        inject.insert("anthropic-beta".into(), "oauth-2025-04-20".into());
        let req = build_request(
            hyper::Method::POST,
            "https://example.test/v1/x",
            &in_headers,
            empty_body(),
            "tok",
            &inject,
        )
        .unwrap();
        assert_eq!(
            header(&req, "anthropic-beta"),
            "existing-flag,oauth-2025-04-20"
        );
    }

    #[test]
    fn inject_headers_noop_when_value_already_present() {
        let mut in_headers = HeaderMap::new();
        in_headers.insert(
            "anthropic-beta",
            "other-flag, oauth-2025-04-20".parse().unwrap(),
        );
        let mut inject = BTreeMap::new();
        inject.insert("anthropic-beta".into(), "oauth-2025-04-20".into());
        let req = build_request(
            hyper::Method::POST,
            "https://example.test/v1/x",
            &in_headers,
            empty_body(),
            "tok",
            &inject,
        )
        .unwrap();
        assert_eq!(
            header(&req, "anthropic-beta"),
            "other-flag, oauth-2025-04-20"
        );
    }

    #[test]
    fn no_inject_when_map_empty() {
        let inject = BTreeMap::new();
        let req = build_request(
            hyper::Method::GET,
            "https://example.test/v1/x",
            &HeaderMap::new(),
            empty_body(),
            "tok",
            &inject,
        )
        .unwrap();
        assert!(req.headers().get("anthropic-beta").is_none());
    }

    #[tokio::test]
    async fn limited_body_passes_through_under_limit() {
        let payload = Bytes::from_static(b"hello");
        let limited = LimitedBody::new(Full::new(payload.clone()), 100);
        let collected = limited
            .collect()
            .await
            .expect("under limit must not error")
            .to_bytes();
        assert_eq!(collected, payload);
    }

    #[tokio::test]
    async fn limited_body_errors_when_exceeded() {
        let payload = Bytes::from_static(b"0123456789");
        let limited = LimitedBody::new(Full::new(payload), 4);
        let err = limited.collect().await.expect_err("over limit must error");
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn limited_body_allows_exact_limit() {
        let payload = Bytes::from_static(b"abcd");
        let limited = LimitedBody::new(Full::new(payload.clone()), 4);
        let collected = limited
            .collect()
            .await
            .expect("exact limit must not error")
            .to_bytes();
        assert_eq!(collected, payload);
    }
}
