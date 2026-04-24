use hyper::Request;
use subtle::ConstantTimeEq;

#[must_use]
pub fn host_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    allowlist.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern.as_str()
        }
    })
}

#[must_use]
pub fn has_valid_session_token<B>(req: &Request<B>, session_token: &str) -> bool {
    bearer_token(req, "authorization")
        .map(|v| constant_time_eq(v, session_token))
        .unwrap_or(false)
}

#[must_use]
fn bearer_token<'a, B>(req: &'a Request<B>, header: &str) -> Option<&'a str> {
    req.headers()
        .get(header)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    #[test]
    fn wildcard_domains_are_allowed() {
        let allowlist = vec!["*.anthropic.com".to_string()];
        assert!(host_allowed("api.anthropic.com", &allowlist));
        assert!(host_allowed("API.ANTHROPIC.COM", &allowlist));
        assert!(!host_allowed("anthropic.co", &allowlist));
    }

    #[test]
    fn validates_bearer_session_token() {
        let req = Request::builder()
            .header("authorization", "Bearer test-token")
            .body(())
            .expect("request should build");
        assert!(has_valid_session_token(&req, "test-token"));
        assert!(!has_valid_session_token(&req, "other-token"));
    }

    #[test]
    fn rejects_request_with_no_auth_headers() {
        let req = Request::builder().body(()).expect("request should build");
        assert!(!has_valid_session_token(&req, "test-token"));
    }

    #[test]
    fn wildcard_matches_apex_and_rejects_trailing_suffix() {
        let allowlist = vec!["*.anthropic.com".to_string()];
        // The apex is allowed to match because the check uses `host == suffix`.
        assert!(host_allowed("anthropic.com", &allowlist));
        // A subdomain is allowed.
        assert!(host_allowed("api.anthropic.com", &allowlist));
        // A name that only has the allowed domain as a non suffix must not match.
        assert!(!host_allowed("example.anthropic.com.evil.test", &allowlist));
        assert!(!host_allowed("anthropic.com.evil.test", &allowlist));
    }

    #[test]
    fn host_allowed_strips_trailing_dot() {
        let allowlist = vec!["api.anthropic.com".to_string()];
        assert!(host_allowed("api.anthropic.com.", &allowlist));
    }

    #[test]
    fn exact_match_is_strict() {
        let allowlist = vec!["anthropic.com".to_string()];
        assert!(host_allowed("anthropic.com", &allowlist));
        assert!(!host_allowed("api.anthropic.com", &allowlist));
        assert!(!host_allowed("xanthropic.com", &allowlist));
    }

    #[test]
    fn session_token_of_different_length_is_rejected() {
        let req = Request::builder()
            .header("authorization", "Bearer shortish")
            .body(())
            .expect("request should build");
        assert!(!has_valid_session_token(&req, "shortish-and-long"));
    }

    #[test]
    fn non_bearer_schemes_are_rejected() {
        let req = Request::builder()
            .header("authorization", "Basic c2VjcmV0")
            .body(())
            .expect("request should build");
        assert!(!has_valid_session_token(&req, "c2VjcmV0"));
    }

    #[test]
    fn raw_token_without_bearer_prefix_is_rejected() {
        let req = Request::builder()
            .header("authorization", "raw-token")
            .body(())
            .expect("request should build");
        assert!(!has_valid_session_token(&req, "raw-token"));
    }

    #[test]
    fn bearer_scheme_is_case_sensitive() {
        // strip_prefix is case sensitive by design. Treat lowercase
        // `bearer ` as invalid so a request cannot sneak past by
        // mis-casing the scheme.
        let req = Request::builder()
            .header("authorization", "bearer test-token")
            .body(())
            .expect("request should build");
        assert!(!has_valid_session_token(&req, "test-token"));
    }
}
