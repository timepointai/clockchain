//! Response privacy hints. Authentication and private ingress enforce access;
//! crawler directives alone cannot prevent retrieval or exfiltration.
//!
//! Mounted on the v1 router only. The legacy router's responses stay
//! byte-for-byte what they were.

use axum::{extract::Request, http::header, middleware::Next, response::Response};

/// Deny-all crawler policy, embedded so the binary needs no file at runtime.
pub const ROBOTS: &str = "User-agent: *\nDisallow: /\n";

pub async fn response_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    for (name, value) in [
        ("cache-control", "private, no-store"),
        ("x-robots-tag", "noindex, nofollow, noarchive"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        headers.insert(name, value.parse().expect("static header value"));
    }
    response
}

pub async fn robots() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        ROBOTS,
    )
}
