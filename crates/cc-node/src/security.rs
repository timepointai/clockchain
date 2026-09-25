//! Response privacy hints. Authentication and private ingress enforce access;
//! crawler directives alone cannot prevent retrieval or exfiltration.

use axum::{extract::Request, middleware::Next, response::Response};

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

pub async fn robots() -> &'static str {
    include_str!("../../../robots.txt")
}
