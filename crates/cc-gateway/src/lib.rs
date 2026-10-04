//! `cc-gateway`: the unauthenticated, read-only public face of a private v1
//! node. The contract is the `/public/v1` table in `docs/design/STAGE-G.md`
//! (G5); the operating notes are `docs/PUBLIC-ACCESS.md`.
//!
//! # What it does
//!
//! Each public route maps to exactly one node read route. The gateway calls
//! the node with its own server-side read key, removes the top-level
//! `instance` field, and returns the node's status and JSON. Nothing a client
//! sends is forwarded except the path parameter and the query string: no
//! client header, cookie or credential reaches the node, and the node's
//! headers do not reach the client.
//!
//! # What it refuses
//!
//! * **Writes.** Only `GET` and `HEAD` reach a handler; `OPTIONS` is answered
//!   as a CORS preflight; every other method is `405 read_only` before any
//!   routing. No handler issues anything but a `GET` to the node, and no route
//!   maps to a node write or export path.
//! * **Abuse.** A per-client GCRA limit (see [`limit`]) runs before the method
//!   check and before any node call, so a refused request costs the node
//!   nothing.
//! * **Node errors.** The gateway fails closed. A node that is unreachable,
//!   slow or answers 503 is `503 node_unavailable`; a node that answers
//!   anything the contract does not name (a refused credential, a redirect, a
//!   5xx, a body that is not a JSON object, a body over the size cap) is
//!   `502 bad_gateway`. A cached answer is never served in place of a failed
//!   node read.
//!
//! # What it strips, and only that
//!
//! Only the top-level `instance` key is removed. Embedded projection content
//! (`rows`, `subjects`, `revision`, and the rest) is commitment material that
//! a browser verifier recomputes from the served bytes, so it is passed
//! through as the node's raw JSON text, never re-encoded.

#![forbid(unsafe_code)]

pub mod cache;
pub mod config;
pub mod limit;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{rejection::PathRejection, ConnectInfo, Path, Request, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde_json::value::RawValue;

use crate::cache::{Cache, Entry};
use crate::config::Config;
use crate::limit::Limiter;

/// The read the gateway makes when it needs the current corpus digest and has
/// no fresh observation. No subject has the all-zero id, so this is a 404
/// `subject_unknown` that names the digest without carrying any content.
pub const PROBE: &str =
    "/v1/subjects/0000000000000000000000000000000000000000000000000000000000000000";

/// The headers every gateway response carries, refusals included.
pub const RESPONSE_HEADERS: [(&str, &str); 7] = [
    ("access-control-allow-origin", "*"),
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'",
    ),
    ("x-robots-tag", "noindex, nofollow"),
    ("access-control-expose-headers", "retry-after, x-cache"),
];

/// Statuses the node answers a read with that the contract passes through.
/// Everything else from the node is a gateway failure.
const ANSWERS: [u16; 4] = [200, 400, 404, 409];

/// Answers that name a corpus digest and may be cached under it.
const CACHEABLE: [u16; 2] = [200, 404];

#[derive(Clone)]
pub struct Gateway(Arc<Inner>);

struct Inner {
    client: reqwest::Client,
    /// The node origin without its trailing slash; paths are appended to it.
    base: String,
    /// `Bearer <read key>`, marked sensitive so no `Debug` prints it.
    auth: HeaderValue,
    max_body: usize,
    client_ip_header: Option<HeaderName>,
    cache: Cache,
    limiter: Limiter,
    probe: std::sync::Mutex<Probe>,
}

type Outcome = Result<String, Failure>;

/// The digest probe, shared. A probe runs in its own task and records its
/// outcome when it ends, whether or not the request that started it is still
/// waiting, so a client that disconnects cannot cancel it. A request takes the
/// outcome of any probe that started after it arrived; otherwise it waits for
/// the probe in flight and then joins or starts the next one. So a request
/// waits for at most two probes, however many requests are queued or dropped.
#[derive(Default)]
struct Probe {
    /// When the last finished probe started, and what it found.
    last: Option<(Instant, Outcome)>,
    /// The probe in flight: when it started, and where its outcome will appear.
    inflight: Option<(Instant, tokio::sync::watch::Receiver<Option<Outcome>>)>,
}

/// Why a node read produced no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// Unreachable, timed out, or the node said 503.
    Unavailable,
    /// The node answered outside the contract.
    BadGateway,
}

impl Failure {
    fn response(self) -> Response {
        match self {
            Failure::Unavailable => refusal(StatusCode::SERVICE_UNAVAILABLE, "node_unavailable"),
            Failure::BadGateway => refusal(StatusCode::BAD_GATEWAY, "bad_gateway"),
        }
    }
}

/// One node answer, already stripped.
struct Answer {
    status: u16,
    body: Bytes,
    digest: Option<String>,
}

impl Gateway {
    pub fn new(config: &Config) -> Gateway {
        let client = reqwest::Client::builder()
            // The read key must never be handed to an environment-configured
            // proxy, nor follow a redirect to a host it was not issued for.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.upstream_timeout)
            .build()
            .expect("a client with static settings builds");
        let mut auth =
            HeaderValue::from_str(&config.read_key.bearer()).expect("a validated key is a header");
        auth.set_sensitive(true);
        Gateway(Arc::new(Inner {
            client,
            base: config.node_url.as_str().trim_end_matches('/').to_string(),
            auth,
            max_body: config.max_body_bytes,
            client_ip_header: config.client_ip_header.clone(),
            cache: Cache::new(config.freshness, config.cache_bytes),
            limiter: Limiter::new(config.rate_per_minute),
            probe: std::sync::Mutex::new(Probe::default()),
        }))
    }
}

/// The public router. Serve it with
/// `into_make_service_with_connect_info::<SocketAddr>()` so the limit can see
/// the peer address; without it every client shares one bucket.
pub fn router(gateway: Gateway) -> Router {
    Router::new()
        .route("/public/v1/health", get(health))
        .route("/public/v1/snapshot", get(snapshot))
        .route("/public/v1/subjects/:subject_id", get(subject))
        .route("/public/v1/revisions/:revision/prose", get(prose))
        .route("/public/v1/support", get(support))
        // `/public/v1/receipts/{event}` is deliberately absent until the node
        // serves receipts (Stage (g) G4), so it is a 404 like any unknown path.
        .fallback(not_found)
        .layer(axum::middleware::from_fn(read_only))
        .layer(axum::middleware::from_fn_with_state(
            gateway.clone(),
            rate_limit,
        ))
        .layer(axum::middleware::from_fn(response_headers))
        .with_state(gateway)
}

fn refusal(status: StatusCode, error: &str) -> Response {
    json_response(status, format!("{{\"error\":\"{error}\"}}").into(), None)
}

fn json_response(status: StatusCode, body: Bytes, cache: Option<&'static str>) -> Response {
    let mut r = (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    if let Some(c) = cache {
        r.headers_mut()
            .insert("x-cache", HeaderValue::from_static(c));
    }
    r
}

async fn response_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    for (name, value) in RESPONSE_HEADERS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

async fn rate_limit(State(gw): State<Gateway>, req: Request, next: Next) -> Response {
    let ip = client_ip(&gw, &req);
    match gw.0.limiter.check(ip) {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            let mut r = refusal(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
            r.headers_mut()
                .insert(header::RETRY_AFTER, secs.max(1).into());
            r
        }
    }
}

/// The configured header when it is present and parses, else the socket peer.
fn client_ip(gw: &Gateway, req: &Request) -> IpAddr {
    let from_header = gw.0.client_ip_header.as_ref().and_then(|h| {
        req.headers()
            .get(h)?
            .to_str()
            .ok()?
            .trim()
            .parse::<IpAddr>()
            .ok()
    });
    from_header
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip())
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

async fn read_only(req: Request, next: Next) -> Response {
    match *req.method() {
        Method::GET | Method::HEAD => next.run(req).await,
        Method::OPTIONS => (
            StatusCode::NO_CONTENT,
            [
                ("access-control-allow-methods", "GET, HEAD, OPTIONS"),
                ("access-control-max-age", "600"),
            ],
        )
            .into_response(),
        _ => {
            let mut r = refusal(StatusCode::METHOD_NOT_ALLOWED, "read_only");
            r.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            r
        }
    }
}

async fn not_found() -> Response {
    refusal(StatusCode::NOT_FOUND, "no_such_route")
}

/// A path parameter is forwarded only if it is plain ASCII alphanumerics of a
/// sane length, so it cannot carry a dot segment, a slash or an encoding that
/// would make the node URL name a different route. Anything else is replaced by
/// a fixed non-hex token, which the node refuses exactly as it refuses the
/// original: neither is 64 lowercase hex.
fn segment(p: Result<Path<String>, PathRejection>) -> String {
    match p {
        Ok(Path(s))
            if (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            s
        }
        _ => "invalid".to_string(),
    }
}

fn with_query(path: String, uri: &Uri) -> String {
    match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    }
}

async fn health(State(gw): State<Gateway>) -> Response {
    match gw.fetch("/health", false).await {
        Ok(a) => json_response(status(a.status), a.body, None),
        Err(f) => f.response(),
    }
}

async fn snapshot(State(gw): State<Gateway>, uri: Uri) -> Response {
    gw.cached(with_query("/v1/snapshot".into(), &uri)).await
}

async fn subject(
    State(gw): State<Gateway>,
    uri: Uri,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let path = format!("/v1/subjects/{}", segment(id));
    gw.cached(with_query(path, &uri)).await
}

async fn prose(
    State(gw): State<Gateway>,
    uri: Uri,
    revision: Result<Path<String>, PathRejection>,
) -> Response {
    let path = format!("/v1/revisions/{}/prose", segment(revision));
    gw.cached(with_query(path, &uri)).await
}

async fn support(State(gw): State<Gateway>, uri: Uri) -> Response {
    gw.cached(with_query("/v1/support".into(), &uri)).await
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).expect("only contract statuses reach here")
}

impl Gateway {
    /// A corpus read: served from the cache when the current digest is known
    /// and the answer for it is held, otherwise read from the node.
    async fn cached(&self, key: String) -> Response {
        let digest = match self.current_digest().await {
            Ok(d) => d,
            Err(f) => return f.response(),
        };
        if let Some(e) = self.0.cache.get(&digest, &key) {
            return json_response(status(e.status), e.body, Some("hit"));
        }
        match self.fetch(&key, true).await {
            Ok(a) => {
                if let (true, Some(d)) = (CACHEABLE.contains(&a.status), &a.digest) {
                    let entry = Entry {
                        status: a.status,
                        body: a.body.clone(),
                    };
                    self.0.cache.put(d, &key, entry);
                }
                json_response(status(a.status), a.body, Some("miss"))
            }
            Err(f) => f.response(),
        }
    }

    /// The fresh digest, or the outcome of a shared probe (see [`Probe`]).
    async fn current_digest(&self) -> Outcome {
        let arrived = Instant::now();
        if let Some(d) = self.0.cache.fresh_digest(arrived) {
            return Ok(d);
        }
        loop {
            let mut rx = {
                let mut p = self.0.probe.lock().unwrap_or_else(|e| e.into_inner());
                if let Some((started, outcome)) = &p.last {
                    if *started >= arrived {
                        return outcome.clone();
                    }
                }
                if let Some((_, rx)) = &p.inflight {
                    rx.clone()
                } else {
                    if let Some(d) = self.0.cache.fresh_digest(Instant::now()) {
                        return Ok(d);
                    }
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    let started = Instant::now();
                    p.inflight = Some((started, rx.clone()));
                    let gw = self.clone();
                    tokio::spawn(async move {
                        let outcome = gw.probe().await;
                        let mut p = gw.0.probe.lock().unwrap_or_else(|e| e.into_inner());
                        p.last = Some((started, outcome.clone()));
                        p.inflight = None;
                        drop(p);
                        let _ = tx.send(Some(outcome));
                    });
                    rx
                }
            };
            if rx.wait_for(Option::is_some).await.is_err() {
                // The probe task ended without an outcome; never wait on it again.
                self.0
                    .probe
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .inflight = None;
                return Err(Failure::BadGateway);
            }
        }
    }

    /// One digest read from the node.
    async fn probe(&self) -> Outcome {
        match self.fetch(PROBE, true).await {
            Ok(Answer {
                status: 200 | 404,
                digest: Some(d),
                ..
            }) => Ok(d),
            Ok(_) => {
                tracing::warn!("node probe named no corpus digest");
                Err(Failure::BadGateway)
            }
            Err(f) => Err(f),
        }
    }

    /// One `GET` to the node. Only the read key and `Accept` are sent.
    async fn fetch(&self, path: &str, authorized: bool) -> Result<Answer, Failure> {
        let requested = Instant::now();
        let mut req = self
            .0
            .client
            .get(format!("{}{path}", self.0.base))
            .header(header::ACCEPT, "application/json");
        if authorized {
            req = req.header(header::AUTHORIZATION, self.0.auth.clone());
        }
        let mut resp = req.send().await.map_err(|e| {
            tracing::warn!(
                timeout = e.is_timeout(),
                connect = e.is_connect(),
                "node unreachable"
            );
            Failure::Unavailable
        })?;
        let code = resp.status().as_u16();
        if code == 503 {
            tracing::warn!("node answered 503");
            return Err(Failure::Unavailable);
        }
        if !ANSWERS.contains(&code) {
            if code == 401 || code == 403 {
                tracing::error!(status = code, "node refused the gateway read key");
            } else {
                tracing::warn!(status = code, "node answered outside the contract");
            }
            return Err(Failure::BadGateway);
        }
        let mut raw = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(c)) if raw.len() + c.len() <= self.0.max_body => raw.extend_from_slice(&c),
                Ok(Some(_)) => {
                    tracing::warn!("node answer exceeds the body cap");
                    return Err(Failure::BadGateway);
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(timeout = e.is_timeout(), "node answer was cut off");
                    return Err(Failure::Unavailable);
                }
            }
        }
        let (body, digest) = strip(&raw).ok_or_else(|| {
            tracing::warn!("node answer is not a JSON object");
            Failure::BadGateway
        })?;
        if let Some(d) = &digest {
            self.0.cache.observe(d, requested);
        }
        Ok(Answer {
            status: code,
            body,
            digest,
        })
    }
}

/// Remove the top-level `instance` key from a JSON object, leaving every other
/// value as the node's exact text, and read its `corpus_digest` if it names a
/// well-formed one. `None` if the body is not a JSON object.
pub fn strip(raw: &[u8]) -> Option<(Bytes, Option<String>)> {
    let mut doc: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(raw).ok()?;
    doc.remove("instance");
    let digest = doc
        .get("corpus_digest")
        .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
        .filter(|d| d.len() == 64 && d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    let body = serde_json::to_vec(&doc).ok()?;
    Some((Bytes::from(body), digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_only_the_top_level_instance() {
        let raw =
            br#"{"instance":"ab","ledger":"v1","rows":[{"instance":1,"n":18446744073709551616}]}"#;
        let (body, digest) = strip(raw).unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"ledger":"v1","rows":[{"instance":1,"n":18446744073709551616}]}"#
        );
        assert!(digest.is_none());
    }

    #[test]
    fn strip_reads_only_a_well_formed_digest_and_refuses_non_objects() {
        let d = "ab".repeat(32);
        let (_, got) = strip(format!(r#"{{"corpus_digest":"{d}"}}"#).as_bytes()).unwrap();
        assert_eq!(got.as_deref(), Some(d.as_str()));
        let (_, upper) =
            strip(format!(r#"{{"corpus_digest":"{}"}}"#, d.to_uppercase()).as_bytes()).unwrap();
        assert!(upper.is_none());
        for bad in [&b"[]"[..], b"\"x\"", b"not json", b"{\"a\":1"] {
            assert!(strip(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn unsafe_path_segments_never_reach_the_node_url() {
        let ok = |s: &str| segment(Ok(Path(s.to_string())));
        assert_eq!(ok("ab12"), "ab12");
        for bad in ["..", "a/b", "%2e%2e", "a.b", "", &"a".repeat(129)] {
            assert_eq!(ok(bad), "invalid", "{bad:?}");
        }
    }
}
