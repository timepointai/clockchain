//! The v1 node client: `/health`, the body and candidate writes, and the
//! subject/prose readback. Tokens are passed in by the caller, which reads
//! them from the environment; they go only to authenticated routes and are
//! redacted from every error, receipt and report, which can quote the node.
use super::genesis::{write_new, Genesis};
use super::{hash_json, time};
use anyhow::{bail, ensure, Context, Result};
use cc_core::v1::receipt::FoldRef;
use cc_core::v1::rule::{fold_v1, supported_fold};
use cc_core::v1::{hash, AssertedTime, Hash};
use cc_filter::v1::FilterIdentity;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode, Url};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

/// Largest response body read from a node.
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
pub const RECEIPT_FILE: &str = "receipt.json";
pub const RECEIPT_SCHEMA: &str = "cc.publisher.v1.receipt";

/// One v1 node at a base URL: `https://`, or plain `http://` to a local host
/// (see [`plain_http_allowed`]).
pub struct Node {
    base: Url,
    http: reqwest::Client,
    /// Sent only to authenticated routes, and redacted from every error.
    token: Option<String>,
}
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}
/// Plain http only where a bearer token cannot cross the public internet:
/// loopback addresses, `localhost`, and single-label host names such as a
/// container name on a private network. Any other host needs https.
fn plain_http_allowed(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    }
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost" || !host.contains('.'),
    }
}

impl Node {
    pub fn new(url: &str, token: Option<&str>) -> Result<Self> {
        // The input is not echoed: it could carry credentials.
        let mut base = Url::parse(url).map_err(|e| anyhow::anyhow!("invalid node URL: {e}"))?;
        ensure!(
            base.username().is_empty() && base.password().is_none(),
            "node URL must not carry credentials"
        );
        ensure!(
            base.query().is_none() && base.fragment().is_none(),
            "node URL must not carry a query or fragment"
        );
        match base.scheme() {
            "https" => {}
            "http" if plain_http_allowed(&base) => {}
            "http" => bail!(
                "refusing plain http to {}; use https (plain http is only for loopback and single-label local hosts)",
                base.host_str().unwrap_or_default()
            ),
            other => bail!("unsupported node URL scheme {other:?}"),
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        if let Some(t) = token {
            ensure!(!t.trim().is_empty(), "node token is empty");
            ensure!(
                t.trim() == t,
                "node token must not start or end with whitespace"
            );
            HeaderValue::from_str(&format!("Bearer {t}")).map_err(|_| {
                anyhow::anyhow!("node token contains characters not allowed in a header")
            })?;
        }
        let mut http = reqwest::Client::builder();
        if base.scheme() == "http" {
            // A proxy would see a plain-http bearer token; https is tunneled.
            http = http.no_proxy();
        }
        let http = http
            // A token is never replayed to a redirect target.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("cc-publisher/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            base,
            http,
            token: token.map(str::to_owned),
        })
    }
    pub fn url(&self) -> &str {
        self.base.as_str()
    }

    /// `text` with the token replaced by `<redacted>`, in case a node echoes it.
    pub fn redact(&self, text: &str) -> String {
        match &self.token {
            Some(t) => text.replace(t.as_str(), "<redacted>"),
            None => text.to_owned(),
        }
    }
    /// [`Node::redact`] applied to every string and key of a JSON value.
    pub fn redact_json(&self, v: &mut Value) {
        match v {
            Value::String(s) => *s = self.redact(s),
            Value::Array(a) => a.iter_mut().for_each(|x| self.redact_json(x)),
            Value::Object(o) => {
                *o = std::mem::take(o)
                    .into_iter()
                    .map(|(k, mut x)| {
                        self.redact_json(&mut x);
                        (self.redact(&k), x)
                    })
                    .collect();
            }
            _ => {}
        }
    }
    /// A response body for an error message: at most 300 characters, control
    /// characters blanked, and the token redacted.
    fn snippet(&self, body: &[u8]) -> String {
        let text = self.redact(&String::from_utf8_lossy(body));
        text.chars()
            .take(300)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    }
    pub(crate) fn json(&self, reply: &Reply, what: &str) -> Result<Value> {
        serde_json::from_slice(&reply.body).with_context(|| {
            format!(
                "{what}: response is not JSON: {}",
                self.snippet(&reply.body)
            )
        })
    }
    pub(crate) fn unexpected(&self, what: &str, reply: &Reply) -> anyhow::Error {
        anyhow::anyhow!(
            "{what}: HTTP {}: {}",
            reply.status,
            self.snippet(&reply.body)
        )
    }

    /// `authenticated` sends the bearer token; public routes never get it.
    pub(crate) async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        authenticated: bool,
    ) -> Result<Reply> {
        let url = self.base.join(path)?;
        let mut request = self.http.request(method.clone(), url);
        if let (true, Some(t)) = (authenticated, &self.token) {
            let mut v = HeaderValue::from_str(&format!("Bearer {t}"))?;
            v.set_sensitive(true);
            request = request.header(AUTHORIZATION, v);
        }
        if let Some(body) = body {
            request = request
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(body.to_vec());
        }
        let mut response = request
            .send()
            .await
            .with_context(|| format!("{method} /{path}"))?;
        let status = response.status();
        let mut out = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                out.len() + chunk.len() <= MAX_RESPONSE,
                "{method} /{path}: response exceeds {MAX_RESPONSE} bytes"
            );
            out.extend_from_slice(&chunk);
        }
        Ok(Reply { status, body: out })
    }
    /// `GET /health`: public, so no token is sent.
    pub async fn health(&self) -> Result<Health> {
        let reply = self.send(Method::GET, "health", None, false).await?;
        if reply.status != StatusCode::OK {
            return Err(self.unexpected("GET /health", &reply));
        }
        Health::parse(&self.json(&reply, "GET /health")?)
    }
    /// `PUT /v1/bodies/{sha256}`: 201 when stored, 200 when already present.
    pub async fn put_body(&self, body: &[u8]) -> Result<StatusCode> {
        let path = format!("v1/bodies/{}", hex::encode(hash(body)));
        let reply = self.send(Method::PUT, &path, Some(body), true).await?;
        match reply.status {
            StatusCode::CREATED | StatusCode::OK => Ok(reply.status),
            _ => Err(self.unexpected(&format!("PUT /{path}"), &reply)),
        }
    }
    /// `POST /v1/candidates`: the HTTP status and the node's admission outcome.
    pub async fn post_candidate(&self, envelope: &[u8]) -> Result<(StatusCode, Admission)> {
        let reply = self
            .send(Method::POST, "v1/candidates", Some(envelope), true)
            .await?;
        match reply.status {
            StatusCode::CREATED | StatusCode::ACCEPTED | StatusCode::UNPROCESSABLE_ENTITY => Ok((
                reply.status,
                Admission::parse(&self.json(&reply, "POST /v1/candidates")?)?,
            )),
            _ => Err(self.unexpected("POST /v1/candidates", &reply)),
        }
    }
    /// `GET /v1/subjects/{id}`; `None` when the node does not know the subject.
    pub async fn subject(&self, id: Hash) -> Result<Option<Value>> {
        let path = format!("v1/subjects/{}", hex::encode(id));
        let reply = self.send(Method::GET, &path, None, true).await?;
        match reply.status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => {
                let v = self.json(&reply, &format!("GET /{path}"))?;
                let unknown =
                    v.get("visibility").and_then(Value::as_str) == Some("subject_unknown");
                Ok((!unknown).then_some(v))
            }
            _ => Err(self.unexpected(&format!("GET /{path}"), &reply)),
        }
    }
    /// `GET /v1/revisions/{revision}/prose`.
    pub async fn prose(&self, revision: Hash) -> Result<Value> {
        let path = format!("v1/revisions/{}/prose", hex::encode(revision));
        let reply = self.send(Method::GET, &path, None, true).await?;
        if reply.status != StatusCode::OK {
            return Err(self.unexpected(&format!("GET /{path}"), &reply));
        }
        self.json(&reply, &format!("GET /{path}"))
    }
}

/// The v1 `/health` document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub ledger: String,
    pub build: Option<String>,
    pub posture: String,
    pub semantic: String,
    pub instance: Hash,
    pub fold: FoldRef,
    pub filter_version: Hash,
    pub curators: Vec<Hash>,
    pub max_hops: u16,
}
impl Health {
    pub fn parse(v: &Value) -> Result<Self> {
        let text = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("/health lacks string field {k:?}"))
        };
        let id = |k: &str| {
            v.get(k)
                .and_then(hash_json)
                .with_context(|| format!("/health lacks 32-byte field {k:?}"))
        };
        let fold = v
            .get("fold_version")
            .context("/health lacks fold_version")?;
        Ok(Self {
            ledger: text("ledger")?,
            build: v.get("build").and_then(Value::as_str).map(str::to_owned),
            posture: text("posture")?,
            semantic: text("semantic")?,
            instance: id("instance")?,
            fold: FoldRef {
                version: fold
                    .get("version")
                    .and_then(Value::as_u64)
                    .and_then(|n| u16::try_from(n).ok())
                    .context("/health fold_version.version is not a u16")?,
                manifest: fold
                    .get("manifest")
                    .and_then(hash_json)
                    .context("/health fold_version.manifest is not 32 bytes")?,
            },
            filter_version: id("filter_version")?,
            curators: v
                .get("curators")
                .and_then(Value::as_array)
                .context("/health lacks curators")?
                .iter()
                .map(|c| hash_json(c).context("/health curator is not a 32-byte key"))
                .collect::<Result<_>>()?,
            max_hops: v
                .get("max_hops")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .context("/health max_hops is not a u16")?,
        })
    }
    /// The node runs exactly this build's `fold_v1()`.
    pub fn fold_matches(&self) -> bool {
        supported_fold(&self.fold)
    }
    /// The reported filter version is the governed identity this build
    /// computes for the reported curators and hop bound.
    pub fn filter_consistent(&self) -> bool {
        FilterIdentity::governed(self.curators.clone(), self.max_hops)
            .is_ok_and(|f| f.version() == self.filter_version)
    }
    pub fn to_json(&self) -> Value {
        json!({
            "ledger": self.ledger,
            "build": self.build,
            "posture": self.posture,
            "semantic": self.semantic,
            "instance": hex::encode(self.instance),
            "fold_version": fold_json(&self.fold),
            "filter_version": hex::encode(self.filter_version),
            "curators": self.curators.iter().map(hex::encode).collect::<Vec<_>>(),
            "max_hops": self.max_hops,
        })
    }
}
fn fold_json(f: &FoldRef) -> Value {
    json!({"version": f.version, "manifest": hex::encode(f.manifest)})
}

/// `node-info` output: the node's identity and this build's fold check.
pub fn node_info(node: &Node, h: &Health) -> Value {
    json!({
        "node": node.url(),
        "health": h.to_json(),
        "build_fold_version": fold_json(&fold_v1()),
        "fold_matches_build": h.fold_matches(),
        "filter_version_consistent": h.filter_consistent(),
    })
}

/// The node's admission outcome for one envelope.
#[derive(Clone, Debug)]
pub struct Admission {
    pub event: Option<Hash>,
    pub input_digest: Hash,
    pub state: String,
    pub reason: String,
}
impl Admission {
    fn parse(v: &Value) -> Result<Self> {
        let status = v.get("status").context("outcome lacks status")?;
        Ok(Self {
            event: match v.get("event") {
                None | Some(Value::Null) => None,
                Some(e) => Some(hash_json(e).context("outcome event is not 32 bytes")?),
            },
            input_digest: v
                .get("input_digest")
                .and_then(hash_json)
                .context("outcome lacks input_digest")?,
            state: status
                .get("state")
                .and_then(Value::as_str)
                .context("outcome lacks status.state")?
                .into(),
            reason: status
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
        })
    }
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "event": self.event.map(hex::encode),
            "input_digest": hex::encode(self.input_digest),
            "state": self.state,
            "reason": self.reason,
        })
    }
}

/// The checks `submit` runs before writing anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trust {
    pub instance: bool,
    pub fold: bool,
    pub curator: bool,
    pub filter: bool,
}
impl Trust {
    pub fn of(h: &Health, g: &Genesis) -> Self {
        Self {
            instance: h.instance == g.instance(),
            fold: h.fold_matches(),
            curator: h.curators.contains(&g.author()),
            filter: h.filter_consistent(),
        }
    }
    /// One message per failed check.
    pub fn failures(&self, h: &Health, g: &Genesis) -> Vec<String> {
        let mut out = Vec::new();
        if !self.instance {
            out.push(format!(
                "instance mismatch: node {} != envelope {}",
                hex::encode(h.instance),
                hex::encode(g.instance())
            ));
        }
        if !self.fold {
            out.push(format!(
                "fold_version mismatch: node {}/{} != this build {}/{}",
                h.fold.version,
                hex::encode(h.fold.manifest),
                fold_v1().version,
                hex::encode(fold_v1().manifest)
            ));
        }
        if !self.curator {
            out.push(format!(
                "author {} is not in the node's curator set",
                hex::encode(g.author())
            ));
        }
        if !self.filter {
            out.push(format!(
                "node filter_version {} is not this build's governed identity for its curators and max_hops",
                hex::encode(h.filter_version)
            ));
        }
        out
    }
    fn to_json(&self, allow_untrusted: bool, overridden: &[String]) -> Value {
        json!({
            "instance_matches": self.instance,
            "fold_matches": self.fold,
            "author_is_curator": self.curator,
            "filter_version_consistent": self.filter,
            "allow_untrusted": allow_untrusted,
            "overridden": overridden,
        })
    }
}

/// Node states in which no write is attempted, trusted or not.
pub(crate) fn writable(h: &Health) -> Result<()> {
    ensure!(
        h.ledger == "v1",
        "node reports ledger {:?}, not \"v1\"",
        h.ledger
    );
    ensure!(
        h.posture != "frozen",
        "node posture is frozen; it refuses writes"
    );
    ensure!(
        h.semantic == "ready",
        "node semantic readiness is {:?}, not \"ready\"",
        h.semantic
    );
    Ok(())
}

/// What `submit` did, for the caller to print.
pub struct Submitted {
    pub receipt: Value,
    pub receipt_written: bool,
    pub warnings: Vec<String>,
}

/// One human-readable line per step of a completed `submit`.
pub fn summary(done: &Submitted, dir: &Path) -> Vec<String> {
    if let Some(lines) = super::authority_node::summary(done, dir) {
        return lines;
    }
    let r = &done.receipt;
    let body = match r["body"]["result"].as_str() {
        Some("stored") => "stored (HTTP 201)".to_owned(),
        _ => "already present on the node (HTTP 200)".to_owned(),
    };
    let envelope = match r["admission"]["result"].as_str() {
        Some("admitted") => "admitted as valid (HTTP 201)".to_owned(),
        _ => "already admitted; not re-posted".to_owned(),
    };
    let path = dir.join(RECEIPT_FILE);
    vec![
        format!("body      {body}"),
        format!("envelope  {envelope}"),
        format!(
            "readback  subject {} resolved and visible at revision {}; prose equals {} ({} bytes)",
            r["subject"].as_str().unwrap_or_default(),
            r["revision"].as_str().unwrap_or_default(),
            super::genesis::BODY_FILE,
            r["readback"]["prose_bytes"]
        ),
        if done.receipt_written {
            format!("receipt   written to {}", path.display())
        } else {
            format!(
                "receipt   {} already exists; left unchanged",
                path.display()
            )
        },
    ]
}

/// Check, write and read back one Genesis directory. See `docs/PUBLISHER-V1.md`;
/// a `delegate` or `revoke` directory goes to `authority_node::submit`.
/// The token is redacted from the error, the receipt and the warnings, which
/// can quote what the node sent.
pub async fn submit(node: &Node, dir: &Path, allow_untrusted: bool) -> Result<Submitted> {
    // A `delegate` or `revoke` directory (`docs/KEYS.md`).
    if super::authority::is_authority_dir(dir) {
        return super::authority_node::submit(node, dir, allow_untrusted).await;
    }
    let mut done = submit_unredacted(node, dir, allow_untrusted)
        .await
        .map_err(|e| anyhow::anyhow!(node.redact(&format!("{e:#}"))))?;
    done.warnings = done.warnings.iter().map(|w| node.redact(w)).collect();
    Ok(done)
}
async fn submit_unredacted(node: &Node, dir: &Path, allow_untrusted: bool) -> Result<Submitted> {
    let g = Genesis::load_dir(dir)?;
    let health = node.health().await?;
    writable(&health)?;
    let trust = Trust::of(&health, &g);
    let warnings = trust.failures(&health, &g);
    if !warnings.is_empty() && !allow_untrusted {
        bail!(
            "refusing to submit; nothing was written:\n  - {}",
            warnings.join("\n  - ")
        );
    }
    // Shown before anything is written, whatever happens next.
    for w in &warnings {
        eprintln!("warning: --allow-untrusted overrides: {w}");
    }
    // A retained Genesis is a known subject; it is reported, never re-posted.
    let already = node.subject(g.subject()).await?.is_some();
    let body_status = node.put_body(&g.body).await?;
    let admission = if already {
        json!({"result": "already_admitted", "http_status": null, "outcome": null})
    } else {
        let (status, outcome) = node.post_candidate(g.signed.bytes()).await?;
        ensure!(
            status == StatusCode::CREATED && outcome.state == "valid",
            "node did not admit the envelope as valid: HTTP {status}, state {:?}, reason {:?}",
            outcome.state,
            outcome.reason
        );
        ensure!(
            outcome.event == Some(g.id()) && outcome.input_digest == hash(g.signed.bytes()),
            "node acknowledged a different envelope: {}",
            outcome.to_json()
        );
        json!({"result": "admitted", "http_status": status.as_u16(), "outcome": outcome.to_json()})
    };
    let readback = readback(node, &g).await?;
    let receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "node": node.url(),
        "node_health": health.to_json(),
        "trust": trust.to_json(allow_untrusted, &warnings),
        "event": hex::encode(g.id()),
        "subject": hex::encode(g.subject()),
        "revision": hex::encode(g.revision()),
        "author": hex::encode(g.author()),
        "instance": hex::encode(g.instance()),
        "body_sha256": hex::encode(hash(&g.body)),
        "envelope_sha256": hex::encode(hash(g.signed.bytes())),
        "body": {
            "http_status": body_status.as_u16(),
            "result": if body_status == StatusCode::CREATED { "stored" } else { "already_present" },
        },
        "admission": admission,
        "readback": readback,
    });
    // Redacted before it is written or returned: it quotes node answers.
    let mut receipt = receipt;
    node.redact_json(&mut receipt);
    let path = dir.join(RECEIPT_FILE);
    let receipt_written = !path.exists();
    if receipt_written {
        write_new(
            &path,
            (serde_json::to_string_pretty(&receipt)? + "\n").as_bytes(),
        )?;
    }
    Ok(Submitted {
        receipt,
        receipt_written,
        warnings,
    })
}

fn asserted(v: &Value) -> Option<AssertedTime> {
    Some(AssertedTime {
        coordinate: v.get("coordinate").and_then(hash_json)?,
        precision: v.get("precision")?.as_str()?.into(),
    })
}
fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}
fn hashes(v: Option<&Value>) -> Value {
    let list = v.and_then(Value::as_array).cloned().unwrap_or_default();
    list.iter()
        .map(|h| hash_json(h).map_or(h.clone(), |h| json!(hex::encode(h))))
        .collect()
}
fn normalized(v: Option<&Value>) -> Value {
    match v {
        Some(v) => hash_json(v).map_or(v.clone(), |h| json!(hex::encode(h))),
        None => Value::Null,
    }
}

/// The subject must read back resolved and visible at exactly this Genesis's
/// revision, and the served prose must equal `body.bin` byte for byte.
async fn readback(node: &Node, g: &Genesis) -> Result<Value> {
    let f = g.fields()?;
    let read = node
        .subject(g.subject())
        .await?
        .context("readback: node does not know the subject after admission")?;
    ensure!(
        read.get("subject").and_then(hash_json) == Some(g.subject()),
        "readback: node answered for another subject"
    );
    ensure!(
        text(&read, "state") == Some("resolved") && text(&read, "visibility") == Some("visible"),
        "readback: subject is {:?}/{:?}, not resolved/visible",
        text(&read, "state"),
        text(&read, "visibility")
    );
    let revision = read
        .get("revision")
        .filter(|r| !r.is_null())
        .context("readback: subject has no current revision")?;
    let current = revision.get("id").and_then(hash_json);
    ensure!(
        current == Some(g.revision()),
        "readback: current revision is {}, not this Genesis's {}",
        current.map_or("unknown".into(), hex::encode),
        hex::encode(g.revision())
    );
    ensure!(
        revision.get("subject").and_then(hash_json) == Some(g.subject())
            && revision.get("creating_event").and_then(hash_json) == Some(g.id())
            && revision.get("body").and_then(hash_json) == Some(f.body),
        "readback: revision {} does not bind this event and body hash",
        hex::encode(g.revision())
    );
    ensure!(
        revision.get("asserted_time").and_then(asserted).as_ref() == Some(f.asserted_time),
        "readback: revision asserted time differs from the envelope"
    );
    let prose = node.prose(g.revision()).await?;
    ensure!(
        prose
            .get("revision")
            .and_then(|r| r.get("id"))
            .and_then(hash_json)
            == Some(g.revision()),
        "readback: prose answered for another revision"
    );
    ensure!(
        text(&prose, "availability") == Some("available"),
        "readback: prose availability is {:?}",
        text(&prose, "availability")
    );
    let served = text(&prose, "prose")
        .context("readback: prose missing")?
        .as_bytes();
    ensure!(
        served == g.body.as_slice(),
        "readback: served prose ({} bytes, sha256 {}) differs from body.bin ({} bytes, sha256 {})",
        served.len(),
        hex::encode(hash(served)),
        g.body.len(),
        hex::encode(hash(&g.body))
    );
    Ok(json!({
        "subject_state": "resolved",
        "visibility": "visible",
        "frontier": hashes(read.get("frontier")),
        "revision": hex::encode(g.revision()),
        "asserted_time": time::render(f.asserted_time),
        "prose_bytes": served.len(),
        "prose_sha256": hex::encode(hash(served)),
        "prose_equals_body_bin": true,
        "rule": read.get("rule").cloned().unwrap_or(Value::Null),
        "corpus_digest": normalized(read.get("corpus_digest")),
        "commitment": normalized(read.get("commitment")),
    }))
}

/// Read-only check of one subject. With a `genesis` directory, the node must
/// also serve exactly that Genesis's revision and body bytes. The token is
/// redacted from the error and the report.
pub async fn verify(node: &Node, subject: Hash, dir: Option<&Path>) -> Result<(bool, Value)> {
    let (ok, mut report) = verify_unredacted(node, subject, dir)
        .await
        .map_err(|e| anyhow::anyhow!(node.redact(&format!("{e:#}"))))?;
    node.redact_json(&mut report);
    Ok((ok, report))
}
async fn verify_unredacted(
    node: &Node,
    subject: Hash,
    dir: Option<&Path>,
) -> Result<(bool, Value)> {
    let local = dir.map(Genesis::load_dir).transpose()?;
    let health = node.health().await?;
    let mut failures = Vec::new();
    if health.ledger != "v1" {
        failures.push(format!("node ledger is {:?}, not \"v1\"", health.ledger));
    }
    if !health.fold_matches() {
        failures.push("node fold_version differs from this build".into());
    }
    let mut report = json!({
        "node": node.url(),
        "node_health": health.to_json(),
        "subject": hex::encode(subject),
    });
    let read = node.subject(subject).await?;
    let mut served = None;
    match &read {
        None => failures.push("node does not know the subject".into()),
        Some(read) => {
            if read.get("subject").and_then(hash_json) != Some(subject) {
                failures.push("node answered for another subject".into());
            }
            report["state"] = json!(text(read, "state"));
            report["visibility"] = json!(text(read, "visibility"));
            report["frontier"] = hashes(read.get("frontier"));
            if text(read, "state") != Some("resolved")
                || text(read, "visibility") != Some("visible")
            {
                failures.push("subject is not resolved and visible".into());
            }
            match read.get("revision").filter(|r| !r.is_null()) {
                None => failures.push("subject has no current revision".into()),
                Some(r) => {
                    let id = r.get("id").and_then(hash_json);
                    let body = r.get("body").and_then(hash_json);
                    report["revision"] = json!({
                        "id": id.map(hex::encode),
                        "creating_event": normalized(r.get("creating_event")),
                        "body": body.map(hex::encode),
                        "asserted_time": r.get("asserted_time").and_then(asserted).map(|t| json!({
                            "calendar": time::render(&t),
                            "precision": t.precision,
                            "coordinate": hex::encode(t.coordinate),
                        })),
                    });
                    if let (Some(id), Some(body)) = (id, body) {
                        let prose = match node.prose(id).await {
                            Ok(p) => {
                                let answered = p.get("revision").and_then(|r| r.get("id"));
                                if answered.and_then(hash_json) != Some(id) {
                                    failures.push("prose answered for another revision".into());
                                }
                                p
                            }
                            Err(e) => json!({"availability": format!("read failed: {e:#}")}),
                        };
                        let availability = text(&prose, "availability");
                        match text(&prose, "prose").filter(|_| availability == Some("available")) {
                            None => {
                                failures.push(format!("prose availability is {availability:?}"))
                            }
                            Some(p) => {
                                let ok = hash(p.as_bytes()) == body;
                                if !ok {
                                    failures.push(
                                        "served prose does not hash to the revision body".into(),
                                    );
                                }
                                report["prose"] = json!({
                                    "bytes": p.len(),
                                    "sha256": hex::encode(hash(p.as_bytes())),
                                    "matches_revision_body": ok,
                                });
                                served = Some((id, p.as_bytes().to_vec()));
                            }
                        }
                    } else {
                        failures.push("current revision lacks an id or body hash".into());
                    }
                }
            }
        }
    }
    if let Some(g) = &local {
        if g.subject() != subject {
            failures.push("--dir holds a different subject".into());
        }
        if health.instance != g.instance() {
            failures.push("node instance differs from the --dir envelope".into());
        }
        if !health.curators.contains(&g.author()) {
            failures.push("--dir author is not in the node's curator set".into());
        }
        match &served {
            Some((id, bytes)) if *id == g.revision() && *bytes == g.body => {}
            _ => failures.push(
                "node does not serve the --dir Genesis revision with body.bin's exact bytes".into(),
            ),
        }
        report["local"] = json!({
            "event": hex::encode(g.id()),
            "revision": hex::encode(g.revision()),
            "body_sha256": hex::encode(hash(&g.body)),
        });
    }
    let ok = failures.is_empty();
    report["ok"] = json!(ok);
    report["failures"] = json!(failures);
    Ok((ok, report))
}
