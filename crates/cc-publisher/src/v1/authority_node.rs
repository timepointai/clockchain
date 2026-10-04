//! The node side of v1 authority: `grants` (read-only) and `submit` for a
//! `delegate` or `revoke` directory.
//!
//! Both read `GET /v1/snapshot`, the node's committed fold, whose `authority`
//! section is the node's own grant derivation and whose `rows` and `subjects`
//! give each event's projection state and the subject's frontier. Nothing here
//! recomputes authority; the publisher compares, and the node decides.
use super::authority::{
    kind_name, AuthorityEvent, Context, EventRow, GrantRow, GrantStatus, Operation, ENVELOPE_FILE,
};
use super::genesis::write_new;
use super::node::{writable, Health, Node, Submitted, RECEIPT_FILE};
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::rule::fold_v1;
use cc_core::v1::{hash, root_grant, Hash, Payload};
use cc_ledger::v1::{Effect, EventReading, Grant, SubjectReading};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const RECEIPT_SCHEMA: &str = "cc.publisher.v1.authority-receipt";

/// The parts of one `GET /v1/snapshot` this module reads.
pub struct Snapshot {
    pub corpus_digest: Hash,
    pub commitment: Hash,
    pub rows: Vec<EventReading>,
    pub subjects: Vec<SubjectReading>,
    pub grants: Vec<(Hash, Grant)>,
    pub active: BTreeSet<Hash>,
    pub tombstones: BTreeSet<Hash>,
    pub canceled: BTreeSet<Hash>,
    /// Non-empty authority effects by event.
    pub effects: BTreeMap<Hash, String>,
}

fn part<T: serde::de::DeserializeOwned>(v: &mut Value, path: &[&str]) -> Result<T> {
    let mut at = &mut *v;
    for k in path {
        at = at
            .get_mut(*k)
            .with_context(|| format!("/v1/snapshot lacks {}", path.join(".")))?;
    }
    serde_json::from_value(at.take()).with_context(|| format!("/v1/snapshot {}", path.join(".")))
}

impl Node {
    /// `GET /v1/snapshot` at the node's bound fold (read scope).
    pub async fn snapshot(&self) -> Result<Snapshot> {
        let reply = self.send(Method::GET, "v1/snapshot", None, true).await?;
        if reply.status != StatusCode::OK {
            return Err(self.unexpected("GET /v1/snapshot", &reply));
        }
        let mut v = self.json(&reply, "GET /v1/snapshot")?;
        let digest = |k: &str, v: &Value| {
            v.get(k)
                .and_then(Value::as_str)
                .and_then(super::hex32)
                .with_context(|| format!("/v1/snapshot {k} is not 64 hex characters"))
        };
        Ok(Snapshot {
            corpus_digest: digest("corpus_digest", &v)?,
            commitment: digest("commitment", &v)?,
            rows: part(&mut v, &["rows"])?,
            subjects: part(&mut v, &["subjects"])?,
            grants: part(&mut v, &["authority", "grants"])?,
            active: part(&mut v, &["authority", "active"])?,
            tombstones: part(&mut v, &["authority", "tombstones"])?,
            canceled: part(&mut v, &["authority", "canceled"])?,
            effects: part::<Vec<(Hash, Effect)>>(&mut v, &["authority", "effects"])?
                .into_iter()
                .filter(|(_, e)| !e.reason.is_empty())
                .map(|(id, e)| (id, e.reason))
                .collect(),
        })
    }
}

fn state_name(r: &EventReading) -> String {
    serde_json::to_value(&r.state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl Snapshot {
    /// One subject's authority, as a grants file.
    pub fn context(&self, node: &Node, health: &Health, subject: Hash) -> Result<Context> {
        let genesis = self
            .rows
            .iter()
            .find(|r| r.event == subject)
            .with_context(|| format!("node does not know subject {}", hex::encode(subject)))?;
        ensure!(
            matches!(genesis.envelope.payload, Payload::Genesis { .. }),
            "{} is not a Genesis event",
            hex::encode(subject)
        );
        ensure!(
            state_name(genesis) != "invalid" && state_name(genesis) != "pending",
            "subject Genesis {} is {}",
            hex::encode(subject),
            state_name(genesis)
        );
        let reading = self
            .subjects
            .iter()
            .find(|s| s.subject == subject)
            .with_context(|| format!("node has no reading of subject {}", hex::encode(subject)))?;
        let mut grants: Vec<GrantRow> = Vec::new();
        let mut todo: Vec<&(Hash, Grant)> = self
            .grants
            .iter()
            .filter(|(_, g)| g.subject == subject)
            .collect();
        // Parents before children; lineage follows issuer links.
        while !todo.is_empty() {
            let before = todo.len();
            todo.retain(|(id, g)| {
                let lineage = match g.issuer {
                    None => Some(vec![*id]),
                    Some(i) => grants.iter().find(|x| x.grant == i).map(|p| {
                        let mut l = p.lineage.clone();
                        l.push(*id);
                        l
                    }),
                };
                let Some(lineage) = lineage else {
                    return true;
                };
                grants.push(GrantRow {
                    grant: *id,
                    status: if self.active.contains(id) {
                        GrantStatus::Active
                    } else if self.tombstones.contains(id) {
                        GrantStatus::Tombstoned
                    } else {
                        GrantStatus::Canceled
                    },
                    holder: g.holder,
                    issuer: g.issuer,
                    issued_by_event: g.issued_by_event,
                    lineage,
                });
                false
            });
            ensure!(
                todo.len() < before,
                "node grants on subject {} do not chain to its root",
                hex::encode(subject)
            );
        }
        grants.sort_by_key(|g| (g.lineage.len(), g.grant));
        let events = self
            .rows
            .iter()
            .filter(|r| r.envelope.subject.unwrap_or(r.event) == subject)
            .filter(|r| {
                !matches!(
                    r.envelope.payload,
                    Payload::EdgeAssert { .. }
                        | Payload::EdgeReaffirm { .. }
                        | Payload::Attestation { .. }
                )
            })
            .map(|r| EventRow {
                event: r.event,
                kind: kind_name(r.envelope.payload.kind()).into(),
                author: r.envelope.author,
                grant: r.envelope.grant,
                parents: r.envelope.parents.0.clone(),
                state: state_name(r),
                reason: r.reason.clone(),
                effect: self.effects.get(&r.event).cloned().unwrap_or_default(),
            })
            .collect();
        let ctx = Context {
            node: node.url().to_owned(),
            health: health.clone(),
            corpus_digest: self.corpus_digest,
            commitment: self.commitment,
            subject,
            subject_key: genesis
                .envelope
                .subject_key
                .clone()
                .context("Genesis lacks a subject key")?,
            state: reading.state.clone(),
            frozen: reading.frozen,
            frontier: reading.frontier.iter().copied().collect(),
            root_holder: genesis.envelope.author,
            grants,
            events,
        };
        ctx.check()?;
        Ok(ctx)
    }
}

/// `grants`: read `/health` and `/v1/snapshot` and return the subject's
/// authority. Read-only. The token is redacted from any error.
pub async fn grants(node: &Node, subject: Hash) -> Result<Context> {
    async {
        let health = node.health().await?;
        ensure!(
            health.ledger == "v1",
            "node reports ledger {:?}, not \"v1\"",
            health.ledger
        );
        ensure!(
            health.fold_matches(),
            "node fold_version {}/{} differs from this build's {}/{}",
            health.fold.version,
            hex::encode(health.fold.manifest),
            fold_v1().version,
            hex::encode(fold_v1().manifest)
        );
        node.snapshot().await?.context(node, &health, subject)
    }
    .await
    .map_err(|e| anyhow!(node.redact(&format!("{e:#}"))))
}

/// The checks `submit` runs on an authority event before writing anything.
/// `author_is_curator` of a Genesis becomes, for an event signed under a
/// grant, "the grant is active, held by the author, and descends from a root
/// grant whose holder is a curator": a delegate key is not a curator, and
/// legitimately signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trust {
    pub instance: bool,
    pub fold: bool,
    pub filter: bool,
    pub root_is_curator: bool,
    pub grant_active_and_held: bool,
    /// Delegate: the parent is the sole head. Revoke: it is the sole head
    /// (an earlier valid parent is reported and needs `--allow-untrusted`).
    pub parent_current: bool,
    /// Delegate: the grantee holds no grant on the subject. Revoke: the
    /// target is active and in the signing grant's issuer scope.
    pub operation: bool,
}
impl Trust {
    fn to_json(&self, allow_untrusted: bool, overridden: &[String]) -> Value {
        json!({
            "instance_matches": self.instance,
            "fold_matches": self.fold,
            "filter_version_consistent": self.filter,
            "root_holder_is_curator": self.root_is_curator,
            "grant_active_and_held_by_author": self.grant_active_and_held,
            "parent_is_sole_head": self.parent_current,
            "operation_permitted": self.operation,
            "allow_untrusted": allow_untrusted,
            "overridden": overridden,
        })
    }
}

/// Failure messages of [`check`]: the node identity checks, which apply to
/// any event, and the authority checks, which apply before admission only.
pub struct Failures {
    pub identity: Vec<String>,
    pub authority: Vec<String>,
}

/// Run every check on `ev` against the node's view; one message per failure.
pub fn check(h: &Health, ctx: &Context, ev: &AuthorityEvent) -> (Trust, Failures) {
    let mut out = Vec::new();
    let instance = h.instance == ev.instance();
    if !instance {
        out.push(format!(
            "instance mismatch: node {} != envelope {}",
            hex::encode(h.instance),
            hex::encode(ev.instance())
        ));
    }
    let fold = h.fold_matches();
    if !fold {
        out.push(format!(
            "fold_version mismatch: node {}/{} != this build {}/{}",
            h.fold.version,
            hex::encode(h.fold.manifest),
            fold_v1().version,
            hex::encode(fold_v1().manifest)
        ));
    }
    let filter = h.filter_consistent();
    if !filter {
        out.push(format!(
            "node filter_version {} is not this build's governed identity for its curators and max_hops",
            hex::encode(h.filter_version)
        ));
    }
    let identity = std::mem::take(&mut out);
    let root_is_curator = h.curators.contains(&ctx.root_holder);
    if !root_is_curator {
        out.push(format!(
            "subject root holder {} is not in the node's curator set",
            hex::encode(ctx.root_holder)
        ));
    }
    let signer = ctx.grant(ev.grant());
    let grant_active_and_held =
        signer.is_some_and(|g| g.status == GrantStatus::Active && g.holder == ev.author());
    if !grant_active_and_held {
        out.push(match signer {
            None => format!(
                "signing grant {} is not a grant on subject {}",
                hex::encode(ev.grant()),
                hex::encode(ctx.subject)
            ),
            Some(g) if g.holder != ev.author() => format!(
                "signing grant {} is held by {}, not the author {}",
                hex::encode(g.grant),
                hex::encode(g.holder),
                hex::encode(ev.author())
            ),
            Some(g) => format!(
                "signing grant {} held by {} is {} on the node",
                hex::encode(g.grant),
                hex::encode(g.holder),
                g.status.as_str()
            ),
        });
    }
    let parent_current = ctx.frontier == [ev.parent()] && !ctx.frozen;
    if !parent_current {
        let past = ctx.past(ev.parent());
        let outside: Vec<_> = ctx
            .events
            .iter()
            .filter(|e| !past.contains(&e.event))
            .map(|e| format!("{} ({}, {})", hex::encode(e.event), e.kind, e.state))
            .collect();
        let known = ctx.event(ev.parent()).is_some();
        out.push(format!(
            "parent {} is not the subject's sole head (frontier: [{}]{}){}",
            hex::encode(ev.parent()),
            ctx.frontier
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(", "),
            if ctx.frozen { ", frozen" } else { "" },
            if known {
                format!(
                    "; events outside its past, which covered grants' acts lose: [{}]",
                    outside.join(", ")
                )
            } else {
                "; the parent is not an event of this subject on the node".into()
            }
        ));
    }
    let operation = match ev.operation() {
        Operation::Delegate { grantee, .. } => {
            match ctx.grants.iter().find(|g| g.holder == grantee) {
                None => true,
                Some(g) => {
                    out.push(format!(
                        "grantee {} already holds grant {} ({}); a delegate key must be fresh",
                        hex::encode(grantee),
                        hex::encode(g.grant),
                        g.status.as_str()
                    ));
                    false
                }
            }
        }
        Operation::Revoke { target, .. } => {
            let t = ctx.grant(target);
            let active = t.is_some_and(|t| t.status == GrantStatus::Active);
            let scope = super::authority::in_scope(ctx, ev.grant(), target);
            if !active {
                out.push(format!(
                    "revoke target {} is {}",
                    hex::encode(target),
                    t.map_or("not a grant on this subject", |t| t.status.as_str())
                ));
            }
            if !scope {
                out.push(format!(
                    "revoke target {} is not a strict issuer descendant of the signing grant {} \
                     (authority.revoke_scope=strict_issuer_descendant_or_root_self)",
                    hex::encode(target),
                    hex::encode(ev.grant())
                ));
            }
            active && scope
        }
    };
    let trust = Trust {
        instance,
        fold,
        filter,
        root_is_curator,
        grant_active_and_held,
        parent_current,
        operation,
    };
    (
        trust,
        Failures {
            identity,
            authority: out,
        },
    )
}

/// `submit` for a `delegate` or `revoke` directory. The token is redacted
/// from the error, the receipt and the warnings.
pub async fn submit(node: &Node, dir: &Path, allow_untrusted: bool) -> Result<Submitted> {
    let mut done = submit_unredacted(node, dir, allow_untrusted)
        .await
        .map_err(|e| anyhow!(node.redact(&format!("{e:#}"))))?;
    done.warnings = done.warnings.iter().map(|w| node.redact(w)).collect();
    Ok(done)
}

async fn submit_unredacted(node: &Node, dir: &Path, allow_untrusted: bool) -> Result<Submitted> {
    let ev = AuthorityEvent::load_dir(dir)?;
    let health = node.health().await?;
    writable(&health)?;
    let before = node.snapshot().await?;
    let ctx = before.context(node, &health, ev.subject())?;
    // A retained event is reported, never re-posted, and is not re-checked
    // against a state it has itself changed.
    let already = ctx.event(ev.id()).cloned();
    let (trust, failures) = check(&health, &ctx, &ev);
    let mut warnings = failures.identity;
    if already.is_none() {
        // Whatever the flags: the node would refuse an event whose signing
        // grant or target was not issued in its parent's past, and keep it.
        let mut grants = vec![ev.grant()];
        if let Operation::Revoke { target, .. } = ev.operation() {
            grants.push(target);
        }
        super::authority::issued_in_past(&ctx, ev.parent(), &grants)
            .map_err(|e| anyhow!("refusing to submit; nothing was written: {e}"))?;
        warnings.extend(failures.authority);
    }
    if !warnings.is_empty() && !allow_untrusted {
        bail!(
            "refusing to submit; nothing was written:\n  - {}",
            warnings.join("\n  - ")
        );
    }
    for w in &warnings {
        eprintln!("warning: --allow-untrusted overrides: {w}");
    }
    let admission = match &already {
        Some(row) => {
            ensure!(
                row.state != "invalid" && row.state != "pending",
                "node retains this envelope as {} ({}); it was not admitted",
                row.state,
                row.reason
            );
            json!({"result": "already_admitted", "http_status": null, "outcome": null})
        }
        None => {
            let (status, outcome) = node.post_candidate(ev.signed.bytes()).await?;
            ensure!(
                status == StatusCode::CREATED && outcome.state == "valid",
                "node did not admit the envelope as valid: HTTP {status}, state {:?}, reason {:?}",
                outcome.state,
                outcome.reason
            );
            ensure!(
                outcome.event == Some(ev.id()) && outcome.input_digest == hash(ev.signed.bytes()),
                "node acknowledged a different envelope: {}",
                outcome.to_json()
            );
            json!({"result": "admitted", "http_status": status.as_u16(), "outcome": outcome.to_json()})
        }
    };
    let after = node
        .snapshot()
        .await?
        .context(node, &health, ev.subject())?;
    let readback = readback(&after, &ev, already.is_none())?;
    let mut receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "node": node.url(),
        "node_health": health.to_json(),
        "trust": trust.to_json(allow_untrusted, &warnings),
        "event_kind": ev.kind_name(),
        "event": hex::encode(ev.id()),
        "subject": hex::encode(ev.subject()),
        "author": hex::encode(ev.author()),
        "grant": hex::encode(ev.grant()),
        "parent": hex::encode(ev.parent()),
        "instance": hex::encode(ev.instance()),
        "envelope_sha256": hex::encode(hash(ev.signed.bytes())),
        "admission": admission,
        "readback": readback,
    });
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

/// After admission the node must show the event valid and authority-eligible
/// (a root relinquishment is eligible as `root_relinquished`, its terminal
/// effect) and, for a fresh admission, the grant change it signs: a
/// Delegate's grant active, held by the grantee under the signing grant; a
/// Revoke's target tombstoned and, with cascade, every grant below it
/// tombstoned too. A rerun reports the current grant state without
/// requiring it, since later events may have changed it.
fn readback(ctx: &Context, ev: &AuthorityEvent, fresh: bool) -> Result<Value> {
    let row = ctx
        .event(ev.id())
        .context("readback: node does not retain the event after admission")?;
    ensure!(
        matches!(row.state.as_str(), "head" | "superseded" | "branch"),
        "readback: event is {} ({:?}), not a valid subject event",
        row.state,
        row.reason
    );
    let relinquish = matches!(
        ev.operation(),
        Operation::Revoke { target, .. } if target == ev.grant() && target == root_grant(ctx.subject)
    );
    ensure!(
        row.effect.is_empty() || (relinquish && row.effect == "root_relinquished"),
        "readback: event is suppressed: {}",
        row.effect
    );
    let grant_json = |g: &GrantRow| json!({"grant": hex::encode(g.grant), "holder": hex::encode(g.holder), "status": g.status.as_str()});
    let op = match ev.operation() {
        Operation::Delegate { grantee, issuer } => {
            let g = ctx
                .grant(ev.id())
                .context("readback: node lists no grant for this Delegate")?;
            ensure!(
                g.holder == grantee && g.issuer == Some(issuer),
                "readback: node grant {} is not held by the grantee under the signing grant",
                hex::encode(g.grant)
            );
            ensure!(
                !fresh || g.status == GrantStatus::Active,
                "readback: new grant {} is {}",
                hex::encode(g.grant),
                g.status.as_str()
            );
            json!({"new_grant": grant_json(g)})
        }
        Operation::Revoke { target, cascade } => {
            let t = ctx
                .grant(target)
                .context("readback: node no longer lists the target grant")?;
            ensure!(
                t.status == GrantStatus::Tombstoned,
                "readback: target grant {} is {}, not tombstoned",
                hex::encode(target),
                t.status.as_str()
            );
            let below = ctx.descendants(target);
            if cascade {
                if let Some(g) = below.iter().find(|g| g.status != GrantStatus::Tombstoned) {
                    bail!(
                        "readback: cascade revoke left grant {} below the target {}",
                        hex::encode(g.grant),
                        g.status.as_str()
                    );
                }
            }
            json!({
                "target": grant_json(t),
                "cascade": cascade,
                "descendants": below.iter().map(|g| grant_json(g)).collect::<Vec<_>>(),
                "relinquished_root": relinquish,
            })
        }
    };
    Ok(json!({
        "event_state": row.state,
        "event_effect": row.effect,
        "frontier": ctx.frontier.iter().map(hex::encode).collect::<Vec<_>>(),
        "event_is_head": ctx.frontier.contains(&ev.id()),
        "subject_state": ctx.state,
        "frozen": ctx.frozen,
        "active_grants": ctx.grants.iter()
            .filter(|g| g.status == GrantStatus::Active)
            .map(|g| hex::encode(g.grant))
            .collect::<Vec<_>>(),
        ev.kind_name(): op,
        "corpus_digest": hex::encode(ctx.corpus_digest),
        "commitment": hex::encode(ctx.commitment),
    }))
}

/// One human-readable line per step of a completed authority `submit`, or
/// `None` when the receipt is a Genesis receipt.
pub fn summary(done: &Submitted, dir: &Path) -> Option<Vec<String>> {
    let r = &done.receipt;
    if r["schema"] != RECEIPT_SCHEMA {
        return None;
    }
    let kind = r["event_kind"].as_str().unwrap_or_default();
    let envelope = match r["admission"]["result"].as_str() {
        Some("admitted") => format!("{kind} admitted as valid (HTTP 201)"),
        _ => format!("{kind} already admitted; not re-posted"),
    };
    let rb = &r["readback"];
    let effect = match kind {
        "delegate" => format!(
            "grant {} active for {}",
            rb["delegate"]["new_grant"]["grant"]
                .as_str()
                .unwrap_or_default(),
            rb["delegate"]["new_grant"]["holder"]
                .as_str()
                .unwrap_or_default()
        ),
        _ => format!(
            "grant {} tombstoned (cascade {}); {} grant(s) below it",
            rb["revoke"]["target"]["grant"].as_str().unwrap_or_default(),
            rb["revoke"]["cascade"],
            rb["revoke"]["descendants"].as_array().map_or(0, Vec::len)
        ),
    };
    let path = dir.join(RECEIPT_FILE);
    Some(vec![
        format!(
            "envelope  {envelope} from {}",
            dir.join(ENVELOPE_FILE).display()
        ),
        format!(
            "readback  {effect}; subject {}{}; frontier [{}]",
            rb["subject_state"].as_str().unwrap_or_default(),
            if rb["subject_state"] == "contested" {
                " (more than one head: it needs a Resolve)"
            } else {
                ""
            },
            rb["frontier"]
                .as_array()
                .map(|f| f
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default()
        ),
        if done.receipt_written {
            format!("receipt   written to {}", path.display())
        } else {
            format!(
                "receipt   {} already exists; left unchanged",
                path.display()
            )
        },
    ])
}
