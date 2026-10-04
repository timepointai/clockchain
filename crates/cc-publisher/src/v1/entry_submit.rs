//! The online half of content authoring: `context` saves a node's verified
//! export for the offline builders, `review-packet` re-checks a packet
//! offline for the owner, and `submit-packet` submits one packet only under
//! the owner's approval of its exact digest, only if nothing else was
//! admitted since its context was taken.
use super::entry_context::Context;
use super::entry_packet::{kind_name, Packet, PACKET_FILE};
use super::hash_json;
use super::node::{self, Node};
use anyhow::{ensure, Context as _, Result};
use cc_core::v1::rule::corpus_digest;
use cc_core::v1::{hash, Hash};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub const REVIEW_SCHEMA: &str = "cc.publisher.v1.packet-review";
pub const SUBMISSION_SCHEMA: &str = "cc.publisher.v1.packet-submission";

/// Read `/health` and `GET /v1/export`, verify the export and return both.
/// Only the verified fields are kept (`encoding`, `rule`, `corpus_digest`,
/// `commitment`, `envelopes`), so nothing else a node sends reaches a file.
pub async fn fetch(node: &Node) -> Result<(node::Health, Value, Context)> {
    let health = node.health().await?;
    ensure!(
        health.fold_matches(),
        "node fold_version differs from this build's fold_v1()"
    );
    let served = node.export().await?;
    let mut export = serde_json::Map::new();
    for k in [
        "encoding",
        "rule",
        "corpus_digest",
        "commitment",
        "envelopes",
    ] {
        export.insert(k.into(), served[k].clone());
    }
    let export = Value::Object(export);
    let ctx = Context::from_export(health.instance, &export).context("GET /v1/export")?;
    Ok((health, export, ctx))
}

/// `cc-publisher v1 context`: save the verified export to a new file.
pub async fn save_context(node: &Node, out: &Path) -> Result<Context> {
    let (health, export, ctx) = fetch(node).await?;
    Context::save(health.instance, &export, out)?;
    Ok(ctx)
}

/// The context with the packet's own events removed: on a rerun after a
/// partial submission they may already be admitted.
fn without_packet(ctx: &Context, packet: &Packet) -> Hash {
    let own: BTreeSet<Hash> = packet.ids().into_iter().collect();
    corpus_digest(
        &ctx.events
            .keys()
            .filter(|id| !own.contains(*id))
            .copied()
            .collect(),
    )
}

/// Offline review: reload the packet and, with a context, require that it is
/// the packet's own context and that every event still classifies valid.
pub fn review(dir: &Path, ctx: Option<&Context>) -> Result<Value> {
    let p = Packet::load_dir(dir)?;
    let digest = p.digest()?;
    let packet: Value = serde_json::from_slice(&p.render()?)?;
    let (context_matches, admissible) = match ctx {
        None => (Value::Null, Value::Null),
        Some(c) => {
            ensure!(
                c.instance == p.instance,
                "context instance differs from the packet's"
            );
            let matches = without_packet(c, &p) == p.context;
            let pending: Vec<_> = p
                .events
                .iter()
                .filter(|e| !c.events.contains_key(&e.id()))
                .cloned()
                .collect();
            let admissible = match c.self_check(&pending) {
                Ok(()) => json!(true),
                Err(e) => json!(format!("{e:#}")),
            };
            (matches.into(), admissible)
        }
    };
    Ok(json!({
        "schema": REVIEW_SCHEMA,
        "packet_digest": hex::encode(digest),
        "context_matches": context_matches,
        "admissible": admissible,
        "status": "ready_for_owner_review",
        "note": "ready_for_owner_review is not approval",
        "publication_authorized": false,
        "writes_performed": false,
        "packet": packet,
    }))
}

/// `cc-publisher v1 submit-packet`. Steps 1 to 4 only read.
pub async fn submit(node: &Node, dir: &Path, approve: Hash) -> Result<Value> {
    match submit_unredacted(node, dir, approve).await {
        Ok(mut report) => {
            node.redact_json(&mut report);
            Ok(report)
        }
        Err(e) => Err(anyhow::anyhow!(node.redact(&format!("{e:#}")))),
    }
}
async fn submit_unredacted(node: &Node, dir: &Path, approve: Hash) -> Result<Value> {
    // 1. The exact packet the owner approved.
    let p = Packet::load_dir(dir)?;
    let digest = p.digest()?;
    ensure!(
        digest == approve,
        "--approve {} is not this packet's digest {}; review {PACKET_FILE} again",
        hex::encode(approve),
        hex::encode(digest)
    );
    // 2. A writable v1 node of this instance, fold and curator set.
    let (health, _, ctx) = fetch(node).await?;
    node::writable(&health)?;
    let mut refusals = vec![];
    if health.instance != p.instance {
        refusals.push("node instance differs from the packet's");
    }
    if !health.curators.contains(&p.author) {
        refusals.push("packet author is not in the node's curator set");
    }
    if !health.filter_consistent() {
        refusals.push("node filter_version is inconsistent with its curators and max_hops");
    }
    ensure!(
        refusals.is_empty(),
        "refusing to submit; nothing was written: {}",
        refusals.join("; ")
    );
    // 3. Nothing but this packet's own events was admitted since its context.
    ensure!(
        without_packet(&ctx, &p) == p.context,
        "refusing to submit; nothing was written: the node's corpus changed since the \
         packet's context {} was taken; fetch a new context, rebuild and review again",
        hex::encode(p.context)
    );
    // 4. The node's own admission rule, offline, over its current corpus.
    let pending: Vec<_> = p
        .events
        .iter()
        .filter(|e| !ctx.events.contains_key(&e.id()))
        .cloned()
        .collect();
    ctx.self_check(&pending)?;
    // 5. Bodies, then events in packet order; each must be admitted valid.
    let mut bodies = vec![];
    for (h, b) in &p.bodies {
        let status = node.put_body(b).await?;
        bodies.push(json!({"sha256": hex::encode(h), "http_status": status.as_u16()}));
    }
    let mut admitted = vec![];
    for e in &p.events {
        let (status, outcome) = node.post_candidate(e.bytes()).await?;
        let j = json!({
            "kind": kind_name(e.envelope().payload.kind()),
            "event": hex::encode(e.id()),
            "http_status": status.as_u16(),
            "state": outcome.state,
            "reason": outcome.reason,
        });
        ensure!(
            status == StatusCode::CREATED
                && outcome.state == "valid"
                && outcome.event == Some(e.id())
                && outcome.input_digest == hash(e.bytes()),
            "node did not admit {} as valid: {j}",
            hex::encode(e.id())
        );
        admitted.push(j);
    }
    // 6. Read back: every packet event is retained and valid in the snapshot.
    let snap = node.snapshot().await?;
    let rows = snap["rows"].as_array().context("snapshot lacks rows")?;
    for e in &p.events {
        let row = rows
            .iter()
            .find(|r| hash_json(&r["event"]) == Some(e.id()))
            .with_context(|| format!("readback: snapshot lacks {}", hex::encode(e.id())))?;
        let state = row["state"].as_str().unwrap_or("absent");
        ensure!(
            matches!(state, "head" | "superseded" | "branch"),
            "readback: {} is {state}",
            hex::encode(e.id())
        );
    }
    let ids: BTreeSet<Hash> = p.ids().into_iter().collect();
    let edges: Vec<Value> = snap["edges"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|x| hash_json(&x["edge"]).is_some_and(|h| ids.contains(&h)))
        .map(|x| json!({"edge": hash_json(&x["edge"]).map(hex::encode), "status": x["status"], "reasons": x["reasons"]}))
        .collect();
    Ok(json!({
        "schema": SUBMISSION_SCHEMA,
        "node": node.url(),
        "packet_digest": hex::encode(digest),
        "command": p.command,
        "bodies": bodies,
        "events": admitted,
        "edges": edges,
        "corpus_digest": snap["corpus_digest"],
        "commitment": snap["commitment"],
    }))
}
