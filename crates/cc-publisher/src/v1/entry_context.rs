//! The node state a content packet is built against: a node's `GET /v1/export`
//! saved by `cc-publisher v1 context`. Every envelope is decoded and verified,
//! the corpus digest is recomputed, and every reading comes from
//! `cc_ledger::v1::project` and `classify`, the node's own fold. Offline.
use super::genesis::{read_capped, write_new};
use super::{hash_json, hex32};
use anyhow::{anyhow, bail, ensure, Context as _, Result};
use cc_core::v1::rule::{corpus_digest, fold_v1};
use cc_core::v1::{AssertedTime, Hash, Kind, Pin, Signed, SubjectKey};
use cc_ledger::v1::{classify, project, EdgeReading, Projection, State};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const CONTEXT_SCHEMA: &str = "cc.publisher.v1.context";
/// The node client refuses larger responses, so no export is larger.
pub const MAX_CONTEXT: usize = 16 * 1024 * 1024;

/// A verified corpus and its projection under this build's fold.
pub struct Context {
    pub instance: Hash,
    pub corpus_digest: Hash,
    pub events: BTreeMap<Hash, Signed>,
    pub projection: Projection,
}

/// The current reading of one resolved subject: what an edge pins and what a
/// correction replaces.
#[derive(Clone, Debug)]
pub struct Current {
    pub subject: Hash,
    /// The single frontier event; the basis of a pin and a correction's parent.
    pub head: Hash,
    pub revision: Hash,
    pub body: Hash,
    pub asserted_time: Option<AssertedTime>,
    pub key: SubjectKey,
    /// The Genesis author: the only key whose `disputes` edges may start here.
    pub creator: Hash,
}
impl Current {
    pub fn pin(&self) -> Pin {
        Pin {
            subject: self.subject,
            basis: self.head,
            revision: self.revision,
            body: self.body,
        }
    }
}

impl Context {
    /// Verify an export against `instance`: canonical, signed envelopes of
    /// that instance, no duplicate, this build's fold, and the corpus digest
    /// the node named.
    pub fn from_export(instance: Hash, export: &Value) -> Result<Self> {
        let fold = &export["rule"];
        let build = fold_v1();
        ensure!(
            fold["fold_version"].as_u64() == Some(u64::from(build.version))
                && hash_json(&fold["fold_manifest"]) == Some(build.manifest),
            "export fold differs from this build's fold_v1()"
        );
        let named = hash_json(&export["corpus_digest"]).context("export lacks a corpus digest")?;
        let list = export["envelopes"]
            .as_array()
            .context("export lacks an envelopes list")?;
        let mut events = BTreeMap::new();
        for (i, e) in list.iter().enumerate() {
            let bytes = e
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .with_context(|| format!("export envelope {i} is not hex"))?;
            let signed = Signed::decode(&bytes).map_err(|e| anyhow!("export envelope {i}: {e}"))?;
            ensure!(
                signed.envelope().instance == instance,
                "export envelope {i} belongs to another instance"
            );
            ensure!(
                events.insert(signed.id(), signed).is_none(),
                "export envelope {i} is a duplicate"
            );
        }
        let ids: BTreeSet<_> = events.keys().copied().collect();
        ensure!(
            corpus_digest(&ids) == named,
            "export corpus digest does not match its envelopes"
        );
        let projection = project(&events);
        Ok(Self {
            instance,
            corpus_digest: named,
            events,
            projection,
        })
    }
    /// The verified export: this build's fold, the corpus digest and every
    /// envelope, all re-encoded from what was checked.
    pub fn export_json(&self) -> Value {
        let fold = fold_v1();
        json!({
            "rule": {"fold_version": fold.version, "fold_manifest": hex::encode(fold.manifest)},
            "corpus_digest": hex::encode(self.corpus_digest),
            "envelopes": self.events.values().map(|e| hex::encode(e.bytes())).collect::<Vec<_>>(),
        })
    }
    /// The file `cc-publisher v1 context` writes.
    pub fn file_json(instance: Hash, export: &Value) -> Value {
        json!({
            "schema": CONTEXT_SCHEMA,
            "instance": hex::encode(instance),
            "export": export,
        })
    }
    pub fn load(path: &Path) -> Result<Self> {
        let v: Value = serde_json::from_slice(&read_capped(path, MAX_CONTEXT)?)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        ensure!(
            v["schema"] == CONTEXT_SCHEMA,
            "{} is not a {CONTEXT_SCHEMA} file",
            path.display()
        );
        let instance = v["instance"]
            .as_str()
            .and_then(hex32)
            .context("context instance must be 64 hex characters")?;
        Self::from_export(instance, &v["export"]).with_context(|| path.display().to_string())
    }
    pub fn save(instance: Hash, export: &Value, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(&Self::file_json(instance, export))? + "\n";
        write_new(path, text.as_bytes())
    }

    /// The single-head, resolved reading of `subject`. Anything else (unknown,
    /// contested, no current body) is refused: a pin or a correction needs
    /// exactly one current revision.
    pub fn current(&self, subject: Hash) -> Result<Current> {
        let s = hex::encode(subject);
        let reading = self
            .projection
            .subjects
            .iter()
            .find(|r| r.subject == subject)
            .with_context(|| format!("subject {s} is not a valid subject in the context"))?;
        ensure!(
            reading.state == "resolved" && reading.frontier.len() == 1,
            "subject {s} is {} with {} frontier head(s); a pin needs one resolved head",
            reading.state,
            reading.frontier.len()
        );
        let head = *reading.frontier.first().unwrap();
        let revision = self
            .projection
            .rows
            .iter()
            .find(|r| r.event == head)
            .and_then(|r| r.revision)
            .with_context(|| format!("subject {s} head selects no revision"))?;
        let r = self
            .projection
            .revisions
            .iter()
            .find(|r| r.id == revision)
            .with_context(|| format!("subject {s} revision is missing"))?;
        let genesis = self.events[&subject].envelope();
        Ok(Current {
            subject,
            head,
            revision,
            body: r.body,
            asserted_time: r.asserted_time.clone(),
            key: genesis
                .subject_key
                .clone()
                .context("Genesis lacks a subject key")?,
            creator: genesis.author,
        })
    }
    /// The valid edge reading for an `EdgeAssert` id.
    pub fn edge(&self, edge: Hash) -> Result<&EdgeReading> {
        self.projection
            .edges
            .iter()
            .find(|e| e.edge == edge)
            .with_context(|| {
                format!(
                    "edge {} is not a valid edge in the context",
                    hex::encode(edge)
                )
            })
    }
    /// The one active grant `holder` holds for `subject`, or the requested one.
    pub fn grant(&self, subject: Hash, holder: Hash, requested: Option<Hash>) -> Result<Hash> {
        let a = &self.projection.authority;
        let held: Vec<Hash> = a
            .active
            .iter()
            .filter(|g| {
                a.grants
                    .get(*g)
                    .is_some_and(|g| g.subject == subject && g.holder == holder)
            })
            .copied()
            .collect();
        match requested {
            Some(g) if held.contains(&g) => Ok(g),
            Some(g) => bail!(
                "grant {} is not an active grant of this key for the subject",
                hex::encode(g)
            ),
            None => match held.as_slice() {
                [g] => Ok(*g),
                [] => bail!(
                    "this key holds no active grant for subject {}",
                    hex::encode(subject)
                ),
                _ => bail!("this key holds several active grants for the subject; pass --grant"),
            },
        }
    }
    /// Admission state of a context event.
    pub fn state(&self, id: Hash) -> Option<State> {
        let row = self.projection.rows.iter().find(|r| r.event == id)?;
        use cc_ledger::v1::ProjectionState::*;
        Some(match row.state {
            Pending => State::Pending,
            Invalid => State::Invalid,
            _ => State::Valid,
        })
    }
    pub fn kind(&self, id: Hash) -> Option<Kind> {
        self.events.get(&id).map(|e| e.envelope().payload.kind())
    }

    /// The node's branch-local admission over this corpus plus `new`: each new
    /// event must be `valid`, exactly as the node would classify it now.
    pub fn self_check(&self, new: &[Signed]) -> Result<()> {
        let mut all = self.events.clone();
        for s in new {
            ensure!(
                s.envelope().instance == self.instance,
                "event belongs to another instance than the context"
            );
            all.insert(s.id(), s.clone());
        }
        let status = classify(&all);
        for s in new {
            let st = &status[&s.id()];
            ensure!(
                st.state == State::Valid,
                "cc_ledger::v1 classifies {} event {} as {:?} ({})",
                super::entry_packet::kind_name(s.envelope().payload.kind()),
                hex::encode(s.id()),
                st.state,
                st.reason
            );
        }
        Ok(())
    }
}
