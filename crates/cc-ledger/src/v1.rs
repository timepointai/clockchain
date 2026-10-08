//! v1 admission, projection and versioned rule identity. Served by `cc-node` in
//! explicit v1 mode only, and only through the versioned snapshot reads.
//! HTTP, import and restore must all use `Store::admit`; SQL insertion is private.
use cc_core::v1::{hash, root_grant, Hash, Kind, Payload, Selection, Signed, Value};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
mod authority;
mod edges;
mod projection;
mod rule;
mod serving;
pub use authority::{Authority, Effect, Grant};
pub use edges::{
    support_graph, EdgeReading, Exclusion, MediaReading, Neighbor, Reason, Support, SupportGraph,
    RELATIONS,
};
pub use projection::{
    project, EventReading, Projection, ProjectionState, Revision, SubjectReading,
};
pub use rule::{canonical_rows, EntityRead, ExportManifest, Readiness, RuleId, Snapshot, Verdict};
pub use serving::CacheKey;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Valid,
    Pending,
    Invalid,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub state: State,
    pub reason: String,
    pub missing: Vec<Hash>,
}
impl Status {
    fn valid() -> Self {
        Self {
            state: State::Valid,
            reason: String::new(),
            missing: vec![],
        }
    }
    fn invalid(reason: &str) -> Self {
        Self {
            state: State::Invalid,
            reason: reason.into(),
            missing: vec![],
        }
    }
    fn pending(reason: &str, missing: Vec<Hash>) -> Self {
        Self {
            state: State::Pending,
            reason: reason.into(),
            missing,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub event: Option<Hash>,
    pub input_digest: Hash,
    pub status: Status,
    pub authority: Option<Effect>,
}

/// Branch-local admission only. Valid does not mean head, support, or publishable.
/// Unsupported later-stage semantics remain explicit pending candidates.
pub fn classify(candidates: &BTreeMap<Hash, Signed>) -> BTreeMap<Hash, Status> {
    fn evaluate(id: Hash, all: &BTreeMap<Hash, Signed>, out: &BTreeMap<Hash, Status>) -> Status {
        let e = all[&id].envelope();
        let kind = e.payload.kind();
        (|| {
            if e.asserted_time
                .as_ref()
                .is_some_and(|t| t.precision.is_empty())
            {
                return Status::invalid("precision");
            }
            if kind == Kind::Genesis {
                return if e.subject.is_none()
                    && e.grant.is_none()
                    && e.parents.0.is_empty()
                    && e.subject_key.is_some()
                {
                    Status::valid()
                } else {
                    Status::invalid("genesis")
                };
            }
            if e.parents.0.is_empty()
                || (kind != Kind::Resolve && e.parents.0.len() != 1)
                || (kind == Kind::Resolve && e.parents.0.len() < 2)
            {
                return Status::invalid("parents");
            }
            if e.subject.is_none() || e.subject_key.is_none() || e.grant.is_none() {
                return Status::invalid("subject_header");
            }
            let missing: Vec<_> = e
                .parents
                .0
                .iter()
                .filter(|p| !all.contains_key(*p))
                .copied()
                .collect();
            if !missing.is_empty() {
                return Status::pending("parent_missing", missing);
            }
            // An edge or attestation is never a subject parent.
            if e.parents.0.iter().any(|p| !is_subject(&all[p])) {
                return Status::invalid("wrong_subject");
            }
            let parent_states: Vec<_> = e.parents.0.iter().map(|p| out[p].clone()).collect();
            if parent_states.iter().any(|s| s.state == State::Invalid) {
                return Status::invalid("ancestor");
            }
            let subject = e.subject.unwrap();
            for p in &e.parents.0 {
                let parent = all[p].envelope();
                let parent_subject = if parent.payload.kind() == Kind::Genesis {
                    Some(*p)
                } else {
                    parent.subject
                };
                if parent_subject != Some(subject) {
                    return Status::invalid("wrong_subject");
                }
                if parent.subject_key != e.subject_key {
                    return Status::invalid("subject_key_changed");
                }
            }
            if parent_states.iter().any(|s| s.state == State::Pending) {
                return Status::pending("ancestor", vec![]);
            }
            let Some(genesis) = all.get(&subject) else {
                return Status::pending("subject_missing", vec![subject]);
            };
            if genesis.envelope().payload.kind() != Kind::Genesis {
                return Status::invalid("wrong_subject");
            }
            let Some(d) = e.payload.decision() else {
                return Status::invalid("decision_missing");
            };
            if d.kind != kind
                || d.parents != e.parents
                || d.rationale.is_empty()
                || d.evidence.0.is_empty()
            {
                return Status::invalid("decision_mismatch");
            }
            if matches!(kind, Kind::Delegate | Kind::Revoke) && e.asserted_time.is_some() {
                return Status::invalid("authority_time_edit");
            }
            let parent = e.parents.0[0];
            let cones: Vec<_> = e
                .parents
                .0
                .iter()
                .map(|p| authority::cone(all, *p))
                .collect();
            if kind == Kind::Resolve
                && cones
                    .iter()
                    .any(|cone| e.parents.0.iter().filter(|p| cone.contains_key(*p)).count() > 1)
            {
                return Status::invalid("comparable_parents");
            }
            let past: BTreeMap<_, _> = cones.iter().flat_map(|c| c.clone()).collect();
            let view = authority::derive(&past);
            let grant = e.grant.unwrap();
            if !view.active.contains(&grant)
                || view.grants[&grant].holder != e.author
                || cones
                    .iter()
                    .any(|c| !authority::derive(c).active.contains(&grant))
            {
                return Status::invalid("parent_authority");
            }
            match &e.payload {
                Payload::Correction { body, decision } => {
                    if decision.old != Value::Body(authority::body(all, parent))
                        || decision.new != Value::Body(*body)
                    {
                        return Status::invalid("decision_mismatch");
                    }
                }
                Payload::Delegate {
                    grantee,
                    issuer,
                    decision,
                } => {
                    if *issuer != grant {
                        return Status::invalid("issuer_grant_mismatch");
                    }
                    if cc_core::AuthorKey::from_bytes(grantee).is_err() {
                        return Status::invalid("key");
                    }
                    if view.grants.values().any(|g| g.holder == *grantee) {
                        return Status::invalid("key_not_fresh");
                    }
                    if decision.old != Value::None
                        || decision.new
                            != (Value::Grant {
                                issuer: *issuer,
                                grantee: *grantee,
                            })
                    {
                        return Status::invalid("decision_mismatch");
                    }
                }
                Payload::Revoke {
                    target,
                    cascade,
                    decision,
                } => {
                    if !view.active.contains(target) || !authority::in_scope(&view, grant, *target)
                    {
                        return Status::invalid("revocation_scope");
                    }
                    if decision.old != Value::ActiveGrant(*target)
                        || decision.new
                            != (Value::RevokedGrant {
                                grant: *target,
                                cascade: *cascade,
                            })
                    {
                        return Status::invalid("decision_mismatch");
                    }
                }
                Payload::Resolve {
                    selection,
                    dispositions,
                    decision,
                } => {
                    if decision.old != Value::Heads(e.parents.clone())
                        || decision.new
                            != match selection {
                                Selection::MergedBody(b) => Value::Body(*b),
                                Selection::Revision(r) => Value::Revision(*r),
                            }
                        || dispositions.0.iter().map(|d| d.parent).collect::<Vec<_>>()
                            != e.parents.0
                        || dispositions.0.iter().any(|d| d.rationale.is_empty())
                    {
                        return Status::invalid("decision_mismatch");
                    }
                    use cc_core::v1::DispositionKind::{Merged, Selected};
                    match selection {
                        Selection::MergedBody(_) => {
                            if dispositions.0.iter().any(|d| d.action == Selected)
                                || !dispositions.0.iter().any(|d| d.action == Merged)
                            {
                                return Status::invalid("disposition_mismatch");
                            }
                        }
                        Selection::Revision(revision) => {
                            let revisions = projection::revisions(&past);
                            let Some(r) = revisions.get(revision) else {
                                return Status::invalid("revision_unreachable");
                            };
                            if !view.effects[&r.creating_event].reason.is_empty() {
                                return Status::invalid("revision_ineligible");
                            }
                            if e.asserted_time.is_some() {
                                return Status::invalid("selection_time_edit");
                            }
                            if dispositions.0.iter().any(|d| d.action == Merged)
                                || !dispositions.0.iter().any(|d| d.action == Selected)
                                || dispositions.0.iter().any(|d| {
                                    d.action == Selected
                                        && !authority::cone(&past, d.parent)
                                            .contains_key(&r.creating_event)
                                })
                            {
                                return Status::invalid("disposition_mismatch");
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
            Status::valid()
        })()
    }
    let mut out = BTreeMap::new();
    let subjects = candidates.iter().filter(|(_, e)| is_subject(e)).count();
    // Iterative dependency evaluation: no chain-depth policy or recursive stack
    // ceiling. An unavailable parent stays pending; display order is irrelevant.
    // Subject events are classified first; edges and media only read them.
    while out.len() < subjects {
        let before = out.len();
        for (&id, event) in candidates {
            if out.contains_key(&id) || !is_subject(event) {
                continue;
            }
            let e = event.envelope();
            if e.payload.kind() == Kind::Genesis
                || e.parents
                    .0
                    .iter()
                    .any(|p| !candidates.get(p).is_some_and(is_subject))
                || e.parents.0.iter().all(|p| out.contains_key(p))
            {
                out.insert(id, evaluate(id, candidates, &out));
            }
        }
        if out.len() == before {
            for (&id, event) in candidates {
                if is_subject(event) {
                    out.entry(id).or_insert_with(|| Status::invalid("cycle"));
                }
            }
        }
    }
    edges::classify(candidates, &mut out);
    out
}
pub(crate) fn is_subject(event: &Signed) -> bool {
    !matches!(
        event.envelope().payload.kind(),
        Kind::EdgeAssert | Kind::EdgeReaffirm | Kind::Attestation
    )
}

/// Branch validity and authority effects are separate; neither selects a body head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    pub admission: BTreeMap<Hash, Status>,
    pub authority: Authority,
}
pub fn analyze(candidates: &BTreeMap<Hash, Signed>) -> Analysis {
    let admission = classify(candidates);
    let valid = candidates
        .iter()
        .filter(|(id, e)| admission[*id].state == State::Valid && is_subject(e))
        .map(|(id, e)| (*id, e.clone()))
        .collect();
    Analysis {
        admission,
        authority: authority::derive(&valid),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("v1_requires_fresh_store")]
    NotEmpty,
    #[error("v1_store_identity_mismatch")]
    Identity,
    #[error("stored_candidate_corrupt")]
    Corrupt,
    #[error("v1_store_unprovisioned")]
    Unprovisioned,
    #[error("unsupported_fold_version")]
    UnsupportedFoldVersion,
    #[error("incompatible_rule_identity")]
    RuleIdentity,
    #[error("rule_identity_unbound")]
    Unbound,
    #[error("root_mismatch")]
    RootMismatch,
    #[error("invalid_node_receipt")]
    Receipt,
    #[error("body_hash_mismatch")]
    BodyHash,
}
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    instance: Hash,
    /// Boot-pinned filter identity; configuration, never a ledger event.
    rule: Option<cc_filter::v1::FilterIdentity>,
    /// The committed-snapshot cache, shared by clones; `None` folds on every
    /// read. Invalidated by every admission.
    cache: Option<serving::SnapshotCache>,
}
const SCHEMA: &str = include_str!("v1.sql");
impl Store {
    /// Provision a fresh database or reopen this exact stage schema/instance.
    /// An empty *projection* or migrated v0 database is not a fresh store.
    pub async fn provision(pool: PgPool, instance: Hash) -> Result<Self, Error> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(73424101)")
            .execute(&mut *tx)
            .await?;
        let exists: bool = sqlx::query_scalar("SELECT to_regclass('cc_v1.identity') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await?;
        let foreign: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','cc_v1') AND c.relkind IN ('r','p','v','m','S','f')").fetch_one(&mut *tx).await?;
        if foreign != 0 {
            return Err(Error::NotEmpty);
        }
        if !exists {
            let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S','f')").fetch_one(&mut *tx).await?;
            if n != 0 {
                return Err(Error::NotEmpty);
            }
            sqlx::raw_sql(SCHEMA).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO cc_v1.identity(singleton,instance,encoding,schema_hash) VALUES(true,$1,1,$2)").bind(instance.to_vec()).bind(hash(SCHEMA.as_bytes()).to_vec()).execute(&mut *tx).await?;
        }
        let row = sqlx::query(
            "SELECT instance,encoding,schema_hash FROM cc_v1.identity WHERE singleton=true",
        )
        .fetch_one(&mut *tx)
        .await?;
        if row.get::<Vec<u8>, _>("instance") != instance
            || row.get::<i16, _>("encoding") != 1
            || row.get::<Vec<u8>, _>("schema_hash") != hash(SCHEMA.as_bytes())
        {
            return Err(Error::Identity);
        }
        tx.commit().await?;
        Ok(Self {
            pool,
            instance,
            rule: None,
            cache: Some(Default::default()),
        })
    }
    /// Reopen a store that `provision` and `bind` already set up, for serving.
    /// Never creates the schema or records a rule identity, and runs read-only:
    /// an unprovisioned, foreign, unbound or mismatched database is refused
    /// before anything is written.
    pub async fn open(
        pool: PgPool,
        instance: Hash,
        filter: cc_filter::v1::FilterIdentity,
    ) -> Result<Self, Error> {
        if !cc_core::v1::rule::supported_fold(&filter.fold) {
            return Err(Error::UnsupportedFoldVersion);
        }
        if !filter.is_governed() {
            return Err(Error::RuleIdentity);
        }
        let mut tx = pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        let foreign: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','cc_v1') AND c.relkind IN ('r','p','v','m','S','f')").fetch_one(&mut *tx).await?;
        if foreign != 0 {
            return Err(Error::NotEmpty);
        }
        let exists: bool = sqlx::query_scalar("SELECT to_regclass('cc_v1.identity') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(Error::Unprovisioned);
        }
        let row = sqlx::query(
            "SELECT instance,encoding,schema_hash FROM cc_v1.identity WHERE singleton=true",
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::Unprovisioned)?;
        if row.get::<Vec<u8>, _>("instance") != instance
            || row.get::<i16, _>("encoding") != 1
            || row.get::<Vec<u8>, _>("schema_hash") != hash(SCHEMA.as_bytes())
        {
            return Err(Error::Identity);
        }
        tx.commit().await?;
        let store = Self {
            pool,
            instance,
            rule: Some(filter),
            cache: Some(Default::default()),
        };
        store.readiness().await?;
        Ok(store)
    }
    /// The instance this store was opened or provisioned for.
    pub fn instance(&self) -> Hash {
        self.instance
    }
    /// Serving readiness: the bound identity is recorded, supported and equal
    /// to the stored one. Anything else is the refusal that names why.
    pub async fn readiness(&self) -> Result<RuleId, Error> {
        let r = self.semantic_readiness().await?;
        match r.semantic.as_str() {
            "ready" => r.rule.ok_or(Error::Unbound),
            "rule_identity_unbound" | "rule_identity_unrecorded" => Err(Error::Unbound),
            "unsupported_fold_version" => Err(Error::UnsupportedFoldVersion),
            _ => Err(Error::RuleIdentity),
        }
    }
    /// The sole v1 semantic write entry point, including import and restore.
    pub async fn admit(&self, bytes: &[u8]) -> Result<Outcome, Error> {
        Ok(self.admit_observed(bytes, None).await?.0)
    }
    /// [`Store::admit`], and, when `node` is given and this call retained the
    /// candidate for the first time, a signed `NodeReceiptV1` for it, written
    /// to `cc_v1.receipts` in the same transaction. The outcome is identical
    /// with or without `node`; receipts never enter the candidate set.
    /// Every call invalidates the snapshot cache, whatever its outcome.
    pub async fn admit_observed(
        &self,
        bytes: &[u8],
        node: Option<&cc_core::SecretKey>,
    ) -> Result<(Outcome, Option<cc_core::v1::receipt::SignedReceipt>), Error> {
        let result = self.admit_once(bytes, node).await;
        if let Some(cache) = &self.cache {
            cache.invalidate();
        }
        result
    }
    async fn admit_once(
        &self,
        bytes: &[u8],
        node: Option<&cc_core::SecretKey>,
    ) -> Result<(Outcome, Option<cc_core::v1::receipt::SignedReceipt>), Error> {
        // A receipt names the fold it was observed under; refuse before any
        // write if there is none.
        let observer = match node {
            Some(key) => Some((key, self.bound(None)?)),
            None => None,
        };
        let digest = hash(bytes);
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT singleton FROM cc_v1.identity WHERE singleton=true FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
        let signed = Signed::decode(bytes);
        let signed = match signed {
            Ok(s) if s.envelope().instance == self.instance => s,
            other => {
                let reason = match other {
                    Err(e) => e.0,
                    Ok(_) => "wrong_instance",
                };
                sqlx::query("INSERT INTO cc_v1.rejections(input_digest,reason) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(digest.to_vec()).bind(reason).execute(&mut *tx).await?;
                tx.commit().await?;
                return Ok((
                    Outcome {
                        event: None,
                        input_digest: digest,
                        status: Status::invalid(reason),
                        authority: None,
                    },
                    None,
                ));
            }
        };
        let id = signed.id();
        let rows = sqlx::query("SELECT event_id,envelope FROM cc_v1.candidates ORDER BY event_id")
            .fetch_all(&mut *tx)
            .await?;
        let mut candidates = BTreeMap::new();
        for row in rows {
            let wire: Vec<u8> = row.get("envelope");
            let s = Signed::decode(&wire).map_err(|_| Error::Corrupt)?;
            if s.envelope().instance != self.instance || row.get::<Vec<u8>, _>("event_id") != s.id()
            {
                return Err(Error::Corrupt);
            }
            candidates.insert(s.id(), s);
        }
        candidates.insert(id, signed);
        let mut analysis = analyze(&candidates);
        let status = analysis.admission.remove(&id).ok_or(Error::Corrupt)?;
        let authority = analysis.authority.effects.remove(&id);
        let inserted = sqlx::query(
            "INSERT INTO cc_v1.candidates(event_id,envelope) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(id.to_vec())
        .bind(bytes)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let receipt = match observer {
            Some((key, filter)) if inserted => {
                let r = serving::receipt_for(
                    key,
                    self.instance,
                    filter,
                    id,
                    &status,
                    serving::now_micros(),
                )?;
                sqlx::query(
                    "INSERT INTO cc_v1.receipts(receipt_digest,event_id,envelope) VALUES($1,$2,$3)",
                )
                .bind(hash(r.bytes()).to_vec())
                .bind(id.to_vec())
                .bind(r.bytes())
                .execute(&mut *tx)
                .await?;
                Some(r)
            }
            _ => None,
        };
        tx.commit().await?;
        Ok((
            Outcome {
                event: Some(id),
                input_digest: digest,
                status,
                authority,
            },
            receipt,
        ))
    }
    /// Retain a verified node observation separately. No grant, event, or
    /// admission boolean is installed from it. This does not endorse its node
    /// key or fold identity; serving version policy remains stage (e).
    pub async fn retain_receipt(&self, bytes: &[u8]) -> Result<(), Error> {
        let signed =
            cc_core::v1::receipt::SignedReceipt::decode(bytes).map_err(|_| Error::Receipt)?;
        let r = signed.receipt();
        if r.instance != self.instance {
            return Err(Error::Receipt);
        }
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM cc_v1.candidates WHERE event_id=$1)")
                .bind(r.event.to_vec())
                .fetch_one(&self.pool)
                .await?;
        if !exists {
            return Err(Error::Receipt);
        }
        sqlx::query("INSERT INTO cc_v1.receipts(receipt_digest,event_id,envelope) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(hash(bytes).to_vec()).bind(r.event.to_vec()).bind(bytes).execute(&self.pool).await?;
        Ok(())
    }
    /// Admit each envelope in order. Private: the served path to bulk
    /// admission is [`Store::restore_export`], which verifies the root first.
    async fn admit_all(&self, envelopes: &[Vec<u8>]) -> Result<Vec<Outcome>, Error> {
        let mut out = Vec::new();
        for bytes in envelopes {
            out.push(self.admit(bytes).await?);
        }
        Ok(out)
    }
    /// Raw bulk import and restore without a verified root. Operator review
    /// and tests only (`review` feature).
    #[cfg(feature = "review")]
    pub async fn import(&self, envelopes: &[Vec<u8>]) -> Result<Vec<Outcome>, Error> {
        self.admit_all(envelopes).await
    }
    #[cfg(feature = "review")]
    pub async fn restore(&self, envelopes: &[Vec<u8>]) -> Result<Vec<Outcome>, Error> {
        self.admit_all(envelopes).await
    }
    /// Recompute classifications from verified retained bytes, never a cached verdict.
    async fn verified_candidates(&self) -> Result<BTreeMap<Hash, Signed>, Error> {
        let rows = sqlx::query("SELECT event_id,envelope FROM cc_v1.candidates ORDER BY event_id")
            .fetch_all(&self.pool)
            .await?;
        let mut candidates = BTreeMap::new();
        for row in rows {
            let wire: Vec<u8> = row.get("envelope");
            let s = Signed::decode(&wire).map_err(|_| Error::Corrupt)?;
            if s.envelope().instance != self.instance || row.get::<Vec<u8>, _>("event_id") != s.id()
            {
                return Err(Error::Corrupt);
            }
            candidates.insert(s.id(), s);
        }
        Ok(candidates)
    }
    // Unversioned review reads (STAGE-E N3). Compiled only with the `review`
    // feature, which tests enable; the served binary has only versioned reads.
    #[cfg(feature = "review")]
    pub async fn review(&self) -> Result<BTreeMap<Hash, Status>, Error> {
        Ok(classify(&self.verified_candidates().await?))
    }
    #[cfg(feature = "review")]
    pub async fn review_authority(&self) -> Result<Analysis, Error> {
        Ok(analyze(&self.verified_candidates().await?))
    }
    #[cfg(feature = "review")]
    pub async fn review_projection(&self) -> Result<Projection, Error> {
        Ok(project(&self.verified_candidates().await?))
    }
    /// Optional content-addressed bytes. Availability cannot change the fold.
    /// Returns whether these bytes were newly retained.
    pub async fn retain_body(&self, expected: Hash, bytes: &[u8]) -> Result<bool, Error> {
        if hash(bytes) != expected {
            return Err(Error::BodyHash);
        }
        let inserted = sqlx::query(
            "INSERT INTO cc_v1.bodies(body_hash,bytes) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(expected.to_vec())
        .bind(bytes)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(inserted == 1)
    }
    pub async fn body_bytes(&self, expected: Hash) -> Result<Option<Vec<u8>>, Error> {
        let bytes: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT bytes FROM cc_v1.bodies WHERE body_hash=$1")
                .bind(expected.to_vec())
                .fetch_optional(&self.pool)
                .await?;
        if bytes.as_ref().is_some_and(|b| hash(b) != expected) {
            return Err(Error::Corrupt);
        }
        Ok(bytes)
    }
}
