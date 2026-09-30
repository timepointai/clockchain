//! Stage (b) candidate admission and authority. No frontier, support or readiness.
//! HTTP, import and restore must all use `Store::admit`; SQL insertion is private.
use cc_core::v1::{hash, root_grant, Hash, Kind, Payload, Signed, Value};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
mod authority;
pub use authority::{Authority, Effect, Grant};

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
            if matches!(
                kind,
                Kind::EdgeAssert | Kind::EdgeReaffirm | Kind::Attestation
            ) {
                if e.subject.is_some()
                    || e.subject_key.is_some()
                    || e.grant.is_some()
                    || e.asserted_time.is_some()
                {
                    return Status::invalid("non_subject_header");
                }
                return Status::pending("stage_d_not_implemented", vec![]);
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
            if kind == Kind::Resolve {
                return Status::pending("stage_c_not_implemented", vec![]);
            }
            let parent = e.parents.0[0];
            let past = authority::cone(all, parent);
            let view = authority::derive(&past);
            let grant = e.grant.unwrap();
            if !view.active.contains(&grant) || view.grants[&grant].holder != e.author {
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
                _ => unreachable!(),
            }
            Status::valid()
        })()
    }
    let mut out = BTreeMap::new();
    // Iterative dependency evaluation: no chain-depth policy or recursive stack
    // ceiling. An unavailable parent stays pending; display order is irrelevant.
    while out.len() < candidates.len() {
        let before = out.len();
        for (&id, event) in candidates {
            if out.contains_key(&id) {
                continue;
            }
            let e = event.envelope();
            let no_parent_semantics = matches!(
                e.payload.kind(),
                Kind::Genesis | Kind::EdgeAssert | Kind::EdgeReaffirm | Kind::Attestation
            );
            if no_parent_semantics
                || e.parents.0.iter().any(|p| !candidates.contains_key(p))
                || e.parents.0.iter().all(|p| out.contains_key(p))
            {
                out.insert(id, evaluate(id, candidates, &out));
            }
        }
        if out.len() == before {
            for &id in candidates.keys() {
                out.entry(id).or_insert_with(|| Status::invalid("cycle"));
            }
        }
    }
    out
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
        .filter(|(id, _)| admission[*id].state == State::Valid)
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
    #[error("stage_b_non_serving")]
    NonServing,
    #[error("invalid_node_receipt")]
    Receipt,
}
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    instance: Hash,
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
        Ok(Self { pool, instance })
    }
    pub fn readiness(&self) -> Result<(), Error> {
        Err(Error::NonServing)
    }
    /// The sole v1 semantic write entry point, including import and restore.
    pub async fn admit(&self, bytes: &[u8]) -> Result<Outcome, Error> {
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
                return Ok(Outcome {
                    event: None,
                    input_digest: digest,
                    status: Status::invalid(reason),
                    authority: None,
                });
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
        sqlx::query(
            "INSERT INTO cc_v1.candidates(event_id,envelope) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(id.to_vec())
        .bind(bytes)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Outcome {
            event: Some(id),
            input_digest: digest,
            status,
            authority,
        })
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
    pub async fn import(&self, envelopes: &[Vec<u8>]) -> Result<Vec<Outcome>, Error> {
        let mut out = Vec::new();
        for bytes in envelopes {
            out.push(self.admit(bytes).await?);
        }
        Ok(out)
    }
    pub async fn restore(&self, envelopes: &[Vec<u8>]) -> Result<Vec<Outcome>, Error> {
        self.import(envelopes).await
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
    pub async fn review(&self) -> Result<BTreeMap<Hash, Status>, Error> {
        Ok(classify(&self.verified_candidates().await?))
    }
    pub async fn review_authority(&self) -> Result<Analysis, Error> {
        Ok(analyze(&self.verified_candidates().await?))
    }
}
