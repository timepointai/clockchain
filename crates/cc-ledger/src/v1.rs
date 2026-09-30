//! Stage (a) candidate admission. No v1 projection, filter support, or serving readiness.
//! HTTP, import and restore must all use `Store::admit`; SQL insertion is private.
use cc_core::v1::{hash, root_grant, Hash, Kind, Payload, Signed, Value};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};

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
}

/// Branch-local admission only. Valid does not mean head, support, or publishable.
/// Unsupported later-stage semantics remain explicit pending candidates.
pub fn classify(candidates: &BTreeMap<Hash, Signed>) -> BTreeMap<Hash, Status> {
    fn evaluate(
        id: Hash,
        all: &BTreeMap<Hash, Signed>,
        out: &mut BTreeMap<Hash, Status>,
        visiting: &mut BTreeSet<Hash>,
    ) -> Status {
        if let Some(s) = out.get(&id) {
            return s.clone();
        }
        if !visiting.insert(id) {
            return Status::invalid("cycle");
        }
        let e = all[&id].envelope();
        let kind = e.payload.kind();
        let result = (|| {
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
            let parent_states: Vec<_> = e
                .parents
                .0
                .iter()
                .map(|p| evaluate(*p, all, out, visiting))
                .collect();
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
            match &e.payload {
                Payload::Correction { body, decision } => {
                    if e.grant != Some(root_grant(subject)) || e.author != genesis.envelope().author
                    {
                        return Status::invalid("parent_authority");
                    }
                    let old = match &all[&e.parents.0[0]].envelope().payload {
                        Payload::Genesis { body, .. } | Payload::Correction { body, .. } => *body,
                        _ => return Status::pending("stage_b_c_not_implemented", vec![]),
                    };
                    if decision.old != Value::Body(old) || decision.new != Value::Body(*body) {
                        return Status::invalid("decision_mismatch");
                    }
                    Status::valid()
                }
                Payload::Delegate { .. } | Payload::Revoke { .. } => {
                    Status::pending("stage_b_not_implemented", vec![])
                }
                Payload::Resolve { .. } => Status::pending("stage_c_not_implemented", vec![]),
                _ => unreachable!(),
            }
        })();
        visiting.remove(&id);
        out.insert(id, result.clone());
        result
    }
    let mut out = BTreeMap::new();
    for id in candidates.keys() {
        evaluate(*id, candidates, &mut out, &mut BTreeSet::new());
    }
    out
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
    #[error("stage_a_non_serving")]
    NonServing,
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
        let status = classify(&candidates).remove(&id).ok_or(Error::Corrupt)?;
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
        })
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
    pub async fn review(&self) -> Result<BTreeMap<Hash, Status>, Error> {
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
        Ok(classify(&candidates))
    }
}
