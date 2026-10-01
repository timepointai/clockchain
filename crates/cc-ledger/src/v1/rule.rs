//! Versioned rule identity: binding, semantic readiness, committed snapshots,
//! `as_of` reads, verdicts, cache keys, export and restore. Every read names
//! `(fold_version, filter_version, corpus_digest)`.
use super::*;
use cc_core::v1::receipt::FoldRef;
use cc_core::v1::rule::{cache_key, corpus_digest, supported_fold, view_commitment};
use cc_filter::v1::FilterIdentity;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleId {
    pub fold_version: u16,
    pub fold_manifest: Hash,
    pub filter_version: Hash,
}
impl RuleId {
    fn of(f: &FilterIdentity) -> Self {
        Self {
            fold_version: f.fold.version,
            fold_manifest: f.fold.manifest,
            filter_version: f.version(),
        }
    }
    fn fold(&self) -> FoldRef {
        FoldRef {
            version: self.fold_version,
            manifest: self.fold_manifest,
        }
    }
}
/// `semantic` is `ready` or the refusal reason. `serving` is true only for a
/// bound, recorded, supported and matching rule identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Readiness {
    pub serving: bool,
    pub semantic: String,
    pub rule: Option<RuleId>,
}

/// Canonical projection rows: every status/reason, frontier, revision,
/// authority, decision (in each signed envelope), edge and media reading.
/// Receipts and body availability are not part of the projection.
pub fn canonical_rows(p: &Projection) -> Vec<u8> {
    #[derive(Serialize)]
    struct Rows<'a> {
        schema: &'static str,
        rows: &'a [EventReading],
        revisions: &'a [Revision],
        subjects: &'a [SubjectReading],
        grants: Vec<(&'a Hash, &'a Grant)>,
        active: &'a BTreeSet<Hash>,
        tombstones: &'a BTreeSet<Hash>,
        effective_revokes: &'a BTreeSet<Hash>,
        canceled: &'a BTreeSet<Hash>,
        effects: Vec<(&'a Hash, &'a Effect)>,
        edges: &'a [EdgeReading],
        media: &'a [MediaReading],
    }
    let a = &p.authority;
    serde_json::to_vec(&Rows {
        schema: "cc.view-rows.json.v1",
        rows: &p.rows,
        revisions: &p.revisions,
        subjects: &p.subjects,
        grants: a.grants.iter().collect(),
        active: &a.active,
        tombstones: &a.tombstones,
        effective_revokes: &a.effective_revokes,
        canceled: &a.canceled,
        effects: a.effects.iter().collect(),
        edges: &p.edges,
        media: &p.media,
    })
    .expect("projection rows serialize")
}

/// A projection committed under one exact rule identity and corpus snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub rule: RuleId,
    pub corpus_digest: Hash,
    pub commitment: Hash,
    pub projection: Projection,
    filter: FilterIdentity,
}
impl Snapshot {
    pub fn of(filter: &FilterIdentity, candidates: &BTreeMap<Hash, Signed>) -> Self {
        let projection = project(candidates);
        let corpus = corpus_digest(&candidates.keys().copied().collect());
        let commitment = view_commitment(
            &filter.fold,
            filter.version(),
            corpus,
            &canonical_rows(&projection),
        );
        Self {
            rule: RuleId::of(filter),
            corpus_digest: corpus,
            commitment,
            projection,
            filter: filter.clone(),
        }
    }
    pub fn cache_key(&self, query: &[u8]) -> Hash {
        cache_key(self.rule.filter_version, self.corpus_digest, query)
    }
    /// `as_of` filters claim visibility after the full authority/conflict fold:
    /// the current revision is visible only if its asserted coordinate is at or
    /// before `as_of`. It never changes authority, frontier or precedence.
    fn visibility(&self, subject: Hash, as_of: Option<Hash>) -> (String, Option<Revision>) {
        let p = &self.projection;
        let Some(s) = p.subjects.iter().find(|s| s.subject == subject) else {
            return ("subject_unknown".into(), None);
        };
        if s.state != "resolved" {
            return (s.state.clone(), None);
        }
        let head = s.frontier.first().unwrap();
        let id = p.rows.iter().find(|r| r.event == *head).unwrap().revision;
        let revision = p.revisions.iter().find(|r| Some(r.id) == id).cloned();
        let state = match (
            as_of,
            revision.as_ref().and_then(|r| r.asserted_time.as_ref()),
        ) {
            (None, _) => "visible",
            (Some(_), None) => "asserted_time_unknown",
            (Some(q), Some(t)) if t.coordinate > q => "after_as_of",
            _ => "visible",
        };
        (state.into(), revision)
    }
    pub fn entity(&self, subject: Hash, as_of: Option<Hash>) -> EntityRead {
        let (visibility, revision) = self.visibility(subject, as_of);
        let reading = self
            .projection
            .subjects
            .iter()
            .find(|s| s.subject == subject);
        EntityRead {
            rule: self.rule.clone(),
            corpus_digest: self.corpus_digest,
            as_of,
            subject,
            state: reading.map(|s| s.state.clone()).unwrap_or_default(),
            frontier: reading.map(|s| s.frontier.clone()).unwrap_or_default(),
            revision: revision.filter(|_| visibility == "visible"),
            visibility,
        }
    }
    /// Governed support graph at `as_of`: subjects whose current revision is
    /// not visible lose their neighbors, which become explicit exclusions.
    pub fn support(&self, as_of: Option<Hash>) -> SupportGraph {
        let curators = self.filter.curators.iter().copied().collect();
        let mut g = support_graph(&self.projection, &curators);
        let hidden: BTreeMap<Hash, String> = g
            .subjects
            .iter()
            .filter(|(_, state)| *state == "resolved")
            .map(|(s, _)| (*s, self.visibility(*s, as_of).0))
            .filter(|(_, v)| v != "visible")
            .collect();
        for (subject, reason) in &hidden {
            g.subjects.insert(*subject, reason.clone());
            for n in g.neighbors.remove(subject).unwrap_or_default() {
                if let Some(other) = g.neighbors.get_mut(&n.subject) {
                    other.retain(|m| m.edge != n.edge);
                }
                let e = self
                    .projection
                    .edges
                    .iter()
                    .find(|e| e.edge == n.edge)
                    .unwrap();
                g.excluded.push(Exclusion {
                    edge: n.edge,
                    event: n.edge,
                    source: e.pins[0].source.subject,
                    target: e.pins[0].target.subject,
                    reasons: vec![format!("as_of:{reason}")],
                });
            }
        }
        g.neighbors.retain(|_, n| !n.is_empty());
        g.excluded.sort_by_key(|x| (x.edge, x.event));
        g.excluded.dedup();
        g
    }
    pub fn verdict(&self, from: Hash, to: Hash, as_of: Option<Hash>) -> Verdict {
        Verdict {
            rule: self.rule.clone(),
            corpus_digest: self.corpus_digest,
            as_of,
            support: self
                .support(as_of)
                .query(from, to, usize::from(self.filter.max_hops)),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EntityRead {
    pub rule: RuleId,
    pub corpus_digest: Hash,
    pub as_of: Option<Hash>,
    pub subject: Hash,
    pub state: String,
    pub frontier: BTreeSet<Hash>,
    /// Present only when visible under `as_of`.
    pub revision: Option<Revision>,
    pub visibility: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub rule: RuleId,
    pub corpus_digest: Hash,
    pub as_of: Option<Hash>,
    pub support: Support,
}
/// Retained candidates plus the root they were committed under. Restore
/// verifies that root before admitting anything and never reinterprets it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportManifest {
    pub encoding: u16,
    pub rule: RuleId,
    pub corpus_digest: Hash,
    pub commitment: Hash,
    pub envelopes: Vec<Vec<u8>>,
}

impl Store {
    /// Bind the boot-pinned filter identity. A fresh store records it; a store
    /// already bound to another identity refuses.
    pub async fn bind(mut self, filter: FilterIdentity) -> Result<Self, Error> {
        if !supported_fold(&filter.fold) {
            return Err(Error::UnsupportedFoldVersion);
        }
        // Commitments must never name a policy or encoding this build lacks.
        if !filter.is_governed() {
            return Err(Error::RuleIdentity);
        }
        sqlx::query("INSERT INTO cc_v1.rule_identity(singleton,fold_version,fold_manifest,filter_identity) VALUES(true,$1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(filter.fold.version as i16).bind(filter.fold.manifest.to_vec()).bind(filter.canonical())
            .execute(&self.pool).await?;
        self.rule = Some(filter);
        match self.semantic_readiness().await?.semantic.as_str() {
            "ready" => Ok(self),
            "unsupported_fold_version" => Err(Error::UnsupportedFoldVersion),
            _ => Err(Error::RuleIdentity),
        }
    }
    pub async fn semantic_readiness(&self) -> Result<Readiness, Error> {
        let row = sqlx::query(
            "SELECT fold_version,fold_manifest,filter_identity FROM cc_v1.rule_identity",
        )
        .fetch_optional(&self.pool)
        .await?;
        let semantic = match (&self.rule, row) {
            (None, _) => "rule_identity_unbound",
            (Some(_), None) => "rule_identity_unrecorded",
            (Some(rule), Some(row)) => {
                let stored = FoldRef {
                    version: row.get::<i16, _>("fold_version") as u16,
                    manifest: row
                        .get::<Vec<u8>, _>("fold_manifest")
                        .try_into()
                        .map_err(|_| Error::Corrupt)?,
                };
                if !supported_fold(&stored) {
                    "unsupported_fold_version"
                } else if row.get::<Vec<u8>, _>("filter_identity") != rule.canonical() {
                    "incompatible_rule_identity"
                } else {
                    "ready"
                }
            }
        };
        Ok(Readiness {
            serving: semantic == "ready",
            semantic: semantic.into(),
            rule: self.rule.as_ref().map(RuleId::of),
        })
    }
    fn bound(&self, requested: Option<&FoldRef>) -> Result<&FilterIdentity, Error> {
        let rule = self.rule.as_ref().ok_or(Error::Unbound)?;
        if requested.is_some_and(|r| !supported_fold(r) || *r != rule.fold) {
            return Err(Error::UnsupportedFoldVersion);
        }
        Ok(rule)
    }
    async fn ready(&self, requested: Option<&FoldRef>) -> Result<&FilterIdentity, Error> {
        let rule = self.bound(requested)?;
        match self.semantic_readiness().await?.semantic.as_str() {
            "ready" => Ok(rule),
            "unsupported_fold_version" => Err(Error::UnsupportedFoldVersion),
            _ => Err(Error::RuleIdentity),
        }
    }
    /// Recompute and commit the projection under the bound rule identity.
    pub async fn snapshot(&self, requested: Option<&FoldRef>) -> Result<Snapshot, Error> {
        let rule = self.ready(requested).await?;
        Ok(Snapshot::of(rule, &self.verified_candidates().await?))
    }
    pub async fn export(&self, requested: Option<&FoldRef>) -> Result<ExportManifest, Error> {
        let rule = self.ready(requested).await?;
        let candidates = self.verified_candidates().await?;
        let s = Snapshot::of(rule, &candidates);
        Ok(ExportManifest {
            encoding: cc_core::CANON_VERSION,
            rule: s.rule,
            corpus_digest: s.corpus_digest,
            commitment: s.commitment,
            envelopes: candidates.values().map(|e| e.bytes().to_vec()).collect(),
        })
    }
    /// Verify the exported root under its own named rule before any admission.
    pub async fn restore_export(&self, m: &ExportManifest) -> Result<Vec<Outcome>, Error> {
        if m.encoding != cc_core::CANON_VERSION || !supported_fold(&m.rule.fold()) {
            return Err(Error::UnsupportedFoldVersion);
        }
        let rule = self.ready(Some(&m.rule.fold())).await?;
        if m.rule != RuleId::of(rule) {
            return Err(Error::RuleIdentity);
        }
        let mut candidates = BTreeMap::new();
        for bytes in &m.envelopes {
            let s = Signed::decode(bytes).map_err(|_| Error::Corrupt)?;
            if s.envelope().instance != self.instance {
                return Err(Error::Corrupt);
            }
            candidates.insert(s.id(), s);
        }
        let s = Snapshot::of(rule, &candidates);
        if s.corpus_digest != m.corpus_digest || s.commitment != m.commitment {
            return Err(Error::RootMismatch);
        }
        self.import(&m.envelopes).await
    }
}
