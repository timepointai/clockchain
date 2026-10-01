//! Stage (d): both-endpoint pinned edges, author-only reaffirmation chains,
//! enforced neighbor filtering and revision-scoped media. Edges never select a
//! body, change authority, retarget a pin or infer a media decision.
use super::projection::{revisions, selections};
use super::*;
use cc_core::v1::{revision_id, Pin, Pins, Set, TargetKind};

/// Governed v1 relation names. `disputes` is evidence, never positive support.
pub const RELATIONS: [&str; 5] = [
    "causation",
    "co_occurrence",
    "disputes",
    "influence",
    "participation",
];

/// Valid subject events with their selected revisions; edges only read these.
struct Subjects {
    valid: BTreeMap<Hash, Signed>,
    selected: BTreeMap<Hash, Hash>,
    revisions: BTreeMap<Hash, Revision>,
}
impl Subjects {
    fn new(candidates: &BTreeMap<Hash, Signed>, out: &BTreeMap<Hash, Status>) -> Self {
        let valid: BTreeMap<_, _> = candidates
            .iter()
            .filter(|(id, e)| is_subject(e) && out[*id].state == State::Valid)
            .map(|(&id, e)| (id, e.clone()))
            .collect();
        Self {
            selected: selections(&valid),
            revisions: revisions(&valid),
            valid,
        }
    }
}

fn pins_of(event: &Signed) -> &Pins {
    match &event.envelope().payload {
        Payload::EdgeAssert { pins, .. } => pins,
        Payload::EdgeReaffirm { new, .. } => new,
        _ => unreachable!("only edge events carry pins"),
    }
}
fn edge_of(id: Hash, event: &Signed) -> Option<Hash> {
    match &event.envelope().payload {
        Payload::EdgeAssert { .. } => Some(id),
        Payload::EdgeReaffirm { edge, .. } => Some(*edge),
        _ => None,
    }
}

/// `basis` must be a valid event of `subject` whose selection is exactly the
/// pinned revision, and that revision must bind exactly the pinned body hash.
fn check_pin(
    pin: &Pin,
    all: &BTreeMap<Hash, Signed>,
    out: &BTreeMap<Hash, Status>,
    s: &Subjects,
) -> Status {
    let mut missing: Vec<_> = [pin.subject, pin.basis]
        .into_iter()
        .filter(|r| !all.contains_key(r))
        .collect();
    missing.dedup();
    if !missing.is_empty() {
        return Status::pending("pin_missing", missing);
    }
    let basis = &all[&pin.basis];
    if all[&pin.subject].envelope().payload.kind() != Kind::Genesis
        || !is_subject(basis)
        || basis.envelope().subject.unwrap_or(pin.basis) != pin.subject
    {
        return Status::invalid("pin_subject");
    }
    match out[&pin.basis].state {
        State::Invalid => return Status::invalid("pin_invalid"),
        State::Pending => return Status::pending("pin_pending", vec![]),
        State::Valid => {}
    }
    if s.selected[&pin.basis] != pin.revision {
        return Status::invalid("pin_revision");
    }
    if s.revisions[&pin.revision].body != pin.body {
        return Status::invalid("pin_body");
    }
    Status::valid()
}
fn check_pins(
    pins: &Pins,
    all: &BTreeMap<Hash, Signed>,
    out: &BTreeMap<Hash, Status>,
    s: &Subjects,
) -> Status {
    let results = [
        check_pin(&pins.source, all, out, s),
        check_pin(&pins.target, all, out, s),
    ];
    if let Some(bad) = results.iter().find(|r| r.state == State::Invalid) {
        return bad.clone();
    }
    let mut missing: Vec<_> = results.iter().flat_map(|r| r.missing.clone()).collect();
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        return Status::pending("pin_missing", missing);
    }
    results
        .into_iter()
        .find(|r| r.state == State::Pending)
        .unwrap_or_else(Status::valid)
}

fn evaluate(
    id: Hash,
    all: &BTreeMap<Hash, Signed>,
    out: &BTreeMap<Hash, Status>,
    s: &Subjects,
) -> Status {
    let e = all[&id].envelope();
    if e.subject.is_some()
        || e.subject_key.is_some()
        || e.grant.is_some()
        || e.asserted_time.is_some()
    {
        return Status::invalid("non_subject_header");
    }
    match &e.payload {
        Payload::EdgeAssert {
            relation,
            pins,
            decision,
        } => {
            if !e.parents.0.is_empty() {
                return Status::invalid("parents");
            }
            if decision.kind != Kind::EdgeAssert
                || decision.parents != e.parents
                || decision.rationale.is_empty()
                || decision.evidence.0.is_empty()
                || decision.old != Value::None
                || decision.new != Value::Pins(pins.clone())
            {
                return Status::invalid("decision_mismatch");
            }
            if !RELATIONS.contains(&relation.as_str()) {
                return Status::invalid("relation");
            }
            let status = check_pins(pins, all, out, s);
            if status.state != State::Valid {
                return status;
            }
            // A counterclaim is the disputing author's own separate subject.
            if relation == "disputes"
                && (pins.source.subject == pins.target.subject
                    || all[&pins.source.subject].envelope().author != e.author)
            {
                return Status::invalid("dispute_counterclaim");
            }
            Status::valid()
        }
        Payload::EdgeReaffirm {
            edge,
            old,
            new,
            decision,
        } => {
            if e.parents.0.is_empty() {
                return Status::invalid("parents");
            }
            let mut missing: Vec<_> = e
                .parents
                .0
                .iter()
                .chain([edge])
                .filter(|r| !all.contains_key(*r))
                .copied()
                .collect();
            missing.sort();
            missing.dedup();
            if !missing.is_empty() {
                return Status::pending("parent_missing", missing);
            }
            let base = &all[edge];
            if base.envelope().payload.kind() != Kind::EdgeAssert
                || e.parents
                    .0
                    .iter()
                    .any(|p| edge_of(*p, &all[p]) != Some(*edge))
            {
                return Status::invalid("wrong_edge");
            }
            let states: Vec<_> = e.parents.0.iter().chain([edge]).map(|p| &out[p]).collect();
            if states.iter().any(|s| s.state == State::Invalid) {
                return Status::invalid("ancestor");
            }
            // Authority is the immutable original author, not endpoint ownership.
            if e.author != base.envelope().author {
                return Status::invalid("edge_author");
            }
            if states.iter().any(|s| s.state == State::Pending) {
                return Status::pending("ancestor", vec![]);
            }
            if e.parents.0.len() > 1
                && e.parents.0.iter().any(|p| {
                    let cone = authority::cone(all, *p);
                    e.parents.0.iter().filter(|q| cone.contains_key(*q)).count() > 1
                })
            {
                return Status::invalid("comparable_parents");
            }
            let base_pins = pins_of(base);
            if new.source.subject != base_pins.source.subject
                || new.target.subject != base_pins.target.subject
            {
                return Status::invalid("endpoint_changed");
            }
            if old.0.iter().map(|o| o.parent).collect::<Vec<_>>() != e.parents.0
                || old.0.iter().any(|o| o.pins != *pins_of(&all[&o.parent]))
                || decision.kind != Kind::EdgeReaffirm
                || decision.parents != e.parents
                || decision.rationale.is_empty()
                || decision.evidence.0.is_empty()
                || decision.old != Value::ParentPins(old.clone())
                || decision.new != Value::Pins(new.clone())
            {
                return Status::invalid("decision_mismatch");
            }
            check_pins(new, all, out, s)
        }
        Payload::Attestation {
            target_kind,
            target,
            artifact_kind,
            ..
        } => {
            if !e.parents.0.is_empty() {
                return Status::invalid("parents");
            }
            if artifact_kind.is_empty() {
                return Status::invalid("artifact_kind");
            }
            match target_kind {
                TargetKind::Revision if s.revisions.contains_key(target) => Status::valid(),
                TargetKind::Revision => Status::pending("revision_missing", vec![*target]),
                TargetKind::Event => match (all.get(target), out.get(target)) {
                    (None, _) => Status::pending("target_missing", vec![*target]),
                    (Some(t), _) if t.envelope().payload.kind() == Kind::Attestation => {
                        Status::invalid("attestation_target")
                    }
                    (Some(_), Some(t)) if t.state == State::Invalid => {
                        Status::invalid("target_invalid")
                    }
                    (Some(_), Some(t)) if t.state == State::Pending => {
                        Status::pending("target_pending", vec![])
                    }
                    _ => Status::valid(),
                },
            }
        }
        _ => unreachable!("subject events are classified separately"),
    }
}

/// Edges after subjects; attestations after edges. Dependency scheduling only.
pub(super) fn classify(candidates: &BTreeMap<Hash, Signed>, out: &mut BTreeMap<Hash, Status>) {
    let subjects = Subjects::new(candidates, out);
    for media in [false, true] {
        let ids: Vec<_> = candidates
            .iter()
            .filter(|(_, e)| {
                !is_subject(e) && (e.envelope().payload.kind() == Kind::Attestation) == media
            })
            .map(|(&id, _)| id)
            .collect();
        loop {
            let mut changed = false;
            for &id in &ids {
                if out.contains_key(&id) {
                    continue;
                }
                let e = candidates[&id].envelope();
                let deps = e.parents.0.iter().chain(match &e.payload {
                    Payload::EdgeReaffirm { edge, .. } => Some(edge),
                    _ => None,
                });
                let ready = deps.into_iter().all(|d| {
                    out.contains_key(d)
                        || candidates
                            .get(d)
                            .is_none_or(|c| c.envelope().payload.kind() == Kind::Attestation)
                });
                if ready {
                    let status = evaluate(id, candidates, out, &subjects);
                    out.insert(id, status);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for id in ids {
            out.entry(id).or_insert_with(|| Status::invalid("cycle"));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeReading {
    /// The EdgeAssert event ID: immutable edge identity.
    pub edge: Hash,
    pub author: Hash,
    pub relation: String,
    pub evidence: Set<Hash>,
    /// Maximal valid events in the author-only chain; more than one conflicts.
    pub heads: BTreeSet<Hash>,
    /// Pins at each head, in head order. Old pins remain visible when not current.
    pub pins: Vec<Pins>,
    /// Every valid assert/reaffirm in the chain: addressable historical readings.
    pub history: BTreeSet<Hash>,
    /// current, stale, endpoint_contested or edge_conflict.
    pub status: String,
    pub reasons: Vec<String>,
}
/// Media is bound to the attested revision/event only; it never follows a correction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaReading {
    pub attestation: Hash,
    pub author: Hash,
    pub target_kind: TargetKind,
    pub target: Hash,
    /// Set only when the target is a revision or the event that created it.
    pub revision: Option<Hash>,
    pub body: Option<Hash>,
    pub artifact_kind: String,
    pub artifact: Hash,
}

/// Pin status against the current subject reading (reflexive ancestry).
fn endpoint(
    pin: &Pin,
    subjects: &BTreeMap<Hash, &SubjectReading>,
    s: &Subjects,
    ancestors: &BTreeMap<Hash, BTreeSet<Hash>>,
) -> Option<&'static str> {
    let reading = subjects[&pin.subject];
    match reading.state.as_str() {
        "contested" => return Some("subject_contested"),
        "no_current_body" => return Some("no_current_body"),
        _ => {}
    }
    let head = *reading.frontier.first().unwrap();
    if !ancestors[&head].contains(&pin.basis) {
        return Some("basis_not_ancestor");
    }
    if s.selected[&head] != pin.revision {
        return Some("revision_changed");
    }
    let created = ancestors[&head]
        .difference(&ancestors[&pin.basis])
        .any(|id| match s.valid[id].envelope().payload {
            Payload::Correction { .. } => true,
            Payload::Resolve { ref selection, .. } => {
                matches!(selection, Selection::MergedBody(_))
            }
            _ => false,
        });
    created.then_some("revision_created_since_basis")
}

pub(super) type RowStates = BTreeMap<Hash, (ProjectionState, String, bool)>;
pub(super) fn project(
    candidates: &BTreeMap<Hash, Signed>,
    admission: &BTreeMap<Hash, Status>,
    subject_readings: &[SubjectReading],
    ancestors: &BTreeMap<Hash, BTreeSet<Hash>>,
) -> (Vec<EdgeReading>, Vec<MediaReading>, RowStates) {
    let s = Subjects::new(candidates, admission);
    let readings: BTreeMap<_, _> = subject_readings.iter().map(|r| (r.subject, r)).collect();
    let valid = |id: &Hash| admission[id].state == State::Valid;
    let mut rows = RowStates::new();
    let mut edges = vec![];
    for (&id, event) in candidates {
        let Payload::EdgeAssert {
            relation, decision, ..
        } = &event.envelope().payload
        else {
            continue;
        };
        if !valid(&id) {
            continue;
        }
        let history: BTreeSet<_> = candidates
            .iter()
            .filter(|(c, e)| valid(c) && edge_of(**c, e) == Some(id))
            .map(|(&c, _)| c)
            .collect();
        let cones: BTreeMap<_, BTreeSet<_>> = history
            .iter()
            .map(|&c| (c, authority::cone(candidates, c).into_keys().collect()))
            .collect();
        let consumed: BTreeSet<_> = cones
            .iter()
            .flat_map(|(c, cone)| cone.iter().filter(move |p| *p != c).copied())
            .collect();
        let heads: BTreeSet<_> = history.difference(&consumed).copied().collect();
        let common = heads
            .iter()
            .map(|h| cones[h].clone())
            .reduce(|a, b| a.intersection(&b).copied().collect())
            .unwrap_or_default();
        for &c in &history {
            let state = if heads.len() == 1 && heads.contains(&c) {
                (ProjectionState::Head, String::new())
            } else if heads.len() > 1 && (heads.contains(&c) || !common.contains(&c)) {
                (ProjectionState::Branch, "edge_conflict".into())
            } else {
                (ProjectionState::Superseded, String::new())
            };
            rows.insert(c, (state.0, state.1, heads.contains(&c)));
        }
        let pins: Vec<_> = heads
            .iter()
            .map(|h| pins_of(&candidates[h]).clone())
            .collect();
        let (status, reasons) = if heads.len() > 1 {
            ("edge_conflict", vec!["edge_conflict".to_owned()])
        } else {
            let found: Vec<_> = [("source", &pins[0].source), ("target", &pins[0].target)]
                .into_iter()
                .filter_map(|(side, pin)| {
                    endpoint(pin, &readings, &s, ancestors).map(|r| (side, r))
                })
                .collect();
            let status = if found.is_empty() {
                "current"
            } else if found.iter().any(|(_, r)| *r == "subject_contested") {
                "endpoint_contested"
            } else {
                "stale"
            };
            (
                status,
                found
                    .iter()
                    .map(|(side, r)| format!("{side}:{r}"))
                    .collect(),
            )
        };
        edges.push(EdgeReading {
            edge: id,
            author: event.envelope().author,
            relation: relation.clone(),
            evidence: decision.evidence.clone(),
            heads,
            pins,
            history,
            status: status.into(),
            reasons,
        });
    }
    let mut media = vec![];
    for (&id, event) in candidates {
        let Payload::Attestation {
            target_kind,
            target,
            artifact_kind,
            artifact,
        } = &event.envelope().payload
        else {
            continue;
        };
        if !valid(&id) {
            continue;
        }
        rows.insert(id, (ProjectionState::Head, String::new(), false));
        let revision = match target_kind {
            TargetKind::Revision => Some(*target),
            TargetKind::Event => s.valid.get(target).and_then(|e| {
                let r = revision_id(e.envelope().subject.unwrap_or(*target), *target);
                s.revisions.contains_key(&r).then_some(r)
            }),
        };
        media.push(MediaReading {
            attestation: id,
            author: event.envelope().author,
            target_kind: *target_kind,
            target: *target,
            revision,
            body: revision.map(|r| s.revisions[&r].body),
            artifact_kind: artifact_kind.clone(),
            artifact: *artifact,
        });
    }
    (edges, media, rows)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Neighbor {
    pub subject: Hash,
    pub edge: Hash,
    pub relation: String,
}
/// An edge withheld from support, with every reason; not a claim of falsity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    pub edge: Hash,
    /// The excluded event: the assertion itself, or a pending/invalid reaffirmation.
    pub event: Hash,
    pub source: Hash,
    pub target: Hash,
    pub reasons: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub subject: Option<Hash>,
    pub edge: Option<Hash>,
}
/// Deliberately two-valued: conflicting readings or missing support never
/// become a contradiction. Excluded edges and disputes touching either queried
/// subject stay visible in both answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Support {
    Supported {
        path: Vec<Hash>,
        excluded: Vec<Reason>,
    },
    Unsupported {
        reasons: Vec<Reason>,
    },
}
/// Only current, trusted, non-dispute edges enter `neighbors`. Not yet the
/// governed Stage (e) filter identity, `as_of` query or verdict commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportGraph {
    pub neighbors: BTreeMap<Hash, BTreeSet<Neighbor>>,
    pub excluded: Vec<Exclusion>,
    /// Subject state, or `untrusted_origin` for a creator outside the curator set.
    pub subjects: BTreeMap<Hash, String>,
}
pub fn support_graph(p: &Projection, curators: &BTreeSet<Hash>) -> SupportGraph {
    let authors: BTreeMap<_, _> = p
        .rows
        .iter()
        .map(|r| (r.event, r.envelope.author))
        .collect();
    let subjects: BTreeMap<_, _> = p
        .subjects
        .iter()
        .map(|s| {
            let state = if curators.contains(&authors[&s.subject]) {
                s.state.clone()
            } else {
                "untrusted_origin".into()
            };
            (s.subject, state)
        })
        .collect();
    let mut graph = SupportGraph {
        neighbors: BTreeMap::new(),
        excluded: vec![],
        subjects,
    };
    for e in &p.edges {
        let ends = (e.pins[0].source.subject, e.pins[0].target.subject);
        let mut reasons = vec![];
        if e.status != "current" {
            reasons.push(e.status.clone());
            reasons.extend(e.reasons.iter().filter(|r| **r != e.status).cloned());
        }
        if e.relation == "disputes" {
            reasons.push("disputes_not_support".into());
        }
        if !curators.contains(&e.author) {
            reasons.push("untrusted_edge_author".into());
        }
        for (side, subject) in [("source", ends.0), ("target", ends.1)] {
            if !curators.contains(&authors[&subject]) {
                reasons.push(format!("{side}:untrusted_origin"));
            }
        }
        if reasons.is_empty() {
            for (a, b) in [ends, (ends.1, ends.0)] {
                graph.neighbors.entry(a).or_default().insert(Neighbor {
                    subject: b,
                    edge: e.edge,
                    relation: e.relation.clone(),
                });
            }
        } else {
            graph.excluded.push(Exclusion {
                edge: e.edge,
                event: e.edge,
                source: ends.0,
                target: ends.1,
                reasons,
            });
        }
    }
    for r in &p.rows {
        let state = match r.state {
            ProjectionState::Pending => "pending",
            ProjectionState::Invalid => "invalid",
            _ => continue,
        };
        let (edge, pins) = match &r.envelope.payload {
            Payload::EdgeAssert { pins, .. } => (r.event, pins),
            Payload::EdgeReaffirm { edge, new, .. } => (*edge, new),
            _ => continue,
        };
        graph.excluded.push(Exclusion {
            edge,
            event: r.event,
            source: pins.source.subject,
            target: pins.target.subject,
            reasons: vec![format!("{state}:{}", r.reason)],
        });
    }
    graph.excluded.sort_by_key(|x| (x.edge, x.event));
    graph
}
impl SupportGraph {
    /// Enforced neighbor read: excluded edges are absent, not merely labeled.
    pub fn neighbors(&self, subject: Hash) -> Vec<Neighbor> {
        self.neighbors
            .get(&subject)
            .map(|n| n.iter().cloned().collect())
            .unwrap_or_default()
    }
    pub fn query(&self, from: Hash, to: Hash, max_hops: usize) -> Support {
        let mut reasons: Vec<_> = [from, to]
            .into_iter()
            .filter_map(|s| {
                let code = match self.subjects.get(&s).map(String::as_str) {
                    None => "subject_unknown",
                    Some("resolved") => return None,
                    Some("contested") => "subject_contested",
                    Some("no_current_body") => "subject_no_current_body",
                    Some(other) => other,
                };
                Some(Reason {
                    code: code.into(),
                    subject: Some(s),
                    edge: None,
                })
            })
            .collect();
        if reasons.is_empty() && from == to {
            reasons.push(Reason {
                code: "same_subject".into(),
                subject: Some(from),
                edge: None,
            });
        }
        let excluded: Vec<_> = self
            .excluded
            .iter()
            .filter(|x| [from, to].iter().any(|s| *s == x.source || *s == x.target))
            .flat_map(|x| {
                x.reasons.iter().map(|r| Reason {
                    code: format!("excluded_edge:{r}"),
                    subject: None,
                    edge: Some(x.event),
                })
            })
            .collect();
        if reasons.is_empty() {
            let mut previous = BTreeMap::from([(from, None)]);
            let mut level = vec![from];
            for _ in 0..max_hops {
                if level.is_empty() {
                    break;
                }
                let mut next = vec![];
                for s in level {
                    for n in self.neighbors(s) {
                        if let std::collections::btree_map::Entry::Vacant(v) =
                            previous.entry(n.subject)
                        {
                            v.insert(Some((s, n.edge)));
                            next.push(n.subject);
                        }
                    }
                }
                if previous.contains_key(&to) {
                    let mut path = vec![];
                    let mut at = to;
                    while let Some(Some((prior, edge))) = previous.get(&at) {
                        path.push(*edge);
                        at = *prior;
                    }
                    path.reverse();
                    return Support::Supported { path, excluded };
                }
                level = next;
            }
            reasons.push(Reason {
                code: "no_current_support_path".into(),
                subject: None,
                edge: None,
            });
        }
        reasons.extend(excluded);
        Support::Unsupported { reasons }
    }
}
