//! Set-derived subject readings. IDs sort output, never pick a winning branch.
use super::*;
use cc_core::v1::{revision_id, AssertedTime, Envelope};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionState {
    Head,
    Superseded,
    Branch,
    Pending,
    Invalid,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub id: Hash,
    pub subject: Hash,
    pub creating_event: Hash,
    pub body: Hash,
    pub asserted_time: Option<AssertedTime>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventReading {
    pub event: Hash,
    pub envelope: Envelope,
    pub state: ProjectionState,
    pub reason: String,
    pub missing: Vec<Hash>,
    pub frontier: bool,
    pub revision: Option<Hash>,
    pub controlling_revokes: BTreeSet<Hash>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectReading {
    pub subject: Hash,
    pub frontier: BTreeSet<Hash>,
    /// resolved, contested, or no_current_body; never a support verdict.
    pub state: String,
    /// No surviving authority; distinct from having no current body.
    pub frozen: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    pub rows: Vec<EventReading>,
    pub revisions: Vec<Revision>,
    pub subjects: Vec<SubjectReading>,
    pub authority: Authority,
}
/// Immutable revision records, including retained suppressed readings.
pub(super) fn revisions(valid: &BTreeMap<Hash, Signed>) -> BTreeMap<Hash, Revision> {
    valid
        .iter()
        .filter_map(|(&id, e)| {
            let body = match e.envelope().payload {
                Payload::Genesis { body, .. }
                | Payload::Correction { body, .. }
                | Payload::Resolve {
                    selection: Selection::MergedBody(body),
                    ..
                } => body,
                _ => return None,
            };
            let subject = e.envelope().subject.unwrap_or(id);
            let r = Revision {
                id: revision_id(subject, id),
                subject,
                creating_event: id,
                body,
                asserted_time: e.envelope().asserted_time.clone(),
            };
            Some((r.id, r))
        })
        .collect()
}
fn selections(valid: &BTreeMap<Hash, Signed>) -> BTreeMap<Hash, Hash> {
    let mut out = BTreeMap::new();
    while out.len() < valid.len() {
        for (&id, e) in valid {
            if out.contains_key(&id) || e.envelope().parents.0.iter().any(|p| !out.contains_key(p))
            {
                continue;
            }
            let selected = match e.envelope().payload {
                Payload::Genesis { .. }
                | Payload::Correction { .. }
                | Payload::Resolve {
                    selection: Selection::MergedBody(_),
                    ..
                } => revision_id(e.envelope().subject.unwrap_or(id), id),
                Payload::Resolve {
                    selection: Selection::Revision(r),
                    ..
                } => r,
                _ => out[&e.envelope().parents.0[0]],
            };
            out.insert(id, selected);
        }
    }
    out
}
pub fn project(candidates: &BTreeMap<Hash, Signed>) -> Projection {
    let Analysis {
        admission,
        authority,
    } = analyze(candidates);
    let valid: BTreeMap<_, _> = candidates
        .iter()
        .filter(|(id, _)| admission[*id].state == State::Valid)
        .map(|(&id, e)| (id, e.clone()))
        .collect();
    let selected = selections(&valid);
    let ancestors: BTreeMap<_, BTreeSet<_>> = valid
        .keys()
        .map(|&id| (id, authority::cone(&valid, id).into_keys().collect()))
        .collect();
    let mut subjects = vec![];
    let mut states = BTreeMap::new();
    for (&subject, e) in &valid {
        if e.envelope().payload.kind() != Kind::Genesis {
            continue;
        }
        let ids: BTreeSet<_> = valid
            .iter()
            .filter(|(id, e)| e.envelope().subject.unwrap_or(**id) == subject)
            .map(|(&id, _)| id)
            .collect();
        let eligible: BTreeSet<_> = ids
            .iter()
            .filter(|id| authority.effects[*id].reason.is_empty())
            .copied()
            .collect();
        let consumed: BTreeSet<_> = eligible
            .iter()
            .chain(authority.effective_revokes.intersection(&ids))
            .flat_map(|id| ancestors[id].iter().filter(move |p| *p != id).copied())
            .collect();
        let frontier: BTreeSet<_> = eligible.difference(&consumed).copied().collect();
        let common = frontier
            .iter()
            .map(|id| ancestors[id].clone())
            .reduce(|a, b| a.intersection(&b).copied().collect())
            .unwrap_or_default();
        for id in ids {
            let reason = &authority.effects[&id].reason;
            let (state, reason) = if reason == "root_relinquished" {
                (ProjectionState::Superseded, reason.clone())
            } else if !reason.is_empty() {
                (ProjectionState::Branch, reason.clone())
            } else if frontier.len() == 1 && frontier.contains(&id) {
                (ProjectionState::Head, String::new())
            } else if frontier.len() > 1 && (frontier.contains(&id) || !common.contains(&id)) {
                (ProjectionState::Branch, "contested".into())
            } else {
                (ProjectionState::Superseded, String::new())
            };
            states.insert(id, (state, reason, frontier.contains(&id)));
        }
        subjects.push(SubjectReading {
            subject,
            state: match frontier.len() {
                0 => "no_current_body",
                1 => "resolved",
                _ => "contested",
            }
            .into(),
            frontier,
            frozen: !authority
                .active
                .iter()
                .any(|g| authority.grants[g].subject == subject),
        });
    }
    let rows = candidates
        .iter()
        .map(|(&id, e)| {
            let s = &admission[&id];
            let (state, reason, frontier) = states.remove(&id).unwrap_or_else(|| {
                (
                    if s.state == State::Invalid {
                        ProjectionState::Invalid
                    } else {
                        ProjectionState::Pending
                    },
                    s.reason.clone(),
                    false,
                )
            });
            EventReading {
                event: id,
                envelope: e.envelope().clone(),
                state,
                reason,
                frontier,
                missing: s.missing.clone(),
                revision: selected.get(&id).copied(),
                controlling_revokes: authority
                    .effects
                    .get(&id)
                    .map(|e| e.controlling_revokes.clone())
                    .unwrap_or_default(),
            }
        })
        .collect();
    Projection {
        rows,
        subjects,
        revisions: revisions(&valid).into_values().collect(),
        authority,
    }
}
