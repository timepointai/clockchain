//! Authority effects over branch-valid G/C/D/R events. No frontier/body projection.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub issued_by_event: Hash,
    pub issuer: Option<Hash>,
    pub holder: Hash,
    pub subject: Hash,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// Empty means authority-eligible, not a selected body/head or filter support.
    pub reason: String,
    pub controlling_revokes: BTreeSet<Hash>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authority {
    pub grants: BTreeMap<Hash, Grant>,
    pub active: BTreeSet<Hash>,
    pub tombstones: BTreeSet<Hash>,
    pub effective_revokes: BTreeSet<Hash>,
    pub canceled: BTreeSet<Hash>,
    pub effects: BTreeMap<Hash, Effect>,
}

/// Reflexive causal cone. Callers have already checked known, valid parents.
pub(super) fn cone(all: &BTreeMap<Hash, Signed>, head: Hash) -> BTreeMap<Hash, Signed> {
    let mut found = BTreeMap::new();
    let mut todo = vec![head];
    while let Some(id) = todo.pop() {
        if found.contains_key(&id) {
            continue;
        }
        let e = &all[&id];
        todo.extend(e.envelope().parents.0.iter().copied());
        found.insert(id, e.clone());
    }
    found
}
fn signer(id: Hash, event: &Signed) -> Hash {
    event.envelope().grant.unwrap_or_else(|| root_grant(id))
}

/// Only the classifier calls this with a causally closed set of valid events.
pub(super) fn derive(valid: &BTreeMap<Hash, Signed>) -> Authority {
    let mut out = Authority::default();
    let mut lineage: BTreeMap<Hash, BTreeSet<Hash>> = BTreeMap::new();
    let mut ancestors: BTreeMap<Hash, BTreeSet<Hash>> = BTreeMap::new();
    // Dependency scheduling only. ID order never chooses an authority or body.
    while ancestors.len() < valid.len() {
        for (&id, event) in valid {
            let e = event.envelope();
            if ancestors.contains_key(&id) || e.parents.0.iter().any(|p| !ancestors.contains_key(p))
            {
                continue;
            }
            let mut past = BTreeSet::from([id]);
            for p in &e.parents.0 {
                past.extend(&ancestors[p]);
            }
            ancestors.insert(id, past);
            let grant = match &e.payload {
                Payload::Genesis { .. } => Some((
                    root_grant(id),
                    Grant {
                        issued_by_event: id,
                        issuer: None,
                        holder: e.author,
                        subject: id,
                    },
                )),
                Payload::Delegate {
                    grantee, issuer, ..
                } => Some((
                    id,
                    Grant {
                        issued_by_event: id,
                        issuer: Some(*issuer),
                        holder: *grantee,
                        subject: e.subject.unwrap(),
                    },
                )),
                _ => None,
            };
            if let Some((g, grant)) = grant {
                let mut path = grant
                    .issuer
                    .map(|i| lineage[&i].clone())
                    .unwrap_or_default();
                path.insert(g);
                lineage.insert(g, path);
                out.grants.insert(g, grant);
            }
        }
    }
    let revokes: BTreeMap<_, _> = valid
        .iter()
        .filter_map(|(&id, event)| {
            if let Payload::Revoke {
                target, cascade, ..
            } = event.envelope().payload
            {
                Some((id, (target, cascade)))
            } else {
                None
            }
        })
        .collect();
    let covers = |r: &Hash, g: &Hash| {
        let (target, cascade) = revokes[r];
        target == *g || (cascade && lineage[g].contains(&target))
    };
    let outside = |e: &Hash, r: &Hash| !ancestors[&valid[r].envelope().parents.0[0]].contains(e);
    let mut order: Vec<_> = out.grants.keys().copied().collect();
    order.sort_by_key(|g| lineage[g].len());
    let cancellations = |effective: &BTreeSet<Hash>| {
        let mut canceled: BTreeMap<Hash, BTreeSet<Hash>> = BTreeMap::new();
        for g in &order {
            let grant = &out.grants[g];
            if let Some(issuer) = grant.issuer {
                let mut controls = canceled.get(&issuer).cloned().unwrap_or_default();
                controls.extend(
                    effective
                        .iter()
                        .filter(|r| covers(r, &issuer) && outside(&grant.issued_by_event, r))
                        .copied(),
                );
                if !controls.is_empty() {
                    canceled.insert(*g, controls);
                }
            }
        }
        canceled
    };
    let relinquishments: BTreeSet<_> = revokes
        .iter()
        .filter_map(|(&id, (target, _))| {
            (signer(id, &valid[&id]) == *target && out.grants[target].issuer.is_none())
                .then_some(id)
        })
        .collect();
    out.effective_revokes = relinquishments.clone();
    let max_depth = lineage.values().map(BTreeSet::len).max().unwrap_or(0);
    for depth in 1..=max_depth {
        let canceled = cancellations(&out.effective_revokes);
        let batch: Vec<_> = revokes
            .keys()
            .filter(|r| {
                let g = signer(**r, &valid[*r]);
                lineage[&g].len() == depth
                    && !relinquishments.contains(*r)
                    && !canceled.contains_key(&g)
                    && !out
                        .effective_revokes
                        .iter()
                        .any(|q| covers(q, &g) && outside(r, q))
            })
            .copied()
            .collect();
        out.effective_revokes.extend(batch);
    }
    let canceled = cancellations(&out.effective_revokes);
    out.canceled = canceled.keys().copied().collect();
    out.tombstones = out
        .grants
        .keys()
        .filter(|g| out.effective_revokes.iter().any(|r| covers(r, g)))
        .copied()
        .collect();
    out.active = out
        .grants
        .keys()
        .filter(|g| !out.canceled.contains(*g) && !out.tombstones.contains(*g))
        .copied()
        .collect();
    for (&id, event) in valid {
        let g = signer(id, event);
        let controls: BTreeSet<_> = out
            .effective_revokes
            .iter()
            .filter(|r| covers(r, &g) && outside(&id, r))
            .copied()
            .collect();
        let effect = if relinquishments.contains(&id) {
            Effect {
                reason: "root_relinquished".into(),
                controlling_revokes: BTreeSet::from([id]),
            }
        } else if !controls.is_empty() {
            Effect {
                reason: "revoked_concurrent".into(),
                controlling_revokes: controls,
            }
        } else if let Some(controls) = canceled.get(&id) {
            Effect {
                reason: "canceled_grant".into(),
                controlling_revokes: controls.clone(),
            }
        } else if let Some(controls) = canceled.get(&g) {
            Effect {
                reason: "canceled_authority".into(),
                controlling_revokes: controls.clone(),
            }
        } else {
            Effect::default()
        };
        out.effects.insert(id, effect);
    }
    // Suppressed body dependencies never become eligible through a good signer.
    // This does not erase an otherwise effective authority control's effects.
    loop {
        let mut changed = false;
        for (&id, event) in valid {
            if !out.effects[&id].reason.is_empty() {
                continue;
            }
            let controls: BTreeSet<_> = event
                .envelope()
                .parents
                .0
                .iter()
                .filter(|p| {
                    !out.effects[*p].reason.is_empty()
                        && out.effects[*p].reason != "root_relinquished"
                })
                .flat_map(|p| out.effects[p].controlling_revokes.iter().copied())
                .collect();
            if !controls.is_empty() {
                out.effects.insert(
                    id,
                    Effect {
                        reason: "revoked_ancestor".into(),
                        controlling_revokes: controls,
                    },
                );
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    out
}

pub(super) fn in_scope(view: &Authority, signer: Hash, target: Hash) -> bool {
    if signer == target {
        return view.grants[&target].issuer.is_none();
    }
    let mut g = target;
    while let Some(issuer) = view.grants[&g].issuer {
        if issuer == signer {
            return true;
        }
        g = issuer;
    }
    false
}

/// The selected body on the supported single-parent path; never a frontier choice.
pub(super) fn body(all: &BTreeMap<Hash, Signed>, mut id: Hash) -> Hash {
    loop {
        let e = all[&id].envelope();
        match e.payload {
            Payload::Genesis { body, .. } | Payload::Correction { body, .. } => return body,
            _ => id = e.parents.0[0],
        }
    }
}
