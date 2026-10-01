//! Read-only admission contracts. No identity remapping, signing or inference.
use anyhow::{ensure, Context, Result};
use cc_authoring::{body_hash, claim_identity};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    DestinationSubjectChanged,
    SourceSubjectChanged,
    EdgeTargetMismatch,
    EdgeBindingMissing,
    SubjectIdentityReused,
}
impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DestinationSubjectChanged => "destination_subject_changed",
            Self::SourceSubjectChanged => "source_subject_changed",
            Self::EdgeTargetMismatch => "edge_target_mismatch",
            Self::EdgeBindingMissing => "edge_binding_missing",
            Self::SubjectIdentityReused => "subject_identity_reused",
        })
    }
}
impl std::error::Error for AdmissionError {}

pub fn entry_binding(entry: &Value) -> Result<Value> {
    let (id, hash) = claim_identity(
        entry["title"].as_str().context("title missing")?,
        entry["year"].as_i64().context("year missing")?,
    );
    let kind = &entry["prov_asserted"]["subject_kind"];
    ensure!(
        kind.is_null()
            || kind
                .as_str()
                .is_some_and(|s| !s.trim().is_empty() && s.len() <= 128),
        "invalid declared subject_kind"
    );
    Ok(
        json!({"entity_id":id.to_string(), "claim_identity":hex::encode(hash),
        "body_hash":hex::encode(body_hash("claim_v4", &entry.to_string())),
        "subject_kind":kind}),
    )
}

pub(crate) fn check_endpoint(
    endpoint: &Value,
    entry: &Value,
    destination: bool,
    allow_unbound: bool,
) -> Result<()> {
    let Some(binding) = endpoint.get("binding") else {
        if allow_unbound {
            return Ok(());
        }
        return Err(AdmissionError::EdgeBindingMissing.into());
    };
    let expected = entry_binding(entry)?;
    if binding["entity_id"] != expected["entity_id"]
        || binding["claim_identity"] != expected["claim_identity"]
    {
        return Err(AdmissionError::EdgeTargetMismatch.into());
    }
    if binding["body_hash"] != expected["body_hash"]
        || binding["subject_kind"] != expected["subject_kind"]
    {
        return Err(if destination {
            AdmissionError::DestinationSubjectChanged
        } else {
            AdmissionError::SourceSubjectChanged
        }
        .into());
    }
    ensure!(binding == &expected, "unexpected edge binding fields");
    Ok(())
}

/// Existing subjects in a frozen proposal may not be repurposed in place, even
/// if a caller recalculates the edge bindings. Open a separate reviewed proposal.
pub fn validate_frozen_subjects(before: &Value, after: &Value) -> Result<()> {
    for (i, old) in before["entries"]
        .as_array()
        .context("base entries missing")?
        .iter()
        .enumerate()
    {
        let new = &after["entries"][i];
        if !new.is_object() {
            return Err(AdmissionError::EdgeTargetMismatch.into());
        }
        if entry_binding(old)? != entry_binding(new)? {
            let destination = before["edges"]
                .as_array()
                .context("base edges missing")?
                .iter()
                .any(|edge| {
                    edge["to"]["title"] == old["title"] && edge["to"]["year"] == old["year"]
                });
            return Err(if destination {
                AdmissionError::DestinationSubjectChanged
            } else {
                AdmissionError::SourceSubjectChanged
            }
            .into());
        }
    }
    Ok(())
}

/// Typed terminal outcomes are receipts, never candidates to repair or retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Proposal,
    MediaPlan,
    NeedsEvidence,
    Abstained,
    ConflictingEvidence,
    Failed,
}
impl AttemptStatus {
    pub fn from_receipt(receipt: &Value) -> Result<Self> {
        ensure!(
            receipt["schema"] == "cc.generation-result.v1" && receipt["published"] == false,
            "invalid_attempt_receipt"
        );
        let status = Self::parse(&receipt["status"])?;
        if matches!(
            status,
            Self::NeedsEvidence | Self::Abstained | Self::ConflictingEvidence
        ) {
            ensure!(
                receipt["reason"]
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty()),
                "terminal_reason_missing"
            );
            ensure!(
                !receipt.get("entries").is_some_and(|n| n != 0)
                    && !receipt.get("edges").is_some_and(|n| n != 0),
                "terminal_attempt_contains_records"
            );
        }
        Ok(status)
    }
    pub fn parse(v: &Value) -> Result<Self> {
        Ok(match v.as_str() {
            Some("proposal") => Self::Proposal,
            Some("media_plan") => Self::MediaPlan,
            Some("needs_evidence") => Self::NeedsEvidence,
            Some("abstained") => Self::Abstained,
            Some("conflicting_evidence") => Self::ConflictingEvidence,
            Some("failed") => Self::Failed,
            _ => anyhow::bail!("invalid_attempt_status"),
        })
    }
    pub fn is_nonproposal(self) -> bool {
        matches!(
            self,
            Self::NeedsEvidence | Self::Abstained | Self::ConflictingEvidence | Self::Failed
        )
    }
}

pub fn dry_run(candidate: &Value, brief: &Value, attempt: &Value) -> Result<Value> {
    let status = AttemptStatus::from_receipt(attempt)?;
    let mut blockers = Vec::new();
    if status != AttemptStatus::Proposal {
        blockers.push(json!({"code":attempt["status"],"reason":attempt["reason"]}));
    }
    let hash = hex::encode(crate::digest(crate::canonical(candidate).as_bytes()));
    // A proposal receipt must bind the exact file. The CLI checks file bytes;
    // this canonical digest is the publisher's admit digest, not a replacement.
    if let Err(error) = crate::validate_candidate(candidate)
        .and_then(|_| crate::require_images(brief, candidate))
        .and_then(|_| crate::verify_images(candidate))
    {
        blockers.push(json!({"code":"admission_rejected","detail":error.to_string()}));
    }
    let entities = candidate["entries"]
        .as_array()
        .context("entries missing")?
        .iter()
        .map(entry_binding)
        .collect::<Result<Vec<_>>>()?;
    let edges = candidate["edges"].as_array().context("edges missing")?.iter().map(|edge|
        json!({"proposal_edge_sha256":hex::encode(crate::digest(crate::canonical(edge).as_bytes())),
            "from":edge["from"],"to":edge["to"],"relation":edge["relation"],
            "evidence_class":edge["evidence_class"],"rationale":edge["rationale"]})).collect::<Vec<_>>();
    let images = candidate["images"].as_array().context("images missing")?;
    Ok(
        json!({"schema":"cc.admit-set.v1", "status":if blockers.is_empty(){"ready_for_owner_review"}else{"blocked"},
        "candidate_digest":hash,"entities":entities,"edges":edges,
        "media":if images.is_empty(){json!({"kind":"none","records":[]})}else{json!({"kind":"prepared_images","records":images})},
        "blockers":blockers,"publication_authorized":false,"writes_performed":false,
        "edge_event_ids":"unassigned until owner signing; proposal hashes above are not event IDs"}),
    )
}
