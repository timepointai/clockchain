//! Conservative admission for new HTTP events, separate from historical replay.
//!
//! A raw moment supplies an opaque body commitment, not prose or a proposed
//! subject-kind change. The node cannot establish that a different commitment
//! means the same subject. Require a new entity instead of carrying its edges.
//! Existing events still union; the ledger's canonical encoding/fold is unchanged.
use cc_core::EventBody;
use cc_ledger::{Appended, Signed};
use sqlx::{PgPool, Postgres, Transaction};

use crate::error::{ApiError, SubjectConflict};

fn unavailable(error: impl std::fmt::Display) -> ApiError {
    ApiError::Unavailable(format!(
        "subject admission could not consult the store: {error}"
    ))
}

pub(crate) async fn commit(pool: &PgPool, signed: &Signed) -> Result<Appended, ApiError> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    // Match the publisher's moments-first ordering. These locks also conflict
    // with ordinary projection INSERT/UPDATE locks, not just other HTTP calls.
    // Hold them through validation AND append so a concurrent edge/body cannot
    // be checked against a different graph from the one we commit into.
    sqlx::query("LOCK TABLE moments, edges, entities IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE event_id=$1)")
        .bind(signed.id().as_bytes().to_vec())
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
    if !exists {
        check(&mut tx, signed).await?;
    }
    let appended = cc_ledger::commit_in_tx(&mut tx, signed, None)
        .await
        .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(appended)
}

async fn check(tx: &mut Transaction<'_, Postgres>, signed: &Signed) -> Result<(), ApiError> {
    match &signed.content().body {
        EventBody::EntityCreate(birth) => {
            let prior: Option<(String, String)> = sqlx::query_as(
                "SELECT resolution_key, canonical_name FROM entities WHERE entity_id=$1",
            )
            .bind(birth.entity_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
            if let Some((key, name)) = prior {
                if key != birth.resolution_key || name != birth.canonical_name {
                    return Err(SubjectConflict::IdentityReused.into());
                }
            } else {
                // Do not attach a new identity to legacy unresolved claims/edges.
                let used: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM moments WHERE subject=$1) OR EXISTS(SELECT 1 FROM edges WHERE src_entity=$1 OR dst_entity=$1)")
                    .bind(birth.entity_id).fetch_one(&mut **tx).await.map_err(unavailable)?;
                if used {
                    return Err(SubjectConflict::BindingUnavailable.into());
                }
            }
        }
        EventBody::Moment(moment) => {
            let known: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM entities WHERE entity_id=$1)")
                    .bind(moment.subject)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(unavailable)?;
            if !known {
                return Err(SubjectConflict::BindingUnavailable.into());
            }
            let (bodies, changed): (i64, bool) = sqlx::query_as(
                "SELECT count(*), COALESCE(bool_or(body_hash<>$2), false) FROM moments WHERE subject=$1",
            )
            .bind(moment.subject)
            .bind(moment.body_hash.to_vec())
            .fetch_one(&mut **tx)
            .await
            .map_err(unavailable)?;
            if changed {
                return Err(changed_subject(tx, moment.subject).await?.into());
            }
            if bodies == 0 {
                let incident: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM edges WHERE src_entity=$1 OR dst_entity=$1)",
                )
                .bind(moment.subject)
                .fetch_one(&mut **tx)
                .await
                .map_err(unavailable)?;
                if incident {
                    return Err(SubjectConflict::BindingUnavailable.into());
                }
            }
            if let Some(parent) = signed.content().supersedes {
                // Only a known current head is reviewable here. Historical
                // out-of-order gossip belongs to replay, not fresh admission.
                let prior: Option<(i64, Vec<u8>)> =
                    sqlx::query_as("SELECT subject, body_hash FROM moments WHERE head_event_id=$1")
                        .bind(parent.as_bytes().to_vec())
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(unavailable)?;
                match prior {
                    Some((subject, hash))
                        if subject == moment.subject && hash == moment.body_hash => {}
                    Some((subject, _)) => return Err(changed_subject(tx, subject).await?.into()),
                    None => return Err(SubjectConflict::BindingUnavailable.into()),
                }
            }
            // A legacy held descendant could become the projected head when
            // this event arrives. Never let it silently substitute another body.
            let waiting: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE supersedes=$1)")
                    .bind(signed.id().as_bytes().to_vec())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(unavailable)?;
            if waiting {
                return Err(SubjectConflict::BindingUnavailable.into());
            }
        }
        EventBody::Edge(edge) => {
            for subject in [edge.src, edge.dst] {
                let (known, bodies): (bool, i64) = sqlx::query_as(
                    "SELECT EXISTS(SELECT 1 FROM entities WHERE entity_id=$1), (SELECT count(DISTINCT body_hash) FROM moments WHERE subject=$1)")
                    .bind(subject).fetch_one(&mut **tx).await.map_err(unavailable)?;
                if !known || bodies != 1 {
                    return Err(SubjectConflict::EdgeTargetMismatch.into());
                }
            }
        }
        EventBody::Attestation(_) | EventBody::VocabularyDeclare(_) => (),
    }
    Ok(())
}

async fn changed_subject(
    tx: &mut Transaction<'_, Postgres>,
    subject: i64,
) -> Result<SubjectConflict, ApiError> {
    let (destination, source): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM edges WHERE dst_entity=$1), EXISTS(SELECT 1 FROM edges WHERE src_entity=$1)")
        .bind(subject).fetch_one(&mut **tx).await.map_err(unavailable)?;
    Ok(if destination {
        SubjectConflict::DestinationChanged
    } else if source {
        SubjectConflict::SourceChanged
    } else {
        SubjectConflict::IdentityReused
    })
}
