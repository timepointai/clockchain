//! Controlled publication: exact proposals, human approvals, one ledger transaction.
use anyhow::{bail, ensure, Context, Result};
use cc_authoring::{admission, body_hash, claim_identity, now_tick, year_tick};
use cc_core::{
    EdgeBody, EdgeRelation, EntityBirth, EventBody, EventContent, EvidenceClass, ExistenceWindow,
    MomentBody, SecretKey, VocabularyEntry, WindowEnd, WindowStart,
};
use cc_ledger::Signed;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, HashSet};

pub fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
pub fn canonical(v: &Value) -> String {
    v.to_string()
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .with_context(|| format!("missing {key}"))
}
fn source_profile(v: &Value, required: &[&str]) -> Result<()> {
    let rows = v.as_array().context("source evidence must be array")?;
    ensure!(!rows.is_empty(), "source evidence empty");
    let mut supported = HashSet::new();
    for row in rows {
        let url = string(row, "url")?;
        ensure!(
            url.starts_with("https://") && url.len() > 8 && !url[8..].contains('@'),
            "source URL must be HTTPS without credentials"
        );
        string(row, "retrieved_at")?;
        let excerpt = string(row, "excerpt")?;
        string(row, "license")?;
        string(row, "locator")?;
        string(row, "publisher")?;
        let retained =
            std::fs::read(string(row, "capture_path")?).context("read retained source capture")?;
        let expected = hex::decode(string(row, "content_sha256")?)?;
        ensure!(
            expected.len() == 32 && digest(&retained) == expected,
            "retained source hash mismatch"
        );
        ensure!(
            std::str::from_utf8(&retained)?.contains(excerpt),
            "evidence excerpt is not present in retained source"
        );
        for item in row["supports"]
            .as_array()
            .context("supports array missing")?
        {
            supported.insert(item.as_str().context("supports must contain strings")?);
        }
    }
    for field in required {
        ensure!(
            supported.contains(field),
            "source evidence does not support {field}"
        );
    }
    Ok(())
}
fn endpoint(v: &Value) -> Result<(i64, i64)> {
    let year = v["year"].as_i64().context("edge endpoint year missing")?;
    Ok((claim_identity(string(v, "title")?, year).0, year))
}
fn relation(v: &Value) -> Result<EdgeRelation> {
    Ok(match string(v, "relation")? {
        "influence" => EdgeRelation::Influence,
        "causation" => EdgeRelation::Causation,
        "participation" => EdgeRelation::Participation,
        "co_occurrence" => EdgeRelation::CoOccurrence,
        _ => bail!("unsupported edge relation"),
    })
}
fn evidence_class(v: &Value) -> Result<EvidenceClass> {
    Ok(match string(v, "evidence_class")? {
        "PrimaryDocument" => EvidenceClass::PrimaryDocument,
        "SecondarySource" => EvidenceClass::SecondarySource,
        "Inference" => EvidenceClass::Inference,
        "Assertion" => EvidenceClass::Assertion,
        _ => bail!("unknown evidence class"),
    })
}
fn source_support(e: &Value) -> Result<()> {
    let support = &e["prov_asserted"]["source_support"];
    ensure!(
        support["schema"] == "cc.source-support.v1",
        "source support schema missing"
    );
    ensure!(
        ["observed", "attributed_announcement"].contains(&string(support, "support_kind")?),
        "unsupported source support kind"
    );
    string(support, "claim")?;
    string(support, "rationale")?;
    let sources = e["prov_measured"]["source_evidence"]
        .as_array()
        .context("sources missing")?;
    let urls = support["source_urls"]
        .as_array()
        .context("source support URLs missing")?;
    ensure!(!urls.is_empty(), "source support URLs empty");
    for url in urls {
        ensure!(
            url.is_string() && sources.iter().any(|s| s["url"] == *url),
            "support references uncaptured source"
        );
    }
    Ok(())
}
pub fn validate_candidate(v: &Value) -> Result<()> {
    let obj = v.as_object().context("candidate must be object")?;
    ensure!(
        obj.keys()
            .all(|k| ["entries", "edges", "images"].contains(&k.as_str())),
        "unknown candidate field"
    );
    let entries = v["entries"].as_array().context("entries array missing")?;
    ensure!(
        !entries.is_empty() && entries.len() <= 5,
        "candidate must have one to five entries"
    );
    let rejections = admission::admit_batch(entries);
    ensure!(rejections.is_empty(), "admission refused: {rejections:?}");
    let mut ids = HashSet::new();
    for e in entries {
        ensure!(
            e["prov_measured"]["source_evidence_schema"] == "cc.source-evidence.v1",
            "source schema missing"
        );
        source_profile(
            &e["prov_measured"]["source_evidence"],
            &["title", "year", "summary"],
        )?;
        source_support(e)?;
        ids.insert(claim_identity(string(e, "title")?, e["year"].as_i64().unwrap()).0);
    }
    for e in v["edges"].as_array().context("edges array missing")? {
        let (src, sy) = endpoint(&e["from"])?;
        let (dst, dy) = endpoint(&e["to"])?;
        string(e, "rationale")?;
        evidence_class(e)?;
        if matches!(
            relation(e)?,
            EdgeRelation::Causation | EdgeRelation::Influence
        ) {
            ensure!(sy <= dy, "cause follows effect");
        }
        ensure!(src != dst, "self edge refused");
        ensure!(
            ids.contains(&src) && ids.contains(&dst),
            "edge endpoints must exist in this candidate"
        );
        relation(e)?;
        source_profile(&e["evidence"], &["relation"])?;
    }
    for im in v["images"].as_array().context("images array missing")? {
        ensure!(
            hex::decode(string(im, "sha256")?)?.len() == 32,
            "image hash width"
        );
        string(im, "path")?;
        ensure!(im["manifest"].is_object(), "image manifest missing");
        let index = im["entry_index"]
            .as_u64()
            .context("image entry_index missing")? as usize;
        ensure!(index < entries.len(), "image references missing entry");
        ensure!(
            im["manifest"]["image_sha256"] == im["sha256"],
            "image manifest digest mismatch"
        );
    }
    Ok(())
}
fn verify_images(v: &Value) -> Result<()> {
    for im in v["images"].as_array().context("images missing")? {
        let bytes = std::fs::read(string(im, "path")?).context("read approved image bytes")?;
        ensure!(
            digest(&bytes) == hex::decode(string(im, "sha256")?)?,
            "image changed since approval"
        );
    }
    Ok(())
}
pub async fn stage_brief(pool: &PgPool, id: &str, v: &Value) -> Result<Value> {
    ensure!(
        v.is_object() && !v.as_object().unwrap().is_empty(),
        "brief must be nonempty object"
    );
    let payload = canonical(v);
    let hash = digest(payload.as_bytes());
    sqlx::query(
        "INSERT INTO generation_briefs(id,digest,payload) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(&hash)
    .bind(&payload)
    .execute(pool)
    .await?;
    let old: Vec<u8> = sqlx::query_scalar("SELECT digest FROM generation_briefs WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    ensure!(old == hash, "brief id already binds different content");
    Ok(json!({"id":id,"digest":hex::encode(hash)}))
}
pub async fn approved(pool: &PgPool, kind: &str, id: &str, hash: &[u8]) -> Result<()> {
    let yes:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM generation_approvals WHERE kind=$1 AND target_id=$2 AND digest=$3)")
      .bind(kind).bind(id).bind(hash).fetch_one(pool).await?;
    ensure!(yes, "{kind} lacks exact digest-bound human approval");
    Ok(())
}
pub async fn stage_candidate(pool: &PgPool, id: &str, brief: &str, v: &Value) -> Result<Value> {
    validate_candidate(v)?;
    verify_images(v)?;
    let brief_payload: String =
        sqlx::query_scalar("SELECT payload FROM generation_briefs WHERE id=$1")
            .bind(brief)
            .fetch_one(pool)
            .await?;
    let brief_value: Value = serde_json::from_str(&brief_payload)?;
    let maximum = brief_value["max_entries"]
        .as_u64()
        .context("brief max_entries required")?;
    ensure!(
        (1..=5).contains(&maximum) && v["entries"].as_array().unwrap().len() <= maximum as usize,
        "brief entry limit exceeded"
    );
    let bh: Vec<u8> = sqlx::query_scalar("SELECT digest FROM generation_briefs WHERE id=$1")
        .bind(brief)
        .fetch_one(pool)
        .await?;
    approved(pool, "brief", brief, &bh).await?;
    let payload = canonical(v);
    let hash = digest(payload.as_bytes());
    sqlx::query("INSERT INTO generation_candidates(id,brief_id,digest,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(id).bind(brief).bind(&hash).bind(&payload).execute(pool).await?;
    let row = sqlx::query("SELECT digest,brief_id FROM generation_candidates WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    ensure!(
        row.get::<Vec<u8>, _>("digest") == hash && row.get::<String, _>("brief_id") == brief,
        "candidate id already binds different content or brief"
    );
    Ok(json!({"id":id,"brief":brief,"digest":hex::encode(hash)}))
}
async fn heads(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, v: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for e in v["entries"].as_array().context("entries missing")? {
        let subject = claim_identity(
            string(e, "title")?,
            e["year"].as_i64().context("year missing")?,
        )
        .0;
        let hashes: Vec<String> = sqlx::query_scalar(
            "SELECT encode(body_hash,'hex') FROM moments WHERE subject=$1 ORDER BY body_hash",
        )
        .bind(subject)
        .fetch_all(&mut **tx)
        .await?;
        result.insert(subject.to_string(), json!(hashes));
    }
    Ok(Value::Object(result))
}
pub async fn approve(
    pool: &PgPool,
    kind: &str,
    id: &str,
    hash: &[u8],
    reviewer: &str,
) -> Result<Value> {
    ensure!(!reviewer.trim().is_empty(), "reviewer required");
    let table = match kind {
        "brief" => "generation_briefs",
        "candidate" => "generation_candidates",
        _ => bail!("invalid approval kind"),
    };
    let actual: Vec<u8> = sqlx::query_scalar(&format!("SELECT digest FROM {table} WHERE id=$1"))
        .bind(id)
        .fetch_one(pool)
        .await?;
    ensure!(
        actual == hash,
        "approval digest differs from staged proposal"
    );
    let mut tx = pool.begin().await?;
    let expected = if kind == "candidate" {
        let payload: String =
            sqlx::query_scalar("SELECT payload FROM generation_candidates WHERE id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let candidate: Value = serde_json::from_str(&payload)?;
        validate_candidate(&candidate)?;
        verify_images(&candidate)?;
        Some(heads(&mut tx, &candidate).await?)
    } else {
        None
    };
    sqlx::query("INSERT INTO generation_approvals(kind,target_id,digest,reviewer,expected_heads) VALUES($1,$2,$3,$4,$5) ON CONFLICT(kind,target_id,digest) DO UPDATE SET expected_heads=EXCLUDED.expected_heads,reviewer=EXCLUDED.reviewer,approved_at=now()")
      .bind(kind).bind(id).bind(hash).bind(reviewer).bind(expected).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(json!({"id":id,"kind":kind,"digest":hex::encode(hash),"approved":true}))
}
pub async fn receipt(pool: &PgPool, id: &str) -> Result<Option<Value>> {
    Ok(
        sqlx::query_scalar("SELECT receipt FROM publication_receipts WHERE candidate_id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}
pub async fn publish(pool: &PgPool, id: &str, hash: &[u8], sk: &SecretKey) -> Result<Value> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT digest,payload,brief_id FROM generation_candidates WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        row.get::<Vec<u8>, _>("digest") == hash,
        "publication digest mismatch"
    );
    let payload: String = row.get("payload");
    ensure!(
        digest(payload.as_bytes()) == hash,
        "stored candidate corruption"
    );
    let found: Option<Value> =
        sqlx::query_scalar("SELECT receipt FROM publication_receipts WHERE candidate_id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(r) = found {
        return Ok(r);
    }
    let brief: String = row.get("brief_id");
    let approvals:i64=sqlx::query_scalar("SELECT count(*) FROM generation_approvals a WHERE (a.kind='candidate' AND a.target_id=$1 AND a.digest=$2) OR (a.kind='brief' AND a.target_id=$3 AND a.digest=(SELECT digest FROM generation_briefs WHERE id=$3))")
      .bind(id).bind(hash).bind(&brief).fetch_one(&mut *tx).await?;
    ensure!(
        approvals == 2,
        "publication requires brief and exact proposal approvals"
    );
    let paused: bool =
        sqlx::query_scalar("SELECT paused FROM publication_control WHERE singleton FOR SHARE")
            .fetch_one(&mut *tx)
            .await?;
    ensure!(!paused, "publication paused by operator");
    let v: Value = serde_json::from_str(&payload)?;
    validate_candidate(&v)?;
    verify_images(&v)?;
    // Stabilize projections through validation and commit, including insert races.
    sqlx::query("LOCK TABLE moments IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let expected:Option<Value>=sqlx::query_scalar("SELECT expected_heads FROM generation_approvals WHERE kind='candidate' AND target_id=$1 AND digest=$2").bind(id).bind(hash).fetch_one(&mut *tx).await?;
    ensure!(
        expected == Some(heads(&mut tx, &v).await?),
        "current heads changed; fresh human approval required"
    );
    let rt = now_tick();
    let author = sk.author();
    let mut events = Vec::new();
    let mut moments = Vec::new();
    let mut first = BTreeMap::new();
    for e in v["entries"].as_array().unwrap() {
        let title = string(e, "title")?;
        let year = e["year"].as_i64().unwrap();
        let (subject, key) = claim_identity(title, year);
        let at = year_tick(year);
        let birth = EventContent {
            event_time: at,
            record_time: rt,
            author,
            supersedes: None,
            body: EventBody::EntityCreate(EntityBirth {
                entity_id: subject,
                resolution_key: format!("claim:{}", hex::encode(&key[..16])),
                canonical_name: title.to_owned(),
                window: ExistenceWindow {
                    start: WindowStart::Known(at),
                    end: WindowEnd::UnknownClosure,
                },
            }),
        };
        let s = Signed::sign(sk, birth);
        cc_ledger::commit_in_tx(&mut tx, &s, None).await?;
        events.push(s.id().to_hex());
        let body = e.to_string();
        let bh = body_hash("claim_v4", &body);
        let s = Signed::sign(
            sk,
            EventContent {
                event_time: at,
                record_time: rt,
                author,
                supersedes: None,
                body: EventBody::Moment(MomentBody {
                    subject,
                    body_hash: bh,
                }),
            },
        );
        cc_ledger::commit_in_tx(&mut tx, &s, None).await?;
        events.push(s.id().to_hex());
        sqlx::query(
            "INSERT INTO claim_bodies(body_hash,body) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(bh.to_vec())
        .bind(&body)
        .execute(&mut *tx)
        .await?;
        let existing: String =
            sqlx::query_scalar("SELECT body FROM claim_bodies WHERE body_hash=$1")
                .bind(bh.to_vec())
                .fetch_one(&mut *tx)
                .await?;
        ensure!(existing == body, "claim body conflict");
        moments.push(json!({"entity_id":subject.to_string(),"event_id":s.id().to_hex(),"body_hash":hex::encode(bh)}));
        let label = string(e, "claim_type")?.to_owned();
        first
            .entry(label)
            .and_modify(|y: &mut i64| *y = (*y).min(year))
            .or_insert(year);
    }
    for (label, year) in first {
        let s = Signed::sign(
            sk,
            EventContent {
                event_time: year_tick(year),
                record_time: rt,
                author,
                supersedes: None,
                body: EventBody::VocabularyDeclare(VocabularyEntry {
                    claim_type: cc_filter::version::claim_code(&label),
                    label,
                    band: ExistenceWindow {
                        start: WindowStart::Known(year_tick(year)),
                        end: WindowEnd::UnknownClosure,
                    },
                }),
            },
        );
        cc_ledger::commit_in_tx(&mut tx, &s, None).await?;
        events.push(s.id().to_hex());
    }
    for e in v["edges"].as_array().unwrap() {
        let (src, sy) = endpoint(&e["from"])?;
        let (dst, dy) = endpoint(&e["to"])?;
        let s = Signed::sign(
            sk,
            EventContent {
                event_time: year_tick(sy.max(dy)),
                record_time: rt,
                author,
                supersedes: None,
                body: EventBody::Edge(EdgeBody {
                    src,
                    dst,
                    relation: relation(e)?,
                    evidence_class: evidence_class(e)?,
                }),
            },
        );
        cc_ledger::commit_in_tx(&mut tx, &s, None).await?;
        events.push(s.id().to_hex());
        let evidence = canonical(
            &json!({"schema":"cc.edge-evidence.v1","sources":e["evidence"],"rationale":e["rationale"],"evidence_class":e["evidence_class"]}),
        );
        let eh = digest(evidence.as_bytes());
        let mut commitment = b"cc.edge-evidence.v1\0".to_vec();
        commitment.extend_from_slice(s.id().as_bytes());
        commitment.extend_from_slice(&eh);
        let sig = sk.sign_message(&commitment);
        sqlx::query("INSERT INTO edge_evidence(event_id,candidate_id,evidence,evidence_sha256,author_key,signature,admitted_coord) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind(s.id().as_bytes().to_vec()).bind(id).bind(&evidence).bind(&eh).bind(author.to_bytes().to_vec()).bind(sig.to_bytes().to_vec()).bind(rt.to_canon_bytes().to_vec()).execute(&mut *tx).await?;
        let old: String =
            sqlx::query_scalar("SELECT evidence FROM edge_evidence WHERE event_id=$1")
                .bind(s.id().as_bytes().to_vec())
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            old == evidence,
            "edge already has different evidence; explicit revision required"
        );
    }
    let receipt = json!({"candidate_id":id,"digest":hex::encode(hash),"brief_id":brief,"events":events,"moments":moments,"images":v["images"]});
    sqlx::query("INSERT INTO publication_receipts(candidate_id,digest,receipt) VALUES($1,$2,$3)")
        .bind(id)
        .bind(hash)
        .bind(&receipt)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(receipt)
}
