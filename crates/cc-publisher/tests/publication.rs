use cc_publisher::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

fn source_capture(raw: &[u8]) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // Parallel tests must never truncate a capture another test is validating.
    let path = std::env::temp_dir().join(format!(
        "cc-source-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        hex::encode(digest(raw))
    ));
    std::fs::write(&path, raw).unwrap();
    path
}
fn candidate() -> Value {
    let raw=b"Egyptian and Hittite forces fought at Kadesh in 1274 BCE. This fixture records the battle and does not establish causal relationships.";
    let path = source_capture(raw);
    let source = json!({"url":"https://example.org/source","retrieved_at":"2026-09-15T00:00:00Z","content_sha256":hex::encode(digest(raw)),"capture_path":path,"excerpt":std::str::from_utf8(raw).unwrap(),"license":"CC0-1.0","publisher":"Fixture","locator":"paragraph 1","supports":["title","year","summary"]});
    json!({"entries":[{"title":"Battle of Kadesh","year":-1274,"claim_type":"conflict-and-warfare","lens":"A","summary":std::str::from_utf8(raw).unwrap(),"date_is_known":true,"temporal_kind":"event","observed_count":1,"tt_release":"tt-ontology/2.1.0","tt_bundle_sha256":cc_filter::version::TT_BUNDLE_SHA256,
 "prov_measured":{"text_model":"fixture","provider":"fixture","method":"test","run":"frozen-test","generated_at":"2026-09-15T00:00:00Z","source_evidence_schema":"cc.source-evidence.v1","source_evidence":[source]},
 "prov_asserted":{"historical_claim":"fixture","source_support":{"schema":"cc.source-support.v1","claim":"battle occurrence","source_urls":["https://example.org/source"],"support_kind":"observed","rationale":"explicit statement"}}}],"edges":[],"images":[]})
}
async fn prepared(pool: &sqlx::PgPool, id: &str) -> Vec<u8> {
    let b = stage_brief(pool, id, &json!({"text":"test","max_entries":5}))
        .await
        .unwrap();
    approve(
        pool,
        "brief",
        id,
        &hex::decode(b["digest"].as_str().unwrap()).unwrap(),
        "test-human",
    )
    .await
    .unwrap();
    let c = stage_candidate(pool, id, id, &candidate()).await.unwrap();
    let hash = hex::decode(c["digest"].as_str().unwrap()).unwrap();
    approve(pool, "candidate", id, &hash, "test-human")
        .await
        .unwrap();
    sqlx::query("UPDATE publication_control SET paused=false")
        .execute(pool)
        .await
        .unwrap();
    hash
}
#[test]
fn required_images_refuse_missing_review_and_changed_claim_body() {
    let mut v = candidate();
    let brief = json!({"images_required":true});
    assert!(require_images(&brief, &v).is_err());
    let e = &v["entries"][0];
    let id =
        cc_authoring::claim_identity(e["title"].as_str().unwrap(), e["year"].as_i64().unwrap()).0;
    let bh = hex::encode(cc_authoring::body_hash("claim_v4", &e.to_string()));
    v["images"] = json!([{"entry_index":0,"manifest":{"source":{"entity_id":id.to_string(),"body_hash":bh},
        "visual_review":"pending","synthetic":true,"historical_verification":"not_assessed"}}]);
    assert!(require_images(&brief, &v).is_err());
    v["images"][0]["manifest"]["visual_review"] = json!("accepted_as_illustration");
    require_images(&brief, &v).unwrap();
    v["entries"][0]["summary"] = json!("changed claim body");
    assert!(require_images(&brief, &v).is_err());
    require_images(&json!({"images_required":false}), &v).unwrap();
    assert!(require_images(&json!({"images_required":"true"}), &v).is_err());
}

#[tokio::test]
async fn required_images_gate_staging_before_any_candidate_write() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let brief = stage_brief(
        &pool,
        "with-images",
        &json!({"max_entries":5,"images_required":true}),
    )
    .await
    .unwrap();
    approve(
        &pool,
        "brief",
        "with-images",
        &hex::decode(brief["digest"].as_str().unwrap()).unwrap(),
        "test-human",
    )
    .await
    .unwrap();
    assert!(
        stage_candidate(&pool, "missing-images", "with-images", &candidate())
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM generation_candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    cleanup.cleanup().await;
}
#[test]
fn rejects_uncaptured_support_and_unknown_edges() {
    let mut v = candidate();
    validate_candidate(&v).unwrap();
    v["entries"][0]["prov_asserted"]["source_support"]["source_urls"] =
        json!(["https://invented.org"]);
    assert!(validate_candidate(&v).is_err());
    let mut v = candidate();
    v["entries"][0]["prov_measured"]["source_evidence"][0]["excerpt"] = json!("invented excerpt");
    assert!(validate_candidate(&v).is_err());
    let mut v = candidate();
    v["edges"] = json!([{"from":{"title":"Battle of Kadesh","year":-1274},"to":{"title":"another event","year":-1270},"relation":"surprise"}]);
    assert!(validate_candidate(&v).is_err());
}
#[tokio::test]
async fn rollback_and_replay_are_atomic() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let hash = prepared(&pool, "atomic").await;
    sqlx::raw_sql("CREATE FUNCTION fail_body() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER fail_body BEFORE INSERT ON claim_bodies FOR EACH ROW EXECUTE FUNCTION fail_body();").execute(&pool).await.unwrap();
    let key = cc_core::SecretKey::from_seed([72; 32]);
    assert!(publish(&pool, "atomic", &hash, &key).await.is_err());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(receipt(&pool, "atomic").await.unwrap().is_none());
    sqlx::query("DROP TRIGGER fail_body ON claim_bodies")
        .execute(&pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        publish(&pool, "atomic", &hash, &key),
        publish(&pool, "atomic", &hash, &key)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM publication_receipts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(publish(&pool, "atomic", &[0; 32], &key).await.is_err());
    pool.close().await;
    cleanup.cleanup().await;
}
#[tokio::test]
async fn pause_approval_and_worker_role_are_enforced() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let hash = prepared(&pool, "gate").await;
    let key = cc_core::SecretKey::from_seed([73; 32]);
    sqlx::query("UPDATE publication_control SET paused=true")
        .execute(&pool)
        .await
        .unwrap();
    assert!(publish(&pool, "gate", &hash, &key).await.is_err());
    sqlx::query("UPDATE publication_control SET paused=false")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM generation_approvals WHERE kind='candidate'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(publish(&pool, "gate", &hash, &key).await.is_err());
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE cc_generation_worker")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(sqlx::query("INSERT INTO generation_approvals(kind,target_id,digest,reviewer) VALUES('candidate','gate',$1,'fake-human')").bind(hash).execute(&mut *tx).await.is_err());
    tx.rollback().await.unwrap();
    pool.close().await;
    cleanup.cleanup().await;
}

fn dated_candidate() -> Value {
    let mut v = candidate();
    let raw = b"Synthetic cause occurred on April 13, 1970. Synthetic effect occurred on April 14, 1970 because the synthetic cause disabled its power supply.";
    let path = source_capture(raw);
    let mut source = v["entries"][0]["prov_measured"]["source_evidence"][0].clone();
    source["capture_path"] = json!(path);
    source["content_sha256"] = json!(hex::encode(digest(raw)));
    source["excerpt"] = json!(std::str::from_utf8(raw).unwrap());
    source["supports"] = json!(["title", "year", "summary", "date", "relation"]);
    let mut first = v["entries"][0].clone();
    first["title"] = json!("Synthetic cause");
    first["year"] = json!(1970);
    first["summary"] = json!(std::str::from_utf8(raw).unwrap());
    first["prov_measured"]["source_evidence"] = json!([source.clone()]);
    first["prov_asserted"]["event_date"] = json!("1970-04-13");
    first["prov_asserted"]["date_precision"] = json!("day");
    let mut second = first.clone();
    second["title"] = json!("Synthetic effect");
    second["prov_asserted"]["event_date"] = json!("1970-04-14");
    v["entries"] = json!([first, second]);
    v["edges"] = json!([{"from":{"title":"Synthetic cause","year":1970},"to":{"title":"Synthetic effect","year":1970},"relation":"causation","evidence_class":"PrimaryDocument","rationale":std::str::from_utf8(raw).unwrap(),"evidence":[source]}]);
    for (side, index) in [("from", 0), ("to", 1)] {
        v["edges"][0][side]["binding"] = review::entry_binding(&v["entries"][index]).unwrap();
    }
    v
}
#[test]
fn day_precision_validates_gregorian_dates_and_causal_order() {
    let legacy = candidate();
    assert_eq!(
        entry_coordinate(&legacy["entries"][0]).unwrap(),
        cc_authoring::year_tick(-1274)
    );
    let mut v = dated_candidate();
    validate_candidate(&v).unwrap();
    let expected =
        cc_core::Tick::from_whole_ticks(-946728000 + 102 * 86400, cc_core::B256Constants::V0.split);
    assert_eq!(entry_coordinate(&v["entries"][0]).unwrap(), expected);
    for date in [
        "1970-02-29",
        "1970-00-10",
        "1970-13-01",
        "1970-04-31",
        "1970-04-00",
        "1970-4-13",
        "1970-04-13T00:00Z",
        "1969-04-13",
    ] {
        v["entries"][0]["prov_asserted"]["event_date"] = json!(date);
        assert!(validate_candidate(&v).is_err(), "accepted invalid {date}");
    }
    v = dated_candidate();
    v["entries"][0]["year"] = json!(2000);
    v["entries"][0]["prov_asserted"]["event_date"] = json!("2000-02-29");
    assert!(entry_coordinate(&v["entries"][0]).is_ok());
    v["entries"][0]["year"] = json!(1900);
    v["entries"][0]["prov_asserted"]["event_date"] = json!("1900-02-29");
    assert!(entry_coordinate(&v["entries"][0]).is_err());
    v = dated_candidate();
    v["entries"][1]["prov_asserted"]["event_date"] = json!("1970-04-12");
    assert!(
        validate_candidate(&v).is_err(),
        "same-year reversed cause accepted"
    );
    v = dated_candidate();
    v["entries"][0]["prov_measured"]["source_evidence"][0]["supports"] =
        json!(["title", "year", "summary"]);
    assert!(
        validate_candidate(&v).is_err(),
        "day accepted without source support"
    );
}
#[tokio::test]
async fn precise_dates_reach_entities_moments_edges_and_vocabulary() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let b = stage_brief(
        &pool,
        "days",
        &json!({"fixture":"day-precision","max_entries":2}),
    )
    .await
    .unwrap();
    approve(
        &pool,
        "brief",
        "days",
        &hex::decode(b["digest"].as_str().unwrap()).unwrap(),
        "test-human",
    )
    .await
    .unwrap();
    let candidate = dated_candidate();
    let c = stage_candidate(&pool, "days", "days", &candidate)
        .await
        .unwrap();
    let hash = hex::decode(c["digest"].as_str().unwrap()).unwrap();
    approve(&pool, "candidate", "days", &hash, "test-human")
        .await
        .unwrap();
    sqlx::query("UPDATE publication_control SET paused=false")
        .execute(&pool)
        .await
        .unwrap();
    publish(
        &pool,
        "days",
        &hash,
        &cc_core::SecretKey::from_seed([79; 32]),
    )
    .await
    .unwrap();
    let at = entry_coordinate(&candidate["entries"][0])
        .unwrap()
        .to_canon_bytes()
        .to_vec();
    let later = entry_coordinate(&candidate["entries"][1])
        .unwrap()
        .to_canon_bytes()
        .to_vec();
    let before = cc_authoring::year_tick(1970).to_canon_bytes().to_vec();
    let early: i64 = sqlx::query_scalar("SELECT count(*) FROM entities WHERE birth_event_time<=$1")
        .bind(before)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(early, 0, "day events appeared at start of year");
    let starts: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT window_start FROM entities ORDER BY window_start")
            .fetch_all(&pool)
            .await
            .unwrap();
    let moments: Vec<Vec<u8>> = sqlx::query_scalar("SELECT coord FROM moments ORDER BY coord")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(starts, vec![at.clone(), later.clone()]);
    assert_eq!(moments, starts);
    let edge: Vec<u8> = sqlx::query_scalar("SELECT event_time FROM edges")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(edge, later);
    let band: Vec<u8> = sqlx::query_scalar("SELECT band_start FROM vocabulary")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(band, at);
    let retained: String = sqlx::query_scalar("SELECT evidence FROM edge_evidence")
        .fetch_one(&pool)
        .await
        .unwrap();
    let retained: Value = serde_json::from_str(&retained).unwrap();
    assert_eq!(
        retained["from_binding"],
        candidate["edges"][0]["from"]["binding"]
    );
    assert_eq!(
        retained["to_binding"],
        candidate["edges"][0]["to"]["binding"]
    );
    cc_ledger::rebuild(&pool).await.unwrap();
    pool.close().await;
    cleanup.cleanup().await;
}

// Synthetic subject substitution: no real historical corpus is copied into tests.
#[test]
fn machine_edge_cannot_be_carried_to_a_retrospective_body() {
    let mut original = dated_candidate();
    original["entries"][1]["prov_asserted"]["subject_kind"] = json!("machine");
    for (side, index) in [("from", 0), ("to", 1)] {
        let entry = &original["entries"][index];
        let binding = review::entry_binding(entry).unwrap();
        original["edges"][0][side]["binding"] = binding;
    }
    validate_candidate(&original).unwrap();
    let frozen = original.to_string();
    let mut rewritten = original.clone();
    rewritten["entries"][1]["prov_asserted"]["subject_kind"] = json!("document");
    rewritten["entries"][1]["prov_asserted"]["historical_claim"] = json!("A later synthetic document describes a machine; the document is the subject of this claim.");
    let error = validate_candidate(&rewritten)
        .expect_err("a machine edge must not survive a document-subject rewrite");
    assert!(
        error.to_string().contains("destination_subject_changed"),
        "{error}"
    );
    assert_eq!(original.to_string(), frozen);
    assert_eq!(rewritten["edges"], original["edges"]);
    assert_eq!(
        error.downcast_ref::<review::AdmissionError>(),
        Some(&review::AdmissionError::DestinationSubjectChanged)
    );
    // Recalculating hashes cannot authorize repurposing a frozen subject.
    rewritten["edges"][0]["to"]["binding"] =
        review::entry_binding(&rewritten["entries"][1]).unwrap();
    assert!(review::validate_frozen_subjects(&original, &rewritten).is_err());
    rewritten["entries"][1]["title"] = json!("Synthetic retrospective document");
    assert_eq!(
        validate_candidate(&rewritten)
            .unwrap_err()
            .downcast_ref::<review::AdmissionError>(),
        Some(&review::AdmissionError::EdgeTargetMismatch)
    );
}

#[test]
fn unbound_edges_and_body_only_substitutions_are_refused() {
    let mut v = dated_candidate();
    v["edges"][0]["to"]
        .as_object_mut()
        .unwrap()
        .remove("binding");
    assert_eq!(
        validate_candidate(&v)
            .unwrap_err()
            .downcast_ref::<review::AdmissionError>(),
        Some(&review::AdmissionError::EdgeBindingMissing)
    );
    let mut v = dated_candidate();
    v["entries"][1]["prov_asserted"]["historical_claim"] =
        json!("A later document, not the original event.");
    assert_eq!(
        validate_candidate(&v)
            .unwrap_err()
            .downcast_ref::<review::AdmissionError>(),
        Some(&review::AdmissionError::DestinationSubjectChanged)
    );
}

#[test]
fn dry_run_reports_exact_claims_only_set_and_blocks_evidence_gap() {
    let v = dated_candidate();
    let before = v.to_string();
    let receipt = json!({"schema":"cc.generation-result.v1","status":"needs_evidence","reason":"Synthetic unresolved destination","published":false});
    let report = review::dry_run(&v, &json!({"images_required":false}), &receipt).unwrap();
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["blockers"][0]["code"], "needs_evidence");
    assert_eq!(
        report["entities"][1],
        review::entry_binding(&v["entries"][1]).unwrap()
    );
    assert_eq!(report["edges"].as_array().unwrap().len(), 1);
    assert_eq!(report["media"], json!({"kind":"none","records":[]}));
    assert_eq!(report["writes_performed"], false);
    assert_eq!(v.to_string(), before);
}

#[tokio::test]
async fn existing_machine_identity_cannot_be_reused_for_document_even_with_new_bindings() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let hash = prepared(&pool, "original").await;
    publish(
        &pool,
        "original",
        &hash,
        &cc_core::SecretKey::from_seed([83; 32]),
    )
    .await
    .unwrap();
    let mut next = candidate();
    next["entries"][0]["prov_asserted"]["subject_kind"] = json!("document");
    next["entries"][0]["prov_asserted"]["historical_claim"] =
        json!("A synthetic retrospective document is the new subject.");
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .unwrap();
    let error = stage_candidate(&pool, "repurposed", "original", &next)
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<review::AdmissionError>(),
        Some(&review::AdmissionError::SubjectIdentityReused)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM generation_candidates WHERE id='repurposed'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    cleanup.cleanup().await;
}
