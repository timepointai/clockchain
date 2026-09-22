use cc_publisher::*;
use serde_json::{json, Value};
fn candidate() -> Value {
    let raw=b"Egyptian and Hittite forces fought at Kadesh in 1274 BCE. This fixture records the battle and does not establish causal relationships.";
    let path = std::env::temp_dir().join(format!("cc-source-{}", hex::encode(digest(raw))));
    std::fs::write(&path, raw).unwrap();
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
