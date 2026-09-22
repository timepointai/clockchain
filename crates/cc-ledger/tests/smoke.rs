//! Real-DB smoke test — no mocks. Requires a live Postgres (`make db-up`
//! locally, the Postgres service container in CI). Each run gets an ephemeral
//! database from `cc-testkit`.

use cc_core::{EventBody, EventContent, MomentBody, SecretKey, Tick};
use cc_ledger::{commit, Appended, Signed};

#[tokio::test]
async fn one_signed_moment_commits_appends_and_projects() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("count events");
    assert_eq!(before, 0, "fresh ledger must start empty");

    // Build, sign, and commit one moment through the real gate.
    let sk = SecretKey::from_seed([1u8; 32]);
    let content = EventContent {
        event_time: Tick::from_i64(1),
        record_time: Tick::from_i64(2),
        author: sk.author(),
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: 7,
            body_hash: [9u8; 32],
        }),
    };
    let signed = Signed::sign(&sk, content);
    let id = signed.id();
    assert_eq!(commit(&pool, &signed).await.expect("commit"), Appended::New);

    // The event landed and we can read the content address back.
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("recount");
    assert_eq!(after, 1);
    let stored: Vec<u8> = sqlx::query_scalar("SELECT event_id FROM events LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("read event_id");
    assert_eq!(stored, id.as_bytes().to_vec());

    // The moment projected into the view in the same transaction.
    let moments: i64 = sqlx::query_scalar("SELECT count(*) FROM moments")
        .fetch_one(&pool)
        .await
        .expect("count moments");
    assert_eq!(moments, 1);

    // Re-committing an identical event is a CRDT union no-op, never an error.
    assert_eq!(
        commit(&pool, &signed).await.expect("re-commit"),
        Appended::Unioned
    );
    let still_one: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("recount after re-commit");
    assert_eq!(still_one, 1, "re-committing a seen event_id is a no-op");

    pool.close().await;
    cleanup.cleanup().await;
}
