//! Replay the LIVE chain's events into an ephemeral database and report the
//! view digest. Ignored by default; it needs an export to point at.
//!
//!     CC_REPLAY_TSV=/path/to/prod-events.tsv \
//!     cargo test -p cc-ledger --test replay_live -- --ignored --nocapture
//!
//! **Why this exists.** M1b changes how every moment projects. The argument
//! that it is a no-op on the live chain is sound — 0 of 1176 stored events
//! carry `supersedes`, so both walks terminate immediately and the row written
//! is the row M1 wrote — but it is an argument, and this repository has a
//! standing rule against shipping one of those where a measurement is
//! available. Run this under the old projector and the new one and compare the
//! two digests: equal means the fold is invisible to the existing corpus, by
//! observation, on the actual bytes.
//!
//! The export carries the six fields needed to reconstruct a `Signed` through
//! the ordinary gate — there is no raw-insert path here either, so the replay
//! re-verifies all 1176 signatures on the way in. Provenance is deliberately
//! omitted: it is an envelope column outside `H0` and outside `view_root`, so
//! it cannot move the digest this test compares.

use cc_core::{parse_event, AuthorKey, Signature, Tick};
use cc_ledger::{commit, view_root, Signed};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("export field is not hex")
}

fn fixed<const N: usize>(v: Vec<u8>, what: &str) -> [u8; N] {
    v.try_into()
        .unwrap_or_else(|_| panic!("{what} has the wrong width"))
}

#[tokio::test]
#[ignore = "needs CC_REPLAY_TSV pointing at an events export"]
async fn replaying_the_live_chain_reports_its_view_digest() {
    let path = std::env::var("CC_REPLAY_TSV").expect("set CC_REPLAY_TSV");
    let text = std::fs::read_to_string(&path).expect("read the export");

    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let mut committed = 0usize;
    let mut unioned = 0usize;

    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 6, "line {} has {} fields", n + 1, f.len());

        let expected_id = unhex(f[0]);
        let author = AuthorKey::from_bytes(&fixed::<32>(unhex(f[1]), "author_key"))
            .expect("author_key is a valid ed25519 key");
        let signature = Signature::from_bytes(fixed::<64>(unhex(f[2]), "signature"));
        let event_time = Tick::from_canon_bytes(fixed::<32>(unhex(f[3]), "event_time"));
        let record_time = Tick::from_canon_bytes(fixed::<32>(unhex(f[4]), "record_time"));
        let payload = unhex(f[5]);

        let content = parse_event(&payload, event_time, record_time, author)
            .unwrap_or_else(|_| panic!("line {} failed to parse", n + 1));
        // The ordinary gate: recomputes H0 and checks the signature. A tampered
        // export cannot get past this, so a green run is also 1176 verified
        // signatures.
        let signed = Signed::seal(content, signature)
            .unwrap_or_else(|_| panic!("line {} failed the signature gate", n + 1));
        assert_eq!(
            signed.id().as_bytes().to_vec(),
            expected_id,
            "line {} : H0 != the exported event_id",
            n + 1
        );

        if commit(&pool, &signed).await.expect("commit").is_new() {
            committed += 1;
        } else {
            unioned += 1;
        }
    }

    let digest = view_root(&pool).await.expect("view_root");
    let stats = cc_ledger::read_stats(&pool)
        .await
        .expect("stats")
        .expect("stats row");
    let corrected: i64 =
        sqlx::query_scalar("SELECT count(*) FROM moments WHERE root_event_id <> head_event_id")
            .fetch_one(&pool)
            .await
            .expect("count corrections");

    println!("replayed        {committed} new, {unioned} unioned");
    println!("entities        {}", stats.entity_count);
    println!("moments         {}", stats.moment_count);
    println!("edges           {}", stats.edge_count);
    println!("corrected rows  {corrected}");
    println!("VIEW_ROOT       {}", hex::encode(digest));

    // A replay is the union-merge property: a second node built from the first
    // node's events. It must be able to prove its own view discardable.
    let after = cc_ledger::rebuild(&pool)
        .await
        .expect("rebuild must not diverge");
    assert_eq!(after, digest, "rebuild diverged from the replayed fold");
    println!("REBUILD         {} (equal)", hex::encode(after));

    cleanup.cleanup().await;
}
