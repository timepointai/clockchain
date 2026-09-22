//! Replay a private corpus snapshot into a fresh local test database, compare
//! every core projection field, then prove that a second rebuild agrees.
//! Never connects to production; never imports operational approvals or data.
use cc_core::{parse_event, AuthorKey, Signature, Tick};
use cc_ledger::{commit, Signed};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};
use std::{collections::BTreeSet, error::Error, os::unix::fs::OpenOptionsExt, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const TABLES: &[(&str, &str)] = &[
    ("entities", "entity_id,birth_event,birth_event_time,resolution_key,canonical_name,window_start,start_state,closure_state,window_end,asserter"),
    ("moments", "root_event_id,head_event_id,subject,coord,record_coord,posture,body_hash,author_key"),
    ("edges", "edge_id,src_entity,dst_entity,relation,evidence_class,asserter,event_time,status,in_g,cross_writer"),
    ("attestations", "event_id,target,author"),
    ("vocabulary", "claim_type,label,declared_by,declared_at,band_start,start_state,band_end,closure_state"),
    ("taxonomy_tags", "event_id,lens,tag"),
    ("ledger_stats", "entity_count,moment_count,edge_count,attestation_count,contested_edges,cross_writer_contested"),
];
fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(
        v.as_str().ok_or("missing hex")?.trim_start_matches("\\x"),
    )?)
}
fn fixed<const N: usize>(v: &Value) -> Result<[u8; N]> {
    bytes(v)?
        .try_into()
        .map_err(|_| "invalid byte width".into())
}
fn signed(row: &Value) -> Result<Signed> {
    let author = AuthorKey::from_bytes(&fixed(&row["author_key"])?)?;
    let event_time = Tick::from_canon_bytes(fixed(&row["event_time"])?);
    let record_time = Tick::from_canon_bytes(fixed(&row["record_time"])?);
    let payload = bytes(&row["payload"])?;
    let content = parse_event(&payload, event_time, record_time, author)?;
    let parent = content
        .supersedes
        .map(|p| format!("\\x{}", hex::encode(p.as_bytes())));
    // parse_event reads identity fields from canon. Independently check every
    // corresponding envelope column, including attestation author/record time.
    if content.event_time != event_time
        || content.record_time != record_time
        || content.author != author
        || json!(parent) != row["supersedes"]
        || content.body.kind() as i64 != row["kind"].as_i64().ok_or("missing kind")?
        || cc_core::canon_event(&content) != payload
    {
        return Err("canonical payload/envelope mismatch".into());
    }
    let event = Signed::seal(content, Signature::from_bytes(fixed(&row["signature"])?))?;
    if event.id().as_bytes().as_slice() != bytes(&row["event_id"])? {
        return Err("event identity mismatch".into());
    }
    Ok(event)
}
fn rows(value: &Value) -> Result<BTreeSet<String>> {
    let list = value.as_array().ok_or("missing table")?;
    let set: BTreeSet<_> = list.iter().map(Value::to_string).collect();
    if list.len() != set.len() {
        return Err("duplicate snapshot rows".into());
    }
    Ok(set)
}
async fn compare(pool: &PgPool, snapshot: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for (table, columns) in TABLES {
        let sql = format!(
            "SELECT coalesce(json_agg(t),'[]'::json)::text FROM (SELECT {columns} FROM {table}) t"
        );
        let text: String = sqlx::query_scalar(&sql).fetch_one(pool).await?;
        let actual = rows(&serde_json::from_str::<Value>(&text)?)?;
        let expected = rows(&snapshot["tables"][table])?;
        result.insert(table.to_string(), json!({
            "equal": actual == expected, "captured_rows": expected.len(), "replayed_rows": actual.len(),
            "captured_only_rows": expected.difference(&actual).count(),
            "replay_only_rows": actual.difference(&expected).count(),
        }));
    }
    Ok(Value::Object(result))
}
async fn run(pool: &PgPool, snapshot: &Value) -> Result<Value> {
    if snapshot["schema"] != "cc.corpus-snapshot.v1" {
        return Err("unsupported snapshot".into());
    }
    let events = snapshot["tables"]["events"]
        .as_array()
        .ok_or("missing events")?;
    if events.is_empty() {
        return Err("empty corpus".into());
    }
    let mut ordered: Vec<_> = events.iter().collect();
    ordered.sort_by_key(|e| (e["event_time"].as_str(), e["event_id"].as_str()));
    for row in ordered {
        commit(pool, &signed(row)?).await?;
    }
    let comparisons = compare(pool, snapshot).await?;
    let matches = comparisons
        .as_object()
        .ok_or("comparison failed")?
        .values()
        .all(|v| v["equal"] == true);
    let root = cc_ledger::rebuild(pool).await?;
    Ok(
        json!({"schema":"cc.replay-audit.v1", "signatures_and_canon":"pass", "events": events.len(),
        "core_projection_matches_capture": matches, "tables": comparisons, "local_rebuild":"pass",
        "local_view_root":hex::encode(root),
        "not_replayed":["claim body storage","edge evidence","commitment log","root and anchor history","media","operational records"],
        "historical_truth":"not_assessed"}),
    )
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: audit_replay PRIVATE_SNAPSHOT PRIVATE_REPORT".into());
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let destination = Path::new(&args[2]);
    let parent = destination
        .parent()
        .ok_or("report parent required")?
        .canonicalize()?;
    if parent.starts_with(repo) {
        return Err("report must be outside the checkout".into());
    }
    let url = std::env::var("TEST_DATABASE_URL")?;
    let options: PgConnectOptions = url.parse()?;
    if !["127.0.0.1", "::1"].contains(&options.get_host())
        || options.get_database() != Some("postgres")
    {
        return Err("use a local loopback test cluster's postgres database".into());
    }
    let snapshot: Value = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let result = run(&pool, &snapshot).await;
    pool.close().await;
    cleanup.cleanup().await;
    match result {
        Ok(report) => {
            serde_json::to_writer_pretty(output, &report)?;
            println!("{}", report);
            if report["core_projection_matches_capture"] != true {
                std::process::exit(1);
            }
            Ok(())
        }
        Err(error) => {
            serde_json::to_writer_pretty(
                output,
                &json!({"schema":"cc.replay-audit.v1","status":"failed","historical_truth":"not_assessed"}),
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_core::{EventBody, EventContent, MomentBody, SecretKey};
    fn row() -> Value {
        let key = SecretKey::from_seed([7; 32]);
        let event = Signed::sign(
            &key,
            EventContent {
                event_time: Tick::ORIGIN,
                record_time: Tick::ORIGIN,
                author: key.author(),
                supersedes: None,
                body: EventBody::Moment(MomentBody {
                    subject: 1,
                    body_hash: [3; 32],
                }),
            },
        );
        let content = event.content();
        json!({"event_id":format!("\\x{}",hex::encode(event.id().as_bytes())),
            "author_key":format!("\\x{}",hex::encode(key.author().to_bytes())),
            "signature":format!("\\x{}",hex::encode(key.seal(content).1.to_bytes())),
            "event_time":format!("\\x{}",hex::encode(Tick::ORIGIN.to_canon_bytes())),
            "record_time":format!("\\x{}",hex::encode(Tick::ORIGIN.to_canon_bytes())),
            "payload":format!("\\x{}",hex::encode(cc_core::canon_event(content))),
            "supersedes":null,"kind":content.body.kind() as i16})
    }
    #[test]
    fn verifies_canon_and_refuses_envelope_drift() {
        let mut r = row();
        assert!(signed(&r).is_ok());
        r["event_time"] = json!(format!(
            "\\x{}",
            hex::encode(Tick::from_i64(1).to_canon_bytes())
        ));
        assert!(signed(&r).is_err());
    }
    #[tokio::test]
    async fn replay_detects_projection_drift() {
        let (pool, cleanup) = cc_testkit::ephemeral_db().await;
        let e = row();
        commit(&pool, &signed(&e).unwrap()).await.unwrap();
        let mut tables = serde_json::Map::new();
        for (table, columns) in TABLES {
            let text:String=sqlx::query_scalar(&format!("SELECT coalesce(json_agg(t),'[]'::json)::text FROM (SELECT {columns} FROM {table}) t")).fetch_one(&pool).await.unwrap();
            tables.insert(table.to_string(), serde_json::from_str(&text).unwrap());
        }
        let mut snapshot = json!({"tables":tables});
        assert!(compare(&pool, &snapshot)
            .await
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .all(|v| v["equal"] == true));
        snapshot["tables"]["moments"][0]["subject"] = json!(999);
        assert_eq!(
            compare(&pool, &snapshot).await.unwrap()["moments"]["equal"],
            false
        );
        pool.close().await;
        cleanup.cleanup().await;
    }
}
