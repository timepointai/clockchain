//! `cc-anchor-tick` — seal an epoch, and optionally anchor it.
//!
//! The cron entry point, as its own binary rather than a server subcommand: a
//! scheduled seal should not require booting an HTTP listener, and an ops task
//! that can run when the node is down is one less thing coupled to the node
//! being up. `cc-node` surfaces the same state read-only on `/health/deep`.
//!
//!   cc-anchor-tick seal        publish a Merkle root over the committed log
//!   cc-anchor-tick anchor      submit the latest root to an OTS calendar
//!   cc-anchor-tick upgrade     ask whether a pending anchor made it into a block
//!   cc-anchor-tick audit       re-verify the whole root chain against the log
//!
//! `now` is passed in from the process clock at the edge and threaded down as a
//! coordinate. Nothing inside `cc-anchor` reads a clock, so a tick is
//! reproducible: the same log and the same `now` seal the same root.

use std::time::{SystemTime, UNIX_EPOCH};

use cc_anchor::{
    anchor_root, committed_leaf_count, latest_anchor, latest_root, publish_root, upgrade_anchor,
    verify_root_chain, RootOutcome,
};
use cc_core::{B256Constants, SecretKey, Tick};

/// Seconds from the Unix epoch to J2000.0, the pinned Clock Zero.
const UNIX_TO_J2000_SECS: i64 = 946_728_000;

/// A public aggregating calendar. No wallet, no funded Bitcoin path: the
/// calendar batches our root into its own timestamped transaction, which is the
/// whole reason OpenTimestamps exists.
const DEFAULT_CALENDAR: &str = "https://a.pool.opentimestamps.org";

fn now_tick() -> Tick {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64;
    Tick::from_whole_ticks(secs - UNIX_TO_J2000_SECS, B256Constants::V0.split)
}

/// The node-0 signing identity. Absence is a refusal to run, never a generated
/// fallback: a tick that quietly invents a key would publish a root nobody can
/// attribute, and the next real tick would fork the stream.
fn genesis_key() -> SecretKey {
    let hex_seed = std::env::var("GENESIS_SECRET_KEY")
        .expect("GENESIS_SECRET_KEY must be set — an anchor tick must not invent an identity");
    let raw = hex::decode(hex_seed.trim()).expect("GENESIS_SECRET_KEY must be hex");
    let seed: [u8; 32] = raw
        .as_slice()
        .try_into()
        .expect("GENESIS_SECRET_KEY must be 32 bytes");
    SecretKey::from_seed(seed)
}

#[tokio::main]
async fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "seal".into());
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = cc_ledger::connect(&url).await.expect("connect");
    let now = now_tick();

    match cmd.as_str() {
        "seal" => {
            let key = genesis_key();
            match publish_root(&pool, &key, now).await.expect("seal") {
                RootOutcome::Published(p) => {
                    println!("published height {} root {}", p.height, p.root.to_hex());
                    println!("  tree_size {}", p.tree_size);
                    match p.prev_root {
                        Some(prev) => println!("  extends   {}", prev.to_hex()),
                        None => println!("  extends   (genesis root, extends nothing)"),
                    }
                    match p.moment {
                        Some(m) => println!("  recorded  {}", m.to_hex()),
                        None => println!("  recorded  MISSING — this root is not settled history"),
                    }
                }
                RootOutcome::Unchanged { height, root } => {
                    println!("unchanged at height {height}: {}", root.to_hex());
                }
            }
        }

        "anchor" => {
            let key = genesis_key();
            let calendar =
                std::env::var("OTS_CALENDAR").unwrap_or_else(|_| DEFAULT_CALENDAR.into());
            let root = latest_root(&pool)
                .await
                .expect("latest root")
                .expect("nothing published yet — run `seal` first");
            let rec = anchor_root(&pool, &key, &root.root, &calendar, now)
                .await
                .expect("anchor");
            println!("anchored {} via {calendar}", root.root.to_hex());
            println!("  status {:?}", rec.status);
        }

        "upgrade" => {
            let key = genesis_key();
            let root = latest_root(&pool)
                .await
                .expect("latest root")
                .expect("nothing published yet");
            let out = upgrade_anchor(&pool, &key, &root.root, now)
                .await
                .expect("upgrade");
            println!("{out:?}");
        }

        "audit" => {
            let leaves = committed_leaf_count(&pool).await.expect("leaf count");
            let audit = verify_root_chain(&pool).await.expect("audit");
            println!("committed leaves  {leaves}");
            println!("roots checked     {}", audit.roots_checked);
            println!("{audit:#?}");
            if let Some(a) = latest_anchor(&pool).await.expect("latest anchor") {
                println!("latest anchor     {:?} ({}s old)", a.status, a.age_seconds);
            } else {
                println!("latest anchor     none");
            }
        }

        other => {
            eprintln!("unknown command {other:?}; expected seal | anchor | upgrade | audit");
            std::process::exit(2);
        }
    }
}
