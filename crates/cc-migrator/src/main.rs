//! `cc-migrator` — the partitioned writer that replays the founding exhibit
//! through the exact same `cc-ledger` write path as everyone else.
//!
//! There is no `Signed::from_trusted()` and no raw-insert bypass. This binary
//! calls `Signed::sign` and `cc_ledger::commit*` — the identical functions any
//! other writer must use — and the only thing it carries that others do not is
//! an `ExhibitRef` recording *where it learned the claim*. "The migrator is just
//! another writer" is a fact about which functions exist, not a policy anyone
//! has to remember (whitepaper §coattest, §bootstrap; memo §1).
//!
//!   migrate          apply the schema migrations to DATABASE_URL
//!   keygen           print a fresh migrator seed (dev convenience)
//!   commit-exhibit   SHA-256 a frozen corpus, record the commitment
//!   genesis          node 0: exhibit commitment + governed constants, as moments
//!   migrate-batch    replay the exhibit's `nodes` block as entities + moments
//!   migrate-edges    replay the exhibit's `edges` block as typed relations
//!   declare-vocabulary  derive the governed claim-type vocabulary from the corpus
//!   status           what the ledger holds
//!   mirror           build THIS ledger from another node's event export

/// The strict admission gate. Nothing this binary authors reaches the ledger
/// without passing it (Sean, 2026-08-17: "every entry has to be perfect").
use cc_authoring::admission;

/// TT classification profiles — enforced here, defined upstream. A port of
/// telemetry's `tt_validate.py`, rule for rule and code for code.
use cc_authoring::classification;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use cc_authoring::{body_hash, claim_identity, now_tick, year_tick};
use cc_core::{
    AuthorKey, B256Constants, EdgeBody, EdgeRelation, EntityBirth, EventBody, EventContent,
    EvidenceClass, ExhibitId, ExhibitRef, ExistenceWindow, FilterVersionId, MomentBody,
    ProtocolConstants, SecretKey, Tick, VocabularyEntry, WindowEnd, WindowStart,
};
use cc_ledger::Signed;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use sqlx::Row;

/// Entity 0 is reserved for node 0 — the ledger records its own governance as a
/// first-class entity under its own discipline (whitepaper §ledger).
const NODE_ZERO: i64 = 0;

/// Seconds from the Unix epoch to J2000.0, the pinned Clock Zero.

#[derive(Parser)]
#[command(
    name = "cc-migrator",
    about = "Replay the founding exhibit. No bypass."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Apply the embedded schema migrations and exit.
    ///
    /// The same `cc_ledger::run_migrations` the node runs, reachable without
    /// booting a server — which is what a restore drill (M6) needs: bring up an
    /// empty database, apply the schema, replay, verify.
    Migrate,
    /// Print a fresh migrator seed. Dev convenience; real keys are provisioned.
    Keygen,
    /// Commit a frozen corpus by SHA-256 over its bytes, exactly as they are.
    CommitExhibit {
        path: String,
        #[arg(long)]
        note: String,
    },
    /// Mint node 0. Optionally anchor it to a committed exhibit.
    ///
    /// Without `--exhibit` the chain is born of nothing but itself: node 0 is
    /// the Clockchain, and its existence window opens at the instant it is
    /// minted. A chain with no corpus behind it should not have to invent one
    /// to have a beginning.
    Genesis {
        #[arg(long)]
        exhibit: Option<String>,
    },
    /// Mint claims from a JSON array through the shared write path.
    ///
    /// Each entry becomes an entity plus a moment. Entity identity is derived
    /// from the CLAIM — never from a path, a slug or a surrogate. That single
    /// rule is the fix for v3's largest defect, where path-derived entity
    /// identity produced 81% duplicates.
    Mint {
        #[arg(long)]
        path: String,
        /// Parse, derive and report without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Replay moments out of a committed exhibit through the shared write path.
    MigrateBatch {
        /// Path to the frozen corpus (must already be committed).
        path: String,
        #[arg(long)]
        exhibit: String,
        /// How many source rows to replay.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// Replay the v1 `edges` block out of a committed exhibit as typed edges.
    ///
    /// Same corpus, same write path, same `ExhibitRef` discipline as
    /// `migrate-batch` — the only new thing is that an edge names two entities
    /// instead of one, so it needs both endpoints' coordinates before it can be
    /// pinned to a coordinate of its own (see `node_coords`).
    MigrateEdges {
        /// Path to the frozen corpus (must already be committed).
        path: String,
        #[arg(long)]
        exhibit: String,
        /// How many source edge rows to consider. `0` means every row.
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
        /// Report the mapping histogram and write nothing. Needs no database.
        #[arg(long)]
        dry_run: bool,
        /// Print a progress line every N source rows.
        #[arg(long, default_value_t = 25_000)]
        progress: usize,
    },
    /// Derive the governed claim-type vocabulary from the exhibit's own tags.
    ///
    /// `Admiss(c, t_q)` cannot hold against an empty vocabulary, so without this
    /// the filter's positive branch is unreachable no matter what the corpus
    /// says. The bands are **measured, not invented**: each `tax:` tag's band
    /// begins at the earliest coordinate of any node carrying it. That is a
    /// claim the exhibit actually supports — "the record first classifies
    /// something this way here" — where a hand-written band would be this
    /// migrator inventing governance.
    DeclareVocabulary {
        /// Path to the frozen corpus (must already be committed).
        path: String,
        #[arg(long)]
        exhibit: String,
        /// Report the derived vocabulary and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Validate a TT classification profile; the same contract as
    /// telemetry's `tt_validate.py`, so the two can be diffed on identical
    /// input. Exit 0 and the normalized profile, or exit 1 and one typed
    /// rejection per line on stderr. Needs no database.
    Classify {
        /// Path to a classification JSON file, or `-` for stdin.
        path: String,
        /// Instead of validating input, BUILD the profile a single-type claim
        /// implies — one entry at mass 1.0, in the lens the bundle assigns.
        /// Keeps lens lookup in one place: a generation pipeline that derived
        /// the lens itself would be a second copy of a bundle fact.
        #[arg(long)]
        from_type: Option<String>,
    },
    /// Summarize the ledger.
    Status,
    /// Replay another node's events into this one and prove the views converge.
    ///
    /// This is the initiation phase's boundary condition (M6): a second node is
    /// nothing but "replay the other node's events", and if that is true then a
    /// Growth-epoch mirror needs no new machinery — only a transport. Nothing
    /// privileged crosses: every event is re-parsed, its `H0` recomputed, its
    /// signature re-verified, and it is applied through the same `commit` any
    /// writer uses. A tampered row is loud corruption, not a silent fold.
    Mirror {
        /// Source node's `DATABASE_URL`. Read-only; never written to.
        #[arg(long)]
        from: String,
    },
}

fn db_url() -> Result<String> {
    std::env::var("DATABASE_URL").context("DATABASE_URL must be set")
}

/// The migrator's signing identity — *an* identity, never a privileged one.
fn migrator_key() -> Result<SecretKey> {
    let hex_seed = std::env::var("MIGRATOR_SECRET_KEY")
        .context("MIGRATOR_SECRET_KEY must be set (see `cc-migrator keygen`)")?;
    let raw = hex::decode(hex_seed.trim()).context("MIGRATOR_SECRET_KEY must be hex")?;
    let seed: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("MIGRATOR_SECRET_KEY must be 32 bytes"))?;
    Ok(SecretKey::from_seed(seed))
}

/// Narrow a stored bytea to a fixed 32-byte array, or say which column was wrong.
fn as32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| anyhow::anyhow!("{what} width != 32"))
}

/// Stream-hash a file. The exhibit is gigabytes, so it never lands in memory
/// whole — and nothing transforms it on the way past, because an external
/// `shasum -a 256` written at capture time has to agree.
fn hash_file(path: &str) -> Result<(ExhibitId, u64)> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {path}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((ExhibitId(digest), total))
}

// ===========================================================================
// Reading the exhibit — byte-offset preserving, never transforming
// ===========================================================================

/// One source row plus the byte offset it starts at, so a migrated entry can
/// point at exactly where in the frozen corpus it came from.
struct ExhibitRow {
    offset: u64,
    line: String,
}

/// The COPY headers this migration reads. The trailing space is load-bearing:
/// the same dump also holds `public.edge_cleanup_audit`, `public.node_figures`
/// and `public.node_dating_audit`, and a prefix match without it would silently
/// start replaying the wrong table.
const NODES_COPY: &str = "COPY public.nodes ";
const EDGES_COPY: &str = "COPY public.edges ";

/// Streams one COPY block out of a pg_dump. Never rewrites the bytes: the
/// exhibit is the object under measurement (§bootstrap), so this reads and
/// offsets, and does nothing else to it.
struct ExhibitRows {
    reader: std::io::BufReader<std::fs::File>,
    offset: u64,
    /// The COPY header this pass is looking for; rows before it are skipped.
    header: &'static str,
    started: bool,
    done: bool,
}

impl ExhibitRows {
    /// The `public.nodes` block — what `migrate-batch` replays.
    fn open(path: &str) -> Result<ExhibitRows> {
        ExhibitRows::open_block(path, NODES_COPY)
    }

    /// Any one COPY block, named by its header.
    ///
    /// Each call is its own pass over the file, and that is not an accident to
    /// optimize away: pg_dump writes `public.edges` *before* `public.nodes`, so
    /// an edge row is read ~427 MB before the endpoint coordinates it depends
    /// on. One handle cannot serve both in dependency order.
    fn open_block(path: &str, header: &'static str) -> Result<ExhibitRows> {
        let f = std::fs::File::open(path).with_context(|| format!("open {path}"))?;
        Ok(ExhibitRows {
            reader: std::io::BufReader::with_capacity(1 << 20, f),
            offset: 0,
            header,
            started: false,
            done: false,
        })
    }
}

impl Iterator for ExhibitRows {
    type Item = Result<ExhibitRow>;

    fn next(&mut self) -> Option<Result<ExhibitRow>> {
        use std::io::BufRead;
        loop {
            if self.done {
                return None;
            }
            let start = self.offset;
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Err(e) => return Some(Err(e.into())),
                Ok(0) => return None,
                Ok(n) => self.offset += n as u64,
            }
            if !self.started {
                if line.starts_with(self.header) {
                    self.started = true;
                }
                continue;
            }
            // pg_dump terminates a COPY block with a lone backslash-dot.
            if line.starts_with("\\.") {
                self.done = true;
                return None;
            }
            return Some(Ok(ExhibitRow {
                offset: start,
                line: line.trim_end().to_string(),
            }));
        }
    }
}

/// The fields this migration reads out of a v1 node row. The corpus is dirty by
/// design — text-typed dates, sentinel coordinates, 200-char truncation — and
/// none of that is repaired here.
struct SourceNode {
    path: String,
    name: String,
    event_time: Tick,
    /// The entity's evidenced start, which is NOT always `event_time`: 47% of
    /// legacy paths carry sentinel garbage, and a row whose date will not parse
    /// evidences no start at all.
    window_start: WindowStart,
}

impl SourceNode {
    fn parse(line: &str) -> Option<SourceNode> {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            return None;
        }
        let path = f[0].to_string();
        if path.is_empty() || path == "\\N" {
            return None;
        }
        let name = if f[2] == "\\N" {
            String::new()
        } else {
            f[2].to_string()
        };
        let dated = v1_coordinate(f[3], f[5], f[6]);
        Some(SourceNode {
            path,
            name,
            // An undated row still needs SOME coordinate for its moment, because
            // an event without an event_time is not representable — ORIGIN is
            // used, and is visibly a non-answer. The entity's window is a
            // different question, and there the record's silence is sayable.
            event_time: dated.unwrap_or(Tick::ORIGIN),
            window_start: match dated {
                Some(t) => WindowStart::Known(t),
                None => WindowStart::Unknown,
            },
        })
    }
}

/// Map a v1 row's text-typed year/month/day to a coordinate, or `None`.
///
/// v1 stored these as TEXT and 47% of legacy paths carry sentinel garbage
/// (memo §2). An unparseable date is NOT guessed and NOT quietly resolved to
/// Clock Zero: a wrong coordinate is a false claim about when something
/// happened, and `ORIGIN` is a claim too — that the subject dates from the
/// origin of the axis. Returning `None` pushes the choice to the caller, which
/// is the only place that knows whether the field being filled can express
/// silence.
fn v1_coordinate(year: &str, month_num: &str, day: &str) -> Option<Tick> {
    let Ok(y) = year.trim().parse::<i64>() else {
        return None;
    };
    let m = month_num.trim().parse::<i64>().unwrap_or(1).clamp(1, 12);
    let d = day.trim().parse::<i64>().unwrap_or(1).clamp(1, 31);
    // Proleptic Gregorian day number, then seconds from J2000.0 (noon).
    let a = (14 - m) / 12;
    let yy = y + 4800 - a;
    let mm = m + 12 * a - 3;
    let jdn = d + (153 * mm + 2) / 5 + 365 * yy + yy / 4 - yy / 100 + yy / 400 - 32045;
    let secs = (jdn - 2_451_545) * 86_400 - 43_200;
    Some(Tick::from_whole_ticks(secs, B256Constants::V0.split))
}

/// A stable positive `entity_id` derived from the v1 path, so re-running the
/// migration resolves the same source row to the same entity. Never 0: that is
/// reserved for node 0.
fn stable_entity_id(path: &str) -> i64 {
    let d = Sha256::digest(path.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    (i64::from_be_bytes(b) & i64::MAX).max(1)
}

// ===========================================================================
// Edges — the v1 `edges` block, replayed as typed relations
// ===========================================================================

/// What an edge endpoint needs from the `nodes` block: the entity its v1 path
/// resolves to, and the coordinate that entity's moment was migrated at.
#[derive(Clone, Copy)]
struct Endpoint {
    entity: i64,
    coord: Tick,
}

/// The fields this migration reads out of a v1 edge row.
///
/// The row also carries `weight`, `theme`, `description`, `created_by` and
/// `schema_version`; all five are read past and dropped. `weight` is the one
/// worth naming: [`EdgeBody`] has no field for it, and that is deliberate —
/// a Φ *magnitude* is non-consensus, so a number one writer attached to an
/// association cannot ride into another node's fold as if it were agreed. The
/// claim that survives is "these two co-occur", not "these two co-occur 0.7".
/// Nothing is lost that the exhibit does not still hold: every event carries an
/// [`ExhibitRef`] to the exact byte offset the weight is written at.
struct SourceEdge<'a> {
    source: &'a str,
    target: &'a str,
    /// v1's `type` column — an untyped string, which is the thing being fixed.
    kind: &'a str,
}

impl<'a> SourceEdge<'a> {
    fn parse(line: &'a str) -> Option<SourceEdge<'a>> {
        let mut f = line.split('\t');
        let source = f.next()?;
        let target = f.next()?;
        let kind = f.next()?;
        if source.is_empty()
            || source == "\\N"
            || target.is_empty()
            || target == "\\N"
            || kind.is_empty()
        {
            return None;
        }
        Some(SourceEdge {
            source,
            target,
            kind,
        })
    }
}

/// The verdict on one v1 `type` string.
enum Mapped {
    /// Emit with the row's own direction.
    Forward(EdgeRelation),
    /// Emit with `src`/`dst` SWAPPED, because the v1 name states the converse.
    Converse(EdgeRelation),
    /// In v1's vocabulary and deliberately not migrated. See `map_relation`.
    Withheld,
}

/// Map a v1 `type` string onto the governed [`EdgeRelation`] vocabulary, or
/// `None` if v1 said something this build has no word for.
///
/// Six of v1's names are co-occurrence claims under different axes — a shared
/// participant, era, theme, place or conflict — and co-occurrence along some
/// axis is exactly what `B(t)` is, so they all land on `CoOccurrence`. The axis
/// itself is not preserved, because the vocabulary has no slot for it; it is
/// still in the exhibit at the recorded offset.
///
/// **`precedes` and `follows` are withheld, not mapped.** They are the one
/// judgment in this function that is not mechanical, so it is stated rather
/// than buried: a temporal-ordering claim is not a co-occurrence claim, and
/// `cc-core` has no relation for sequence. Folding 207,762 ordering assertions
/// into `CoOccurrence` would put a claim in the ledger that the source never
/// made — and `Known_k` reads this relation directly, so the fabrication would
/// not sit inertly, it would manufacture evidenced walks. Ordering is real and
/// worth having; it needs a governed relation (a `Precedence` variant, or the
/// pair recorded as a coordinate comparison rather than an edge). **This is an
/// open governance question, not an oversight** — when the vocabulary gains a
/// word for sequence, these rows are still in the exhibit, unaltered, and this
/// command replays them by changing one match arm.
///
/// `caused_by` is v1's converse spelling of `causes`; it is emitted with the
/// endpoints swapped so that direction on a `Causation` edge means one thing.
fn map_relation(v1_type: &str) -> Option<Mapped> {
    Some(match v1_type {
        "same_figure" | "same_era" | "thematic" | "contemporaneous" | "same_location"
        | "same_conflict" => Mapped::Forward(EdgeRelation::CoOccurrence),
        "influences" => Mapped::Forward(EdgeRelation::Influence),
        "causes" => Mapped::Forward(EdgeRelation::Causation),
        "caused_by" => Mapped::Converse(EdgeRelation::Causation),
        "precedes" | "follows" => Mapped::Withheld,
        // Never guessed. An unknown string is counted and reported, because a
        // relation invented at migration time is indistinguishable, downstream,
        // from one the corpus actually asserted.
        _ => return None,
    })
}

/// Field index of `tags` in the v1 `public.nodes` COPY block.
const TAGS_FIELD: usize = 15;

/// Split a Postgres text-array literal into its taxonomy tags.
///
/// Only `tax:`-prefixed entries become claim types. v1 mixed free-form topical
/// tags ("space", "nasa") with a curated `tax:` namespace in one column, and the
/// free-form ones are folksonomy, not a governed vocabulary — promoting them
/// would make `Admiss` answer to whatever anyone once typed.
fn parse_tags(field: &str) -> Vec<String> {
    let t = field.trim();
    if t.is_empty() || t == "\\N" {
        return Vec::new();
    }
    t.trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| s.starts_with("tax:"))
        .collect()
}

/// A stable claim-type code for a label.
///
/// Delegates to `cc-filter`, which is where the query boundary reads it from as
/// well. Two copies of an identity function is one too many: they agree until
/// somebody edits one, and then the writer and the reader disagree about what a
/// tag means with nothing failing in between.
fn claim_code(label: &str) -> u32 {
    cc_filter::version::claim_code(label)
}

/// The stored discriminant's name, for the histogram only — never a key.
fn relation_name(r: EdgeRelation) -> &'static str {
    match r {
        EdgeRelation::CoOccurrence => "CoOccurrence",
        EdgeRelation::Influence => "Influence",
        EdgeRelation::Causation => "Causation",
        EdgeRelation::Participation => "Participation",
        EdgeRelation::Attestation => "Attestation",
        EdgeRelation::Supersession => "Supersession",
    }
}

/// Index the `public.nodes` block by v1 path.
///
/// This is the first of the two passes `ExhibitRows::open_block` documents, and
/// the only thing this migration holds in memory: ~24k entries, bounded by the
/// node count, while the 1.5M-row `edges` block still streams.
///
/// The coordinate stored here is [`SourceNode`]'s `event_time` — computed by
/// the same parse `migrate-batch` used — so an edge is pinned to a coordinate
/// its endpoints were actually migrated at, rather than to a second, subtly
/// different reading of the same dirty date fields.
fn node_coords(path: &str) -> Result<HashMap<String, Endpoint>> {
    let mut map: HashMap<String, Endpoint> = HashMap::new();
    for row in ExhibitRows::open_block(path, NODES_COPY)? {
        let row = row?;
        let Some(node) = SourceNode::parse(&row.line) else {
            continue;
        };
        let endpoint = Endpoint {
            entity: stable_entity_id(&node.path),
            coord: node.event_time,
        };
        map.insert(node.path, endpoint);
    }
    Ok(map)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Migrate => {
            let pool = cc_ledger::connect(&db_url()?).await?;
            cc_ledger::run_migrations(&pool).await?;
            println!("migrations applied");
        }

        Cmd::Keygen => {
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
            let sk = SecretKey::from_seed(seed);
            println!("MIGRATOR_SECRET_KEY={}", hex::encode(seed));
            println!("public={}", hex::encode(sk.author().to_bytes()));
        }

        Cmd::CommitExhibit { path, note } => {
            let (id, len) = hash_file(&path)?;
            let pool = cc_ledger::connect(&db_url()?).await?;
            sqlx::query(
                "INSERT INTO exhibits (exhibit_id, byte_len, source_note) \
                 VALUES ($1,$2,$3) ON CONFLICT (exhibit_id) DO NOTHING",
            )
            .bind(id.as_bytes().to_vec())
            .bind(len as i64)
            .bind(&note)
            .execute(&pool)
            .await?;
            println!("exhibit {}", id.to_hex());
            println!("  bytes {len}");
            println!("  note  {note}");
        }

        Cmd::Genesis { exhibit } => {
            let pool = cc_ledger::connect(&db_url()?).await?;

            // An exhibit is optional, but if one is named it must already be
            // committed — a provenance pointer that dangles is worse than no
            // pointer, because it reads as sourced.
            let exhibit_id = match exhibit.as_deref() {
                Some(hex_str) => {
                    let raw = hex::decode(hex_str.trim()).context("--exhibit must be hex")?;
                    let bytes: [u8; 32] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("--exhibit must be 32 bytes"))?;
                    let id = ExhibitId(bytes);
                    let known: i64 =
                        sqlx::query("SELECT count(*) FROM exhibits WHERE exhibit_id = $1")
                            .bind(id.as_bytes().to_vec())
                            .fetch_one(&pool)
                            .await?
                            .get(0);
                    if known == 0 {
                        bail!(
                            "exhibit {} is not committed; run commit-exhibit first",
                            id.to_hex()
                        );
                    }
                    Some(id)
                }
                None => None,
            };

            let sk = migrator_key()?;
            let author: AuthorKey = sk.author();
            let rt = now_tick();

            // Node 0 as a first-class entity, so the ledger's governance is part
            // of the history it keeps rather than configuration beside it.
            let birth = EventContent {
                event_time: rt,
                record_time: rt,
                author,
                supersedes: None,
                body: EventBody::EntityCreate(EntityBirth {
                    entity_id: NODE_ZERO,
                    resolution_key: "node-0".into(),
                    canonical_name: "Clockchain node 0".into(),
                    window: ExistenceWindow {
                        start: WindowStart::Known(rt),
                        end: WindowEnd::KnownOpen,
                    },
                }),
            };
            let signed = Signed::sign(&sk, birth);
            let a = cc_ledger::commit(&pool, &signed).await?;
            println!("node-0 entity     {} {:?}", signed.id().to_hex(), a);

            // The exhibit commitment, carrying a provenance pointer at offset 0 —
            // the whole corpus is its source. Absent on a chain born clean.
            match exhibit_id {
                Some(exhibit_id) => {
                    let m1 = EventContent {
                        event_time: rt,
                        record_time: rt,
                        author,
                        supersedes: None,
                        body: EventBody::Moment(MomentBody {
                            subject: NODE_ZERO,
                            body_hash: body_hash("exhibit_commit", &exhibit_id.to_hex()),
                        }),
                    };
                    let s1 = Signed::sign(&sk, m1);
                    let a1 = cc_ledger::commit_with_provenance(
                        &pool,
                        &s1,
                        Some(ExhibitRef {
                            exhibit: exhibit_id,
                            offset: 0,
                        }),
                    )
                    .await?;
                    println!("exhibit moment    {} {:?}", s1.id().to_hex(), a1);
                }
                None => println!("exhibit moment    (none — chain born without a corpus)"),
            }

            // The governed constants, so a coordinate is only ever interpretable
            // against a recorded constants set.
            // The recorded filter version is the one THIS build runs, read out
            // of cc-filter rather than restated here. A constant would let the
            // ledger's founding moment disagree with the rule the node applies.
            let fv = FilterVersionId(*cc_filter::v0_version().as_bytes());
            let c = ProtocolConstants::v0(fv);
            let constants = format!(
                "clock_zero={};tick={};split={};anchor={};filter_version={}",
                c.b256.clock_zero,
                c.b256.tick,
                c.b256.split.0,
                c.b256.anchor_chain,
                c.filter_version.to_hex()
            );
            let m2 = EventContent {
                event_time: rt,
                record_time: rt,
                author,
                supersedes: None,
                body: EventBody::Moment(MomentBody {
                    subject: NODE_ZERO,
                    body_hash: body_hash("protocol_constants_v0", &constants),
                }),
            };
            let s2 = Signed::sign(&sk, m2);
            let a2 = cc_ledger::commit(&pool, &s2).await?;
            println!("constants moment  {} {:?}", s2.id().to_hex(), a2);
            println!("  {constants}");
        }

        Cmd::Mint { path, dry_run } => {
            let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
            // Either a bare array of entries, or {entries, edges}. Edges are
            // optional because a batch of claims with no asserted relations is
            // a real thing to mint; a batch that SILENTLY dropped its edges
            // would not be.
            let parsed: serde_json::Value =
                serde_json::from_str(&text).context("input must be JSON")?;
            let (items, edge_specs): (Vec<serde_json::Value>, Vec<serde_json::Value>) =
                match &parsed {
                    serde_json::Value::Array(a) => (a.clone(), Vec::new()),
                    serde_json::Value::Object(o) => (
                        o.get("entries")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .context("object form needs an `entries` array")?,
                        o.get("edges")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default(),
                    ),
                    _ => bail!("input must be a JSON array or an object"),
                };

            // ---- the gate, before anything is signed or connected to --------
            //
            // Runs first so a rejected batch costs nothing and touches nothing.
            // All-or-nothing: "every entry has to be perfect" is a property of
            // the batch, and a partial mint would also strand this batch's edges
            // on titles that never landed, degrading the graph silently.
            let verdicts = admission::admit_batch(&items);
            if !verdicts.is_empty() {
                let mut by_entry: BTreeMap<usize, Vec<String>> = BTreeMap::new();
                for (i, r) in &verdicts {
                    by_entry.entry(*i).or_default().push(r.to_string());
                }
                eprintln!(
                    "REFUSED — {} of {} entries failed admission, {} rejections. Nothing was minted.",
                    by_entry.len(),
                    items.len(),
                    verdicts.len()
                );
                for (i, rs) in &by_entry {
                    let name = items[*i]["title"].as_str().unwrap_or("(no title)");
                    eprintln!("\n  [{i}] {name}");
                    for r in rs {
                        eprintln!("      {r}");
                    }
                }
                let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
                for (_, r) in &verdicts {
                    *counts.entry(r.rule).or_default() += 1;
                }
                eprintln!("\n  by rule:");
                for (rule, n) in &counts {
                    eprintln!("      {n:>4}  {rule}");
                }
                bail!("admission refused the batch");
            }
            println!("admission: {} of {} entries pass", items.len(), items.len());

            // The abstention count, reported at mint. TT's denominator rule:
            // an abstention RATE divides by moments actually put to the
            // classifier, never by all moments — "declined" and "never asked"
            // are different facts. This batch IS that denominator, so the two
            // numbers are printed together and never as a bare percentage.
            let profiled = items
                .iter()
                .filter(|e| e.get("classification").is_some())
                .count();
            if profiled > 0 {
                let abstained = items
                    .iter()
                    .filter_map(|e| e.get("classification"))
                    .filter(|c| classification::is_abstention(c))
                    .count();
                println!(
                    "classification: {abstained} abstained of {profiled} put to the classifier \
                     ({} entries carried no profile)",
                    items.len() - profiled
                );
            }

            // There was a non-blocking advisory pass here (`scale-mismatch-review`).
            // Telemetry ruled it deleted rather than patched — see the note in
            // `admission.rs`. Nothing replaces it: the honest interim control is
            // a human-review queue for B-primary claims, or nothing, and this is
            // nothing on purpose.

            let pool = cc_ledger::connect(&db_url()?).await?;
            let sk = migrator_key()?;
            let author: AuthorKey = sk.author();
            let rt = now_tick();

            let mut tx = pool.begin().await?;
            let (mut ents, mut moms, mut union) = (0u64, 0u64, 0u64);
            for it in &items {
                let title = it["title"].as_str().context("entry has no title")?;
                let year = it["year"].as_i64().context("entry has no year")?;
                let known = it["date_is_known"].as_bool().unwrap_or(true);

                // Identity from the claim, so two writers asserting the same
                // event converge on one entity rather than minting two.
                let (entity_id, d) = claim_identity(title, year);

                let at = year_tick(year);
                let window = ExistenceWindow {
                    // An unknown start is a TYPED unknown, never a guessed
                    // coordinate. A process dated to one year has no known
                    // start, and recording one would assert precision the
                    // evidence does not carry.
                    start: if known {
                        WindowStart::Known(at)
                    } else {
                        WindowStart::Unknown
                    },
                    // No cessation is recorded and none is implied.
                    end: WindowEnd::UnknownClosure,
                };

                if dry_run {
                    println!("{entity_id:>20}  {year:>6}  {title}");
                    continue;
                }

                let birth = EventContent {
                    event_time: at,
                    record_time: rt,
                    author,
                    supersedes: None,
                    body: EventBody::EntityCreate(EntityBirth {
                        entity_id,
                        resolution_key: format!("claim:{}", hex::encode(&d[0..16])),
                        canonical_name: title.to_string(),
                        window,
                    }),
                };
                let s = Signed::sign(&sk, birth);
                match cc_ledger::commit_in_tx(&mut tx, &s, None).await? {
                    a if a.is_new() => ents += 1,
                    _ => union += 1,
                }

                // The moment carries the whole claim, provenance included, so
                // the body hash commits to what was asserted AND to how it was
                // produced. A body hash over the prose alone would let the
                // provenance drift without changing identity.
                let moment = EventContent {
                    event_time: at,
                    record_time: rt,
                    author,
                    supersedes: None,
                    body: EventBody::Moment(MomentBody {
                        subject: entity_id,
                        body_hash: body_hash("claim_v4", &it.to_string()),
                    }),
                };
                let sm = Signed::sign(&sk, moment);
                if cc_ledger::commit_in_tx(&mut tx, &sm, None).await?.is_new() {
                    moms += 1;
                }

                // Keep the bytes the hash commits to. Without this the claim's
                // provenance — which model, which run, which bundle — is
                // committed to and unreadable, which is a worse position than
                // v2's, where at least a text_model column could be queried.
                //
                // Written AFTER the commit and keyed by the same hash, so it is
                // an attachment to a settled claim rather than a parallel truth.
                // ON CONFLICT DO NOTHING because the hash is the identity: the
                // same bytes arriving twice is convergence, not a collision.
                sqlx::query(
                    "INSERT INTO claim_bodies (body_hash, body) VALUES ($1, $2) \
                     ON CONFLICT (body_hash) DO NOTHING",
                )
                .bind(body_hash("claim_v4", &it.to_string()).to_vec())
                .bind(it.to_string())
                .execute(&mut *tx)
                .await?;
            }
            // Vocabulary before edges: `Admiss(c, t_q)` cannot hold against an
            // empty vocabulary, so without this the filter's positive branch is
            // unreachable no matter what the corpus or the graph says. That was
            // v3's bug and it reappeared in v4 the moment claims were minted
            // without declaring the types they use.
            //
            // Bands are MEASURED, not invented: a type's band opens at the
            // earliest coordinate in THIS batch carrying it. That is a claim
            // the corpus supports — "the record first classifies something this
            // way here" — where a hand-picked band would be the migrator
            // inventing governance.
            let mut first_seen: BTreeMap<String, i64> = BTreeMap::new();
            for it in &items {
                if let (Some(ct), Some(y)) = (it["claim_type"].as_str(), it["year"].as_i64()) {
                    first_seen
                        .entry(ct.to_string())
                        .and_modify(|e| *e = (*e).min(y))
                        .or_insert(y);
                }
            }
            let mut vocab_new = 0u64;
            if !dry_run {
                for (label, first_year) in &first_seen {
                    let content = EventContent {
                        event_time: year_tick(*first_year),
                        record_time: rt,
                        author,
                        supersedes: None,
                        body: EventBody::VocabularyDeclare(VocabularyEntry {
                            claim_type: claim_code(label),
                            label: label.clone(),
                            band: ExistenceWindow {
                                start: WindowStart::Known(year_tick(*first_year)),
                                // Nothing records a retirement, and silence is
                                // not confirmation that a type is current.
                                end: WindowEnd::UnknownClosure,
                            },
                        }),
                    };
                    let sv = Signed::sign(&sk, content);
                    if cc_ledger::commit_in_tx(&mut tx, &sv, None).await?.is_new() {
                        vocab_new += 1;
                    }
                }
            }

            // Edges last: both endpoints must already exist as entities, and
            // minting them in the same pass guarantees that without a lookup.
            let (mut edges_new, mut edges_conv) = (0u64, 0u64);
            for e in &edge_specs {
                let (ft, fy) = (e["from"]["title"].as_str(), e["from"]["year"].as_i64());
                let (tt, ty) = (e["to"]["title"].as_str(), e["to"]["year"].as_i64());
                let (Some(ft), Some(fy), Some(tt), Some(ty)) = (ft, fy, tt, ty) else {
                    bail!("malformed or self edge rejects entire batch");
                };
                let (src, _) = claim_identity(ft, fy);
                let (dst, _) = claim_identity(tt, ty);
                // A self-edge is a malformed assertion, not a fact about
                // history. Refused rather than stored, so the graph never
                // carries a loop nobody meant.
                if src == dst {
                    bail!("malformed or self edge rejects entire batch");
                }
                let relation = match e["relation"].as_str().context("edge relation required")? {
                    "causation" | "caused" | "causes" => EdgeRelation::Causation,
                    "participation" => EdgeRelation::Participation,
                    "influence" => EdgeRelation::Influence,
                    "co_occurrence" => EdgeRelation::CoOccurrence,
                    _ => bail!("unknown edge relation"),
                };
                if dry_run {
                    println!("edge {src:>20} -> {dst:>20}  {relation:?}");
                    continue;
                }
                let ev = EventContent {
                    // The edge takes effect at the LATER endpoint: a cause
                    // cannot be evidenced as connected to its effect before the
                    // effect exists, and dating it earlier would let a verdict
                    // pinned before the effect see the link.
                    event_time: year_tick(fy.max(ty)),
                    record_time: rt,
                    author,
                    supersedes: None,
                    body: EventBody::Edge(EdgeBody {
                        src,
                        dst,
                        relation,
                        // A model said so. Not a document, not an inference
                        // over evidence we hold — an assertion, and the
                        // evidence class says exactly that from birth.
                        evidence_class: EvidenceClass::Assertion,
                    }),
                };
                let se = Signed::sign(&sk, ev);
                if cc_ledger::commit_in_tx(&mut tx, &se, None).await?.is_new() {
                    edges_new += 1;
                } else {
                    edges_conv += 1;
                }
            }

            if !dry_run {
                tx.commit().await?;
            }
            if dry_run {
                println!(
                    "\ndry run: {} entries, {} edges, nothing written",
                    items.len(),
                    edge_specs.len()
                );
            } else {
                println!(
                    "minted {} entities ({} converged onto existing), {} moments, from {} entries",
                    ents,
                    union,
                    moms,
                    items.len()
                );
                println!("minted {edges_new} edges ({edges_conv} converged)");
                println!(
                    "declared {vocab_new} vocabulary entries of {} distinct claim types",
                    first_seen.len()
                );
            }
        }

        Cmd::MigrateBatch {
            path,
            exhibit,
            limit,
        } => {
            let raw = hex::decode(exhibit.trim()).context("--exhibit must be hex")?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("--exhibit must be 32 bytes"))?;
            let exhibit_id = ExhibitId(bytes);

            let pool = cc_ledger::connect(&db_url()?).await?;
            let known: i64 = sqlx::query("SELECT count(*) FROM exhibits WHERE exhibit_id = $1")
                .bind(exhibit_id.as_bytes().to_vec())
                .fetch_one(&pool)
                .await?
                .get(0);
            if known == 0 {
                bail!("exhibit {} is not committed", exhibit_id.to_hex());
            }

            let sk = migrator_key()?;
            let author = sk.author();
            let record = now_tick();

            let mut new_entities = 0usize;
            let mut new_moments = 0usize;
            let mut existing = 0usize;
            let mut seen_entities: std::collections::HashSet<i64> =
                std::collections::HashSet::new();

            for row in ExhibitRows::open(&path)?.take(limit) {
                let row = row?;
                let Some(node) = SourceNode::parse(&row.line) else {
                    continue;
                };

                // One entity per source node, resolved by its v1 path. Proper
                // entity extraction (figures -> first-class entities) is the
                // resolve() step and is deliberately NOT done here: v1 stored
                // figures as in-row role strings, the "entities as decoration"
                // anti-pattern (memo §10), and inventing entities from them
                // would fabricate resolution the source never had.
                let entity_id = stable_entity_id(&node.path);
                if seen_entities.insert(entity_id) {
                    let birth = EventContent {
                        event_time: node.event_time,
                        record_time: record,
                        author,
                        supersedes: None,
                        body: EventBody::EntityCreate(EntityBirth {
                            entity_id,
                            resolution_key: node.path.clone(),
                            canonical_name: node.name.clone(),
                            // No cessation is recorded in v1 and none is implied.
                            // UnknownClosure, never KnownOpen: "no recorded
                            // cessation" and "confirmed active" must not merge.
                            window: ExistenceWindow {
                                start: node.window_start,
                                end: WindowEnd::UnknownClosure,
                            },
                        }),
                    };
                    let signed = Signed::sign(&sk, birth);
                    if cc_ledger::commit_with_provenance(
                        &pool,
                        &signed,
                        Some(ExhibitRef {
                            exhibit: exhibit_id,
                            offset: row.offset,
                        }),
                    )
                    .await?
                    .is_new()
                    {
                        new_entities += 1;
                    }
                }

                let moment = EventContent {
                    event_time: node.event_time,
                    record_time: record,
                    author,
                    supersedes: None,
                    body: EventBody::Moment(MomentBody {
                        subject: entity_id,
                        body_hash: body_hash("v1_node", &row.line),
                    }),
                };
                let signed = Signed::sign(&sk, moment);
                if cc_ledger::commit_with_provenance(
                    &pool,
                    &signed,
                    Some(ExhibitRef {
                        exhibit: exhibit_id,
                        offset: row.offset,
                    }),
                )
                .await?
                .is_new()
                {
                    new_moments += 1;
                } else {
                    existing += 1;
                }
            }

            println!("replayed from {}", exhibit_id.to_hex());
            println!("  entities new {new_entities}");
            println!("  moments  new {new_moments}");
            println!("  already present {existing}   (idempotent re-run)");
        }

        Cmd::MigrateEdges {
            path,
            exhibit,
            limit,
            dry_run,
            progress,
        } => {
            let raw = hex::decode(exhibit.trim()).context("--exhibit must be hex")?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("--exhibit must be 32 bytes"))?;
            let exhibit_id = ExhibitId(bytes);

            // A dry run answers the mapping question out of the corpus alone, so
            // it takes no database, no key, and no write path — which is what
            // makes it usable as a check on the mapping BEFORE anything is
            // committed anywhere.
            let writer = if dry_run {
                None
            } else {
                let pool = cc_ledger::connect(&db_url()?).await?;
                let known: i64 = sqlx::query("SELECT count(*) FROM exhibits WHERE exhibit_id = $1")
                    .bind(exhibit_id.as_bytes().to_vec())
                    .fetch_one(&pool)
                    .await?
                    .get(0);
                if known == 0 {
                    bail!("exhibit {} is not committed", exhibit_id.to_hex());
                }
                Some((pool, migrator_key()?))
            };

            let clock = Instant::now();
            let coords = node_coords(&path)?;
            println!(
                "indexed {} nodes from {} in {:.1}s",
                coords.len(),
                exhibit_id.to_hex(),
                clock.elapsed().as_secs_f64()
            );

            let record = now_tick();
            let cap = if limit == 0 { usize::MAX } else { limit };
            let every = progress.max(1) as u64;

            let mut v1_types: BTreeMap<String, u64> = BTreeMap::new();
            let mut relations: BTreeMap<&'static str, u64> = BTreeMap::new();
            let mut rows_read = 0u64;
            let mut malformed = 0u64;
            let mut unrecognized = 0u64;
            let mut withheld = 0u64;
            let mut unresolved = 0u64;
            let mut self_loops = 0u64;
            let mut new_edges = 0u64;
            let mut already = 0u64;
            let mut in_run_dupes = 0u64;

            // An `H0` already emitted in THIS run names the same event, so
            // committing it again is a union no-op by construction and the round
            // trip is pure cost. v1's vocabulary is redundant (`same_era` and
            // `contemporaneous` on one pair are one CoOccurrence claim), so this
            // is a large fraction of the block. Reported separately from
            // "already present" so the two are never confused.
            let mut emitted: HashSet<[u8; 32]> = HashSet::new();

            let run = Instant::now();
            for row in ExhibitRows::open_block(&path, EDGES_COPY)?.take(cap) {
                let row = row?;
                rows_read += 1;
                if rows_read.is_multiple_of(every) {
                    let secs = run.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
                    println!(
                        "  {rows_read:>9} rows  {new_edges:>9} new  {:>7.0} rows/s  {secs:>6.0}s",
                        rows_read as f64 / secs
                    );
                }

                let Some(edge) = SourceEdge::parse(&row.line) else {
                    malformed += 1;
                    continue;
                };
                *v1_types.entry(edge.kind.to_string()).or_default() += 1;

                let Some(mapping) = map_relation(edge.kind) else {
                    unrecognized += 1;
                    continue;
                };
                let (relation, src_path, dst_path) = match mapping {
                    Mapped::Withheld => {
                        withheld += 1;
                        continue;
                    }
                    Mapped::Forward(r) => (r, edge.source, edge.target),
                    Mapped::Converse(r) => (r, edge.target, edge.source),
                };

                let (Some(src), Some(dst)) = (coords.get(src_path), coords.get(dst_path)) else {
                    // An endpoint v1 never had a node for. Skipped rather than
                    // birthed: inventing an entity from a dangling path would
                    // fabricate resolution the corpus never had (memo §10).
                    unresolved += 1;
                    continue;
                };
                if src.entity == dst.entity {
                    // v1 has no self-referential rows and the `no_self_loop`
                    // CHECK would reject one anyway; this is here so a hash
                    // collision surfaces as a counted skip instead of aborting
                    // a multi-hundred-thousand-row run.
                    self_loops += 1;
                    continue;
                }
                *relations.entry(relation_name(relation)).or_default() += 1;

                let Some((pool, sk)) = &writer else {
                    continue; // dry run: everything above, nothing below
                };

                let content = EventContent {
                    // An edge is evidenced at a coordinate, and it cannot be
                    // evidenced before both the things it relates exist — so the
                    // LATER endpoint coordinate, never the earlier and never the
                    // record-time.
                    event_time: src.coord.max(dst.coord),
                    record_time: record,
                    author: sk.author(),
                    supersedes: None,
                    body: EventBody::Edge(EdgeBody {
                        src: src.entity,
                        dst: dst.entity,
                        relation,
                        // These are v1's own machine-generated associations —
                        // `created_by` on every row is `auto` — not documents and
                        // not a cited secondary source. `Inference` is the class
                        // that says so, and it is what gives a challenge
                        // something to aim at: an edge that claims to be a
                        // PrimaryDocument cannot be argued with on the right
                        // grounds.
                        evidence_class: EvidenceClass::Inference,
                    }),
                };
                let signed = Signed::sign(sk, content);
                if !emitted.insert(*signed.id().as_bytes()) {
                    in_run_dupes += 1;
                } else if cc_ledger::commit_with_provenance(
                    pool,
                    &signed,
                    Some(ExhibitRef {
                        exhibit: exhibit_id,
                        offset: row.offset,
                    }),
                )
                .await?
                .is_new()
                {
                    new_edges += 1;
                } else {
                    already += 1;
                }
            }

            let secs = run.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
            println!("\nv1 `type` histogram ({rows_read} source rows read)");
            for (k, n) in &v1_types {
                println!("  {n:>9}  {k}");
            }
            println!("\nmapped to EdgeRelation");
            for (k, n) in &relations {
                println!("  {n:>9}  {k}");
            }
            println!("\nnot migrated");
            println!("  {withheld:>9}  withheld (precedes/follows — no relation for sequence)");
            println!("  {unrecognized:>9}  unrecognized v1 type (never guessed)");
            println!("  {unresolved:>9}  endpoint not in the nodes block");
            println!("  {self_loops:>9}  self-loop after entity resolution");
            println!("  {malformed:>9}  unparseable row");
            if dry_run {
                println!("\nDRY RUN — nothing written");
            } else {
                println!("\nwritten to the ledger");
                println!("  {new_edges:>9}  edge events created");
                println!("  {already:>9}  already present (idempotent re-run)");
                println!(
                    "  {in_run_dupes:>9}  duplicate H0 within this run (union no-ops, skipped)"
                );
            }
            println!(
                "\n{rows_read} rows in {secs:.0}s = {:.0} rows/s",
                rows_read as f64 / secs
            );
        }

        Cmd::Mirror { from } => {
            let src = cc_ledger::connect(&from).await?;
            let dst = cc_ledger::connect(&db_url()?).await?;

            // Ordered by (event_time, event_id) — the canonical fold order — but
            // the ORDER is a convenience for progress reporting, not a
            // requirement. Convergence must not depend on it, which is exactly
            // what comparing view_root at the end tests.
            let rows = sqlx::query(
                "SELECT event_id, author_key, signature, event_time, record_time, payload \
                 FROM events ORDER BY event_time, event_id",
            )
            .fetch_all(&src)
            .await?;
            println!("source holds {} events", rows.len());

            let mut applied = 0u64;
            let mut already = 0u64;
            for r in &rows {
                let author = cc_core::AuthorKey::from_bytes(&as32(
                    r.try_get::<Vec<u8>, _>("author_key")?,
                    "author_key",
                )?)
                .map_err(|_| anyhow::anyhow!("author_key is not a valid ed25519 key"))?;
                let event_time =
                    Tick::from_canon_bytes(as32(r.try_get::<Vec<u8>, _>("event_time")?, "et")?);
                let record_time =
                    Tick::from_canon_bytes(as32(r.try_get::<Vec<u8>, _>("record_time")?, "rt")?);
                let payload: Vec<u8> = r.try_get("payload")?;
                let sig_bytes: [u8; 64] = r
                    .try_get::<Vec<u8>, _>("signature")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("signature width != 64"))?;

                // `Signed::seal` is the peer-ingest constructor: it recomputes H0
                // from the parsed content and verifies the signature under the
                // claimed author. There is no `from_trusted` to reach for.
                let content = cc_core::parse_event(&payload, event_time, record_time, author)
                    .map_err(|e| anyhow::anyhow!("payload failed to parse: {e:?}"))?;
                let signed = Signed::seal(content, cc_core::Signature::from_bytes(sig_bytes))
                    .map_err(|e| anyhow::anyhow!("rejected by the write path: {e:?}"))?;

                if cc_ledger::commit(&dst, &signed).await?.is_new() {
                    applied += 1;
                } else {
                    already += 1;
                }
            }
            println!("  applied {applied}   already present {already}");

            let a = cc_ledger::view_root(&src).await?;
            let b = cc_ledger::view_root(&dst).await?;
            println!("source view_root {}", hex::encode(a));
            println!("mirror view_root {}", hex::encode(b));
            if a != b {
                bail!("views diverged — the mirror is NOT a replica");
            }
            println!("CONVERGED: byte-identical materialized view");
        }

        Cmd::DeclareVocabulary {
            path,
            exhibit,
            dry_run,
        } => {
            let raw = hex::decode(exhibit.trim()).context("--exhibit must be hex")?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("--exhibit must be 32 bytes"))?;
            let exhibit_id = ExhibitId(bytes);

            // tag -> (earliest coordinate seen, first byte offset that evidences it)
            let mut bands: BTreeMap<String, (Tick, u64)> = BTreeMap::new();
            let mut rows = 0u64;
            for row in ExhibitRows::open_block(&path, NODES_COPY)? {
                let row = row?;
                rows += 1;
                let f: Vec<&str> = row.line.split('\t').collect();
                if f.len() <= TAGS_FIELD {
                    continue;
                }
                // Only a dated node can evidence when a classification starts.
                // An undated one still carries the tag, but contributes no
                // coordinate — the same reason its entity gets no window start.
                let Some(node) = SourceNode::parse(&row.line) else {
                    continue;
                };
                let WindowStart::Known(coord) = node.window_start else {
                    continue;
                };
                for tag in parse_tags(f[TAGS_FIELD]) {
                    bands
                        .entry(tag)
                        .and_modify(|e| {
                            if coord < e.0 {
                                *e = (coord, row.offset);
                            }
                        })
                        .or_insert((coord, row.offset));
                }
            }
            println!("scanned {rows} nodes, found {} taxonomy tags", bands.len());

            if dry_run {
                for (tag, (coord, _)) in bands.iter().take(20) {
                    println!("  {:>10} {tag}", claim_code(tag));
                    let _ = coord;
                }
                println!("DRY RUN — nothing written");
                return Ok(());
            }

            let sk = migrator_key()?;
            let author: AuthorKey = sk.author();
            let record = now_tick();
            let pool = cc_ledger::connect(&db_url()?).await?;

            let mut new = 0u64;
            let mut existing = 0u64;
            let mut collisions = 0u64;
            let mut seen: BTreeMap<u32, String> = BTreeMap::new();
            for (tag, (coord, offset)) in &bands {
                let code = claim_code(tag);
                // A truncated hash can collide. Two labels sharing a code would
                // make one of them permanently unaskable, so it is reported
                // rather than silently overwritten.
                if let Some(prev) = seen.insert(code, tag.clone()) {
                    eprintln!("  code collision {code}: {prev:?} and {tag:?} — skipping {tag:?}");
                    collisions += 1;
                    continue;
                }
                let content = EventContent {
                    event_time: *coord,
                    record_time: record,
                    author,
                    supersedes: None,
                    body: EventBody::VocabularyDeclare(VocabularyEntry {
                        claim_type: code,
                        label: tag.clone(),
                        band: ExistenceWindow {
                            start: WindowStart::Known(*coord),
                            // The corpus records no retirement of any tag, and
                            // silence is not a confirmation that one is current.
                            end: WindowEnd::UnknownClosure,
                        },
                    }),
                };
                let signed = Signed::sign(&sk, content);
                if cc_ledger::commit_with_provenance(
                    &pool,
                    &signed,
                    Some(ExhibitRef {
                        exhibit: exhibit_id,
                        offset: *offset,
                    }),
                )
                .await?
                .is_new()
                {
                    new += 1;
                } else {
                    existing += 1;
                }
            }
            println!("declared {new} new, {existing} already present, {collisions} collisions");
        }

        Cmd::Classify { path, from_type } => {
            if let Some(ct) = from_type {
                match classification::from_single_type(&ct) {
                    Some(c) => {
                        println!("{}", serde_json::to_string_pretty(&c)?);
                        return Ok(());
                    }
                    None => {
                        eprintln!("rejected: unknown-id: {ct}: no such id in the bundle");
                        std::process::exit(1);
                    }
                }
            }
            let text = if path == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?
            };
            let v: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("rejected: not-json: {e}");
                    std::process::exit(1);
                }
            };
            match classification::validate(&v) {
                Ok(n) => println!("{}", serde_json::to_string_pretty(&n)?),
                Err(errs) => {
                    for e in errs {
                        eprintln!("{e}");
                    }
                    std::process::exit(1);
                }
            }
        }
        Cmd::Status => {
            let pool = cc_ledger::connect(&db_url()?).await?;
            let r = sqlx::query(
                "SELECT (SELECT count(*) FROM events) AS events,
                        (SELECT count(*) FROM events WHERE provenance_exhibit IS NOT NULL) AS migrated,
                        (SELECT count(*) FROM moments)  AS moments,
                        (SELECT count(*) FROM entities) AS entities,
                        (SELECT count(*) FROM exhibits) AS exhibits",
            )
            .fetch_one(&pool)
            .await?;
            println!("events    {}", r.get::<i64, _>("events"));
            println!(
                "  migrated {}   (carry an exhibit pointer)",
                r.get::<i64, _>("migrated")
            );
            println!("moments   {}", r.get::<i64, _>("moments"));
            println!("entities  {}", r.get::<i64, _>("entities"));
            println!("exhibits  {}", r.get::<i64, _>("exhibits"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrong coordinate is a permanent wrong claim, so the conversion is
    /// pinned against dates computed independently rather than trusted.
    #[test]
    fn year_tick_is_exact_for_known_epochs() {
        // Compare on the canonical bytes' integer part, via the same
        // whole-tick view the coordinate axis uses.
        let secs = |y: i64| {
            let t = year_tick(y).whole_ticks(B256Constants::V0.split);
            i128::try_from(t).expect("pilot years fit in i128 seconds")
        };
        // 1970-01-01 is the Unix epoch; J2000 sits 946_728_000 s after it.
        assert_eq!(secs(1970), -946_728_000);
        // 2000-01-01 00:00 UTC is 12 h before J2000's noon epoch.
        assert_eq!(secs(2000), -43_200);
        // 1969 is not a leap year: exactly 365 days before 1970.
        assert_eq!(secs(1969), -946_728_000 - 365 * 86_400);
        // Proleptic Gregorian has a year zero, and it is 1 BCE.
        assert!(secs(0) < secs(1));
        assert!(secs(-1) < secs(0));
        // The oldest coordinate in the pilot set.
        assert_eq!(secs(-4000), -189_341_755_200);

        // A year where TRUNCATING and FLOORING division disagree.
        //
        // This algorithm is Hinnant's, which assumes C-style truncation — the
        // `y - 399` term exists to compensate for it. A floored implementation
        // double-compensates and lands one day early. Every other fixture here
        // (-4000, 1970, 2000, 1) divides exactly, so all of them agree under
        // both readings and NONE of them can tell a correct implementation
        // from a broken one. The monotonicity sweep cannot either, since both
        // readings are monotonic.
        //
        // -260 is the first year in the corpus where they diverge, and this
        // value is derived independently via proleptic-Gregorian JDN rather
        // than from this function. Verified against the coordinate actually
        // stored for the Kalinga War entity in production.
        assert_eq!(secs(-260), -71_318_750_400);
        assert_eq!(secs(-261), -71_350_286_400);
        // Monotonic across the era boundary, which is where the algorithm's
        // floor-division would break if it were written with truncation.
        for y in -401..401 {
            assert!(secs(y) < secs(y + 1), "not monotonic at {y}");
        }
    }

    /// Edges resolve their endpoints through `claim_identity`. If that is not
    /// stable and not shared with the entity path, an edge points at an entity
    /// that does not exist — and does it silently, because nothing checks.
    #[test]
    fn claim_identity_is_stable_and_normalises_the_title() {
        let (a, _) = claim_identity("Fall of Constantinople", 1453);
        let (b, _) = claim_identity("Fall of Constantinople", 1453);
        assert_eq!(a, b, "the same claim must derive the same id every time");

        // Punctuation, case and spacing are not part of the claim.
        let (c, _) = claim_identity("  the FALL, of  Constantinople!  ", 1453);
        let (d, _) = claim_identity("the fall of constantinople", 1453);
        assert_eq!(c, d, "normalisation must collapse presentational noise");

        // The year IS part of it: same name, different event.
        let (e, _) = claim_identity("Battle of Panipat", 1526);
        let (f, _) = claim_identity("Battle of Panipat", 1761);
        assert_ne!(e, f, "distinct years are distinct claims");

        // Never node 0, never negative — an id colliding with the ledger's own
        // entity would attach history to the chain's genesis record.
        for (t, y) in [("", 0), ("x", -4000), ("A Very Long Title Indeed", 1969)] {
            let (id, _) = claim_identity(t, y);
            assert!(id > 0, "id must be positive, got {id}");
        }
    }
}
