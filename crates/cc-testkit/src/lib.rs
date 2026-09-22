//! `cc-testkit` — the real-DB test harness. No mocks: every test runs against a
//! real Postgres, because the ledger's guarantees (append-only enforcement,
//! byte-identical rebuild, `bytea` coordinate ordering) are Postgres behaviors a
//! fake could not stand in for.
//!
//! [`ephemeral_db`] provisions a fresh database per test run against the server
//! named by `TEST_DATABASE_URL` (falling back to `DATABASE_URL`), applies the
//! migrations, and hands back a live pool plus a best-effort [`Cleanup`].

use sqlx::{Connection, PgConnection, PgPool};

/// A best-effort teardown handle for an ephemeral database.
pub struct Cleanup {
    admin_url: String,
    db_name: String,
}

impl Cleanup {
    /// Drop the ephemeral database. Best-effort: errors are swallowed so a test
    /// teardown never masks the test's own result.
    pub async fn cleanup(self) {
        let Ok(admin) = PgPool::connect(&self.admin_url).await else {
            return;
        };
        // Kick any lingering backends off the database before dropping it.
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = '{}' AND pid <> pg_backend_pid()",
            self.db_name
        ))
        .execute(&admin)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{}\"", self.db_name))
            .execute(&admin)
            .await;
        admin.close().await;
    }
}

/// Provision an ephemeral database, migrate it, and return a live pool plus a
/// teardown handle.
///
/// # Panics
/// Panics if no `TEST_DATABASE_URL`/`DATABASE_URL` is set or the server is
/// unreachable — a test that cannot reach a real Postgres has failed by design.
pub async fn ephemeral_db() -> (PgPool, Cleanup) {
    let base = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("TEST_DATABASE_URL or DATABASE_URL must be set");

    // The media reserve is a percent of the volume holding the media directory.
    // Under test that directory is a temporary path on the host disk, not the
    // dedicated production volume, so the production default would refuse every
    // write on any developer machine or runner that is more than 80% full. Every
    // caller writes the same value, so this does not race; a test that exercises
    // the pause itself sets its own value first and is left alone.
    if std::env::var_os("CC_MEDIA_FREE_RESERVE_PERCENT").is_none() {
        std::env::set_var("CC_MEDIA_FREE_RESERVE_PERCENT", "0");
    }

    let db_name = format!("cc_test_{}", uuid::Uuid::new_v4().simple());

    // Serialize provisioning across every concurrent test on this cluster.
    //
    // `0002_events_append_only.sql` creates the `cc_app` role, and a role is a
    // CLUSTER-global object: `CREATE ROLE` from two ephemeral databases at once
    // races. The migration guards it with `IF NOT EXISTS` plus an
    // `EXCEPTION WHEN duplicate_object` handler, and neither fires — under a
    // real race the loser's index insert fails first, raising `unique_violation`
    // (23505) on `pg_authid_rolname_index`, which that handler does not catch.
    //
    // The fix belongs here rather than in the migration. `0002` is applied to
    // the live chain, `sqlx::migrate!` validates the checksum of every applied
    // migration, and editing one would stop production from starting — a far
    // worse outcome than a flaky test.
    //
    // A session-level advisory lock, held on this connection while another
    // connection migrates, is enough: it is cluster-wide by key, so every
    // `cargo test` process on this server queues behind it. Migration is ~100ms,
    // so the serialization is not worth optimizing.
    //
    // This raced in CI and NOT on the machine that wrote it, for a reason worth
    // keeping: `cleanup` is best-effort, 36 test databases had accumulated
    // locally, and the objects they owned made `cc_app` undroppable. The role
    // was therefore always already present here and the guard's happy path
    // always taken. A green suite on a dirty cluster is not evidence about a
    // clean one.
    const PROVISION_LOCK: i64 = 0x001b_0cc0_de1e_d6e5_u64 as i64;
    let mut admin = PgConnection::connect(&base)
        .await
        .expect("connect to admin database");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PROVISION_LOCK)
        .execute(&mut admin)
        .await
        .expect("take the provisioning lock");

    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&mut admin)
        .await
        .expect("create ephemeral database");

    // Connect to the fresh database and migrate it, still under the lock.
    let url = swap_db_name(&base, &db_name);
    let pool = cc_ledger::connect(&url)
        .await
        .expect("connect to ephemeral database");
    let migrated = cc_ledger::run_migrations(&pool).await;

    // Release before asserting, so one failed migration does not wedge every
    // other test behind a lock that is never given back.
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PROVISION_LOCK)
        .execute(&mut admin)
        .await;
    let _ = admin.close().await;
    migrated.expect("migrate ephemeral database");

    (
        pool,
        Cleanup {
            admin_url: base,
            db_name,
        },
    )
}

/// Replace the database segment of a Postgres URL with `name`.
fn swap_db_name(base: &str, name: &str) -> String {
    match base.rsplit_once('/') {
        Some((prefix, _)) => format!("{prefix}/{name}"),
        None => format!("{base}/{name}"),
    }
}
