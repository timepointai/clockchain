//! M0 exit criterion: a mutation of `events` RAISES under BOTH enforcement
//! mechanisms — the table owner hits the trigger; the `cc_app` role hits the
//! permission wall (the ACL denies before the trigger is even reached). Real
//! Postgres only; the guarantees are Postgres behaviors a mock could not stand
//! in for.

#[tokio::test]
async fn events_is_append_only_under_owner_trigger_and_app_permission() {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;

    // Insert one row as the owner (owners may INSERT into the ledger).
    sqlx::query(
        "INSERT INTO events \
         (event_id, kind, author_key, signature, event_time, record_time, payload) \
         VALUES ($1,1,$2,$3,$4,$4,$5)",
    )
    .bind(vec![1u8; 32])
    .bind(vec![0u8; 32])
    .bind(vec![0u8; 64])
    .bind(vec![0u8; 32])
    .bind(vec![9u8; 3])
    .execute(&pool)
    .await
    .expect("owner insert");

    // TRUNCATE ... CASCADE, not a bare TRUNCATE: a bare one is stopped earlier by
    // the FK-reference guard (a third, incidental defense) before the trigger is
    // reached. CASCADE satisfies that guard, so the BEFORE TRUNCATE trigger
    // itself fires — and CASCADE is the more dangerous op to prove blocked.
    let mutations = [
        ("UPDATE", "UPDATE events SET kind = 9"),
        ("DELETE", "DELETE FROM events"),
        ("TRUNCATE", "TRUNCATE events CASCADE"),
    ];

    // --- Owner path: the trigger fires for every role and raises 'append-only'.
    for (op, sql) in mutations {
        let err = sqlx::query(sql)
            .execute(&pool)
            .await
            .expect_err(&format!("{op} on events must fail for the owner"));
        assert!(
            err.to_string().contains("append-only"),
            "{op} owner path should hit the append-only trigger, got: {err}"
        );
    }

    // --- App-role path: cc_app lacks UPDATE/DELETE/TRUNCATE, so the ACL denies
    // before the trigger. SET ROLE / RESET ROLE must run on ONE connection.
    let mut conn = pool.acquire().await.expect("acquire connection");
    for (op, sql) in mutations {
        sqlx::query("SET ROLE cc_app")
            .execute(&mut *conn)
            .await
            .expect("set role cc_app");
        let err = sqlx::query(sql)
            .execute(&mut *conn)
            .await
            .expect_err(&format!("{op} on events must fail for cc_app"));
        assert!(
            err.to_string().contains("permission denied"),
            "{op} app path should hit the permission wall, got: {err}"
        );
        sqlx::query("RESET ROLE")
            .execute(&mut *conn)
            .await
            .expect("reset role");
    }
    drop(conn);

    // The row survived every rejected mutation — the ledger is intact.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1, "no rejected mutation touched the ledger");

    pool.close().await;
    cleanup.cleanup().await;
}
