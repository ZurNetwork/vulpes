//! The migration set itself, run against an empty database rather than the
//! pre-migrated template every other test clones.
//!
//! Two properties, and the second is the one worth having: the set applies from
//! scratch, and it **fails loudly** when one of its names is already taken.

use crate::pg::fresh_unmigrated_pool;

#[tokio::test]
async fn the_migration_set_applies_to_an_empty_database() {
    let (pool, _db) = fresh_unmigrated_pool().await;

    zurid::postgres::migrate(&pool)
        .await
        .expect("the migrations apply to an empty database");

    // Every table the set is responsible for is there afterwards.
    for table in [
        "account_keys",
        "plc_operations",
        "atproto_oauth.client_session",
        "atproto_oauth.auth_request",
    ] {
        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("the catalogue lookup runs");
        assert_eq!(
            exists.as_deref(),
            Some(table),
            "`{table}` must exist after the migrations run"
        );
    }

    // Re-running is a no-op: already-applied versions are skipped, not replayed.
    zurid::postgres::migrate(&pool)
        .await
        .expect("re-running the migrations is a no-op");
}

// A NAME COLLISION MUST FAIL, NOT BE SWALLOWED. zurid's table names are
// unprefixed (FORKS F9), so a consumer may already own an `account_keys`. With
// `CREATE TABLE IF NOT EXISTS` the migration would succeed against THEIR table
// and be recorded as applied — after which zurid reads and writes a schema it
// does not control, the ledger claims the DDL ran, and no later `migrate` will
// ever create the real table. The loud failure at migrate time is the whole
// point: it is recoverable, and the silent success is not.
#[tokio::test]
async fn a_colliding_table_fails_the_migration_loudly() {
    let (pool, _db) = fresh_unmigrated_pool().await;

    sqlx::query("CREATE TABLE account_keys (something_else text PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("the consumer's own table");

    let failure = zurid::postgres::migrate(&pool)
        .await
        .expect_err("a name collision must fail the migration");
    assert!(
        failure.to_string().contains("account_keys"),
        "the failure must name the colliding relation, got: {failure}"
    );

    // The migration ran in a transaction, so nothing was recorded as applied —
    // fixing the collision and re-running is all it takes.
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("the ledger is readable");
    assert_eq!(
        applied, 0,
        "a failed migration must not be recorded as applied"
    );

    // And the consumer's table is untouched — the failure changed nothing.
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_name = 'account_keys' ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("the catalogue lookup runs");
    assert_eq!(columns, vec!["something_else".to_string()]);
}

// The same for a schema, which `CREATE SCHEMA IF NOT EXISTS` would have hidden.
#[tokio::test]
async fn a_colliding_schema_fails_the_migration_loudly() {
    let (pool, _db) = fresh_unmigrated_pool().await;

    sqlx::query("CREATE SCHEMA atproto_oauth")
        .execute(&pool)
        .await
        .expect("the consumer's own schema");

    let failure = zurid::postgres::migrate(&pool)
        .await
        .expect_err("a schema collision must fail the migration");
    assert!(
        failure.to_string().contains("atproto_oauth"),
        "the failure must name the colliding schema, got: {failure}"
    );
}
