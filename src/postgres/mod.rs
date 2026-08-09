//! PostgreSQL implementations of every zurid storage trait, plus the schema they
//! need.
//!
//! Three ready stores — [`PgKeyStore`], [`PgPlcOperationLog`] and
//! [`PgOAuthStateStore`] — each built from an `sqlx::PgPool` you already have.
//! None of them owns a connection or a runtime; they are cheap to clone and to
//! share.
//!
//! # The schema
//!
//! The DDL lives in `migrations/` at the crate root and is shipped two ways:
//!
//! - **embedded** — call [`migrate`] on your pool and zurid's tables appear,
//!   tracked in the standard `_sqlx_migrations` table;
//! - **as files** — copy `migrations/*.sql` into your own migration directory if
//!   you would rather own the versioning (renumber them to fit your sequence).
//!
//! Pick one. Running both would apply the same DDL under two version numbers.
//!
//! ```no_run
//! # async fn run(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//! zurid::postgres::migrate(&pool).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The migrations are embedded by a build script rather than by `sqlx::migrate!`
//! — see `build.rs` for why (in short: so zurid never turns on sqlx's `macros`
//! feature in your build).
//!
//! # Where the SQL is
//!
//! Every statement lives in a file under `queries/`, included at compile time —
//! so the exact SQL that runs is reviewable as SQL, not as a Rust string
//! fragment.

use std::borrow::Cow;

use sqlx::SqlSafeStr as _;
use sqlx::migrate::{MigrateError, Migration, MigrationType, Migrator};

use crate::StorageError;

mod key_store;
mod oauth_state;
mod plc_log;

pub use key_store::PgKeyStore;
pub use oauth_state::PgOAuthStateStore;
pub use plc_log::PgPlcOperationLog;

// `static EMBEDDED_MIGRATIONS: &[(i64, &str, &str)] = &[(version, description, sql), …];`
include!(concat!(env!("OUT_DIR"), "/embedded_migrations.rs"));

/// Run zurid's migrations — key custody, the operation log, and the OAuth state
/// tables.
///
/// Already-applied migrations are skipped, so this is safe to call on every
/// boot. Errors if a migration fails or the recorded history has diverged from
/// the embedded set (a checksum mismatch).
pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), MigrateError> {
    migrator().run(pool).await
}

/// zurid's embedded migration set, as a `sqlx` [`Migrator`].
///
/// Reach for this over [`migrate`] when you want to merge zurid's migrations
/// into a larger set, inspect their versions, or stop between them in a test.
/// The checksums match what sqlx's own directory resolver computes, so a ledger
/// written by the sqlx CLI over the same files validates unchanged.
pub fn migrator() -> Migrator {
    let migrations: Vec<Migration> = EMBEDDED_MIGRATIONS
        .iter()
        .map(|(version, description, sql)| {
            Migration::new(
                *version,
                Cow::Borrowed(*description),
                MigrationType::Simple,
                // A `&'static str` baked into the binary is `SqlSafeStr` by
                // definition — these are our own files, never runtime input.
                (*sql).into_sql_str(),
                false,
            )
        })
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

/// Map an `sqlx` failure into a [`StorageError`].
///
/// A database fault must surface as a store error and never as "no row" — see
/// the [storage contract](crate::KeyStore).
pub(crate) fn storage(err: sqlx::Error) -> StorageError {
    StorageError::new(err)
}
