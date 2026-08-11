//! The shared-container PostgreSQL harness: one container per test process, a
//! fully migrated template database, and a private clone per test via
//! `CREATE DATABASE … TEMPLATE …`.
//!
//! A clone costs tens of milliseconds, so every test still gets a pristine
//! database without paying for a container boot and a migration replay each
//! time.
//!
//! The container is **refcounted**, not static: each [`TestDb`] holds an `Arc`,
//! and a process-wide `Weak` lets later tests rejoin. The last live handle reaps
//! the container on drop — testcontainers has no reaper daemon, so a
//! never-dropped static would leak a running container past process exit.
//!
//! Requires a container runtime socket (`DOCKER_HOST` is honored).

use std::sync::{Arc, Mutex, Weak};

use sqlx::{Connection as _, PgConnection, PgPool, postgres::PgPoolOptions};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};

/// Name of the migrated template database inside the shared container.
const TEMPLATE: &str = "vulpes_template";

/// The PostgreSQL image tag the shared container boots.
///
/// Pinned deliberately: `testcontainers_modules::postgres::Postgres` defaults to
/// an image several majors behind anything in production, which means migrations
/// get validated against a PostgreSQL nobody runs. Tests here use a version a
/// deployment plausibly does.
const POSTGRES_TAG: &str = "16-alpine";

/// The per-process shared container plus the coordinates to clone from it.
struct SharedPg {
    /// Held only for its `Drop`: the last `Arc` owner reaps the container.
    _container: ContainerAsync<Postgres>,
    /// Admin URL (the stock `postgres` database) used for `CREATE DATABASE`.
    admin_url: String,
    /// Serializes clones: PostgreSQL rejects concurrent copies of one template.
    create: tokio::sync::Mutex<()>,
}

/// Rejoin point for the shared container. `Weak`, so holding the static never
/// keeps the container alive on its own.
static SHARED: Mutex<Weak<SharedPg>> = Mutex::new(Weak::new());

/// Serializes the boot path so racing tests cannot start two containers.
static BOOT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A private clone of the migrated template database. Keep it alive for the
/// test's duration — it also keeps the shared container alive.
pub struct TestDb {
    url: String,
    _shared: Arc<SharedPg>,
}

impl TestDb {
    /// Connection URL of this test's private database.
    #[allow(dead_code)]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// A fresh, fully migrated private database plus a pool on it.
///
/// Keep the returned handle alive for the whole test.
pub async fn fresh_pool() -> (PgPool, TestDb) {
    let db = create_db().await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&db.url)
        .await
        .expect("the test pool connects");
    (pool, db)
}

/// An **empty** private database plus a pool on it — vulpes's migrations have
/// **not** been run.
///
/// The migration set itself is what a test using this is examining: that it
/// applies from scratch, and that it refuses to run onto a schema that already
/// holds one of its names.
#[allow(dead_code)]
pub async fn fresh_unmigrated_pool() -> (PgPool, TestDb) {
    let db = create_named_db(None).await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&db.url)
        .await
        .expect("the test pool connects");
    (pool, db)
}

/// Clone the migrated template into a uniquely-named database for one test.
async fn create_db() -> TestDb {
    create_named_db(Some(TEMPLATE)).await
}

/// A uniquely-named database, cloned from `template` or empty when `None`.
async fn create_named_db(template: Option<&str>) -> TestDb {
    let shared = shared().await;
    let name = format!("t_{}", uuid::Uuid::now_v7().simple());
    {
        let _serialize = shared.create.lock().await;
        let mut admin = PgConnection::connect(&shared.admin_url)
            .await
            .expect("an admin connection for the clone");
        // Identifiers cannot be bind parameters; every part here is
        // harness-generated (a uuid and a constant), never external input.
        let from = template
            .map(|template| format!(r#" TEMPLATE "{template}""#))
            .unwrap_or_default();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            r#"CREATE DATABASE "{name}"{from}"#
        )))
        .execute(&mut admin)
        .await
        .expect("create the test database");
        admin.close().await.ok();
    }
    let (base, _) = shared
        .admin_url
        .rsplit_once('/')
        .expect("the admin url has a database segment");
    TestDb {
        url: format!("{base}/{name}"),
        _shared: shared,
    }
}

/// The live shared container, booting it (and building the template) if this
/// test is the first — or the first after a drain.
async fn shared() -> Arc<SharedPg> {
    if let Some(live) = SHARED.lock().expect("shared pg lock").upgrade() {
        return live;
    }
    let _booting = BOOT.lock().await;
    // Re-check under the boot lock: a racer may have finished while we waited.
    if let Some(live) = SHARED.lock().expect("shared pg lock").upgrade() {
        return live;
    }

    let container = Postgres::default()
        .with_tag(POSTGRES_TAG)
        .start()
        .await
        .expect("the postgres container starts (is a container runtime running?)");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("the mapped postgres port");
    let admin_url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    // Build the template: create it, migrate it, then fully disconnect — a
    // template can only be copied while it has no connections.
    let mut admin = PgConnection::connect(&admin_url)
        .await
        .expect("an admin connection for the template");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"CREATE DATABASE "{TEMPLATE}""#
    )))
    .execute(&mut admin)
    .await
    .expect("create the template database");
    admin.close().await.ok();

    let (base, _) = admin_url.rsplit_once('/').expect("the admin url shape");
    let template_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base}/{TEMPLATE}"))
        .await
        .expect("the template pool connects");
    vulpes::postgres::migrate(&template_pool)
        .await
        .expect("vulpes's migrations run");
    template_pool.close().await;

    let live = Arc::new(SharedPg {
        _container: container,
        admin_url,
        create: tokio::sync::Mutex::new(()),
    });
    *SHARED.lock().expect("shared pg lock") = Arc::downgrade(&live);
    live
}
