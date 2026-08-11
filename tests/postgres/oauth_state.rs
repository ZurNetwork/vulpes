//! Round-trips [`PgOAuthStateStore`] against a throwaway PostgreSQL container.
//!
//! This layer stores **opaque bytes** — the sealing lives one level up — so what
//! is proven here is the storage contract itself: upsert replaces in place,
//! delete removes, an absent row reads as `None` rather than erroring, and the
//! two row families do not collide.

use std::time::Duration;

use vulpes::OAuthStateStore;
use vulpes::postgres::{DEFAULT_AUTH_REQUEST_TTL, PgOAuthStateStore};

use crate::pg::fresh_pool;

const DID: &str = "did:plc:alice";

#[tokio::test]
async fn a_session_upserts_reads_and_deletes() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool);

    assert!(
        store.get_session(DID, "session-1").await.unwrap().is_none(),
        "an absent session reads as None, not an error"
    );

    store
        .upsert_session(DID, "session-1", b"sealed-blob-one")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_session(DID, "session-1")
            .await
            .unwrap()
            .as_deref(),
        Some(b"sealed-blob-one".as_slice())
    );

    // Upsert replaces in place — this is the path a token refresh takes, and it
    // is why a later request on any replica reads the freshest grant.
    store
        .upsert_session(DID, "session-1", b"sealed-blob-two")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_session(DID, "session-1")
            .await
            .unwrap()
            .as_deref(),
        Some(b"sealed-blob-two".as_slice()),
        "the rotated blob replaced the prior one"
    );

    store.delete_session(DID, "session-1").await.unwrap();
    assert!(
        store.get_session(DID, "session-1").await.unwrap().is_none(),
        "the session is gone after delete"
    );
}

// Sessions are keyed by the PAIR: two session ids for one DID are two rows, and
// deleting one leaves the other.
#[tokio::test]
async fn sessions_are_keyed_by_did_and_session_id() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool);

    store.upsert_session(DID, "one", b"first").await.unwrap();
    store.upsert_session(DID, "two", b"second").await.unwrap();
    store.delete_session(DID, "one").await.unwrap();

    assert!(store.get_session(DID, "one").await.unwrap().is_none());
    assert_eq!(
        store.get_session(DID, "two").await.unwrap().as_deref(),
        Some(b"second".as_slice()),
        "deleting one session leaves the other"
    );
}

#[tokio::test]
async fn an_auth_request_saves_reads_and_deletes() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool);

    assert!(store.get_auth_request("state-xyz").await.unwrap().is_none());

    store
        .save_auth_request("state-xyz", b"sealed-request")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_auth_request("state-xyz")
            .await
            .unwrap()
            .as_deref(),
        Some(b"sealed-request".as_slice())
    );

    // The read above already consumed the row (see
    // `reading_an_auth_request_consumes_it`); jacquard's follow-up delete must
    // still succeed against an absent row rather than erroring.
    store.delete_auth_request("state-xyz").await.unwrap();
    assert!(
        store.get_auth_request("state-xyz").await.unwrap().is_none(),
        "the auth request is gone"
    );
}

// SINGLE USE. The read CONSUMES the row, atomically: the blob holds one
// authorization's PKCE verifier and DPoP key, and jacquard's callback does a get
// followed by a SEPARATE delete — a window in which two callbacks carrying the
// same `state` would both come away with it. A second read must see nothing.
#[tokio::test]
async fn reading_an_auth_request_consumes_it() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool.clone());

    store
        .save_auth_request("state-once", b"sealed-request")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_auth_request("state-once")
            .await
            .unwrap()
            .as_deref(),
        Some(b"sealed-request".as_slice()),
        "the first read gets the blob"
    );
    assert!(
        store
            .get_auth_request("state-once")
            .await
            .unwrap()
            .is_none(),
        "the read consumed the row — a replay must find nothing"
    );

    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM atproto_oauth.auth_request WHERE state = $1")
            .bind("state-once")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "the row is gone, not merely hidden");

    // The follow-up delete jacquard issues must stay a harmless no-op.
    store.delete_auth_request("state-once").await.unwrap();
}

/// Age a saved auth request by moving its `created_at` back — the only way to
/// exercise a TTL without sleeping through it.
async fn backdate(pool: &sqlx::PgPool, state: &str, seconds: i64) {
    sqlx::query(
        "UPDATE atproto_oauth.auth_request \
         SET created_at = now() - make_interval(secs => $2) WHERE state = $1",
    )
    .bind(state)
    .bind(seconds as f64)
    .execute(pool)
    .await
    .expect("backdate the request");
}

// A row past its TTL reads as ABSENT. An auth request holds a live PKCE verifier
// and DPoP key for a sign-in still in flight; "the visitor never came back" and
// "the callback arrived a week later" are otherwise the same row, so a redirect
// captured today would still complete a sign-in started long ago.
#[tokio::test]
async fn an_expired_auth_request_reads_as_absent() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool.clone()).with_auth_request_ttl(Duration::from_secs(60));

    store
        .save_auth_request("state-stale", b"sealed-request")
        .await
        .unwrap();
    backdate(&pool, "state-stale", 61).await;

    assert!(
        store
            .get_auth_request("state-stale")
            .await
            .unwrap()
            .is_none(),
        "a row past its TTL must read as absent, not as a usable authorization"
    );

    // Expiry is enforced in the READ, not by a sweeper — the row is still there
    // and still refused, so a lapsed prune job cannot extend the window.
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM atproto_oauth.auth_request WHERE state = $1")
            .bind("state-stale")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining, 1,
        "the read refuses it without needing the sweep"
    );
}

// The other side of the boundary: a row inside the TTL still reads, so the TTL
// does not simply break every sign-in.
#[tokio::test]
async fn an_auth_request_inside_its_ttl_still_reads() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool.clone()).with_auth_request_ttl(Duration::from_secs(60));

    store
        .save_auth_request("state-fresh", b"sealed-request")
        .await
        .unwrap();
    backdate(&pool, "state-fresh", 30).await;

    assert_eq!(
        store
            .get_auth_request("state-fresh")
            .await
            .unwrap()
            .as_deref(),
        Some(b"sealed-request".as_slice()),
        "a request well inside its TTL must still complete"
    );
}

// `prune_expired` drops exactly the expired rows and leaves the live ones.
#[tokio::test]
async fn prune_expired_drops_only_the_stale_requests() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool.clone()).with_auth_request_ttl(Duration::from_secs(60));

    for state in ["stale-one", "stale-two", "live"] {
        store.save_auth_request(state, b"sealed").await.unwrap();
    }
    backdate(&pool, "stale-one", 600).await;
    backdate(&pool, "stale-two", 61).await;

    assert_eq!(
        store.prune_expired().await.unwrap(),
        2,
        "both expired requests are pruned"
    );

    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT state FROM atproto_oauth.auth_request ORDER BY state")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, vec!["live".to_string()], "the live row survives");

    assert_eq!(
        store.prune_expired().await.unwrap(),
        0,
        "a second sweep with nothing to do prunes nothing"
    );
}

#[tokio::test]
async fn the_default_ttl_is_ten_minutes() {
    let (pool, _db) = fresh_pool().await;
    assert_eq!(
        PgOAuthStateStore::new(pool).auth_request_ttl(),
        DEFAULT_AUTH_REQUEST_TTL,
    );
    assert_eq!(DEFAULT_AUTH_REQUEST_TTL, Duration::from_secs(600));
}

// A re-issued `state` overwrites rather than erroring, so a retried sign-in does
// not wedge on a primary-key collision.
#[tokio::test]
async fn re_saving_an_auth_request_replaces_it() {
    let (pool, _db) = fresh_pool().await;
    let store = PgOAuthStateStore::new(pool);

    store.save_auth_request("state", b"first").await.unwrap();
    store.save_auth_request("state", b"second").await.unwrap();
    assert_eq!(
        store.get_auth_request("state").await.unwrap().as_deref(),
        Some(b"second".as_slice())
    );
}
