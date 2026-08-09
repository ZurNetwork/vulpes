//! Round-trips [`PgOAuthStateStore`] against a throwaway PostgreSQL container.
//!
//! This layer stores **opaque bytes** — the sealing lives one level up — so what
//! is proven here is the storage contract itself: upsert replaces in place,
//! delete removes, an absent row reads as `None` rather than erroring, and the
//! two row families do not collide.

use zurid::OAuthStateStore;
use zurid::postgres::PgOAuthStateStore;

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
