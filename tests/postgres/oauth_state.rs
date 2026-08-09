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

    // The callback consumes the in-flight request once it has been used.
    store.delete_auth_request("state-xyz").await.unwrap();
    assert!(
        store.get_auth_request("state-xyz").await.unwrap().is_none(),
        "the auth request is gone after delete"
    );
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
