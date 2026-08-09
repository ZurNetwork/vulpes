//! The OAuth bridge end to end against a throwaway PostgreSQL container:
//! [`JacquardAuthStore`] over [`PgOAuthStateStore`].
//!
//! Two things are proven here that neither layer proves alone. First, that
//! jacquard's `#[serde(flatten)]`-heavy records survive the JSON encode/decode
//! this bridge relies on — the reason it is JSON and not MessagePack. Second,
//! and more importantly, that what lands **on disk** is ciphertext: the DPoP
//! private key, the refresh token and the PKCE verifier must not be recoverable
//! from a raw column read, which is the leaked-backup / read-replica threat.

use fluent_uri::Uri;
use jacquard_common::types::did::Did;
use jacquard_oauth::{
    authstore::ClientAuthStore,
    scopes::Scopes,
    session::{AuthRequestData, ClientSessionData, DpopClientData, DpopReqData},
    types::{OAuthTokenType, TokenSet},
    utils::generate_key,
};
use smol_str::SmolStr;
use sqlx::PgPool;
use zurid::SecretVault;
use zurid::oauth::JacquardAuthStore;
use zurid::postgres::PgOAuthStateStore;

use crate::pg::fresh_pool;

/// A fixed 32-byte root key. A real deployment sources this from a KMS; a test
/// only needs *a* valid key so seal/open round-trips.
fn vault() -> SecretVault {
    SecretVault::from_bytes(&[7u8; 32]).expect("a 32-byte test root key")
}

/// The bridge on a fresh, fully migrated database, plus the raw pool so a test
/// can read the at-rest bytes directly — bypassing the decrypt path — to prove
/// what actually landed on disk.
async fn fresh_bridge() -> (JacquardAuthStore<PgOAuthStateStore>, PgPool, impl Sized) {
    let (pool, db) = fresh_pool().await;
    let bridge = JacquardAuthStore::new(PgOAuthStateStore::new(pool.clone()), vault());
    (bridge, pool, db)
}

fn client_session(did: &'static str, session_id: &'static str) -> ClientSessionData {
    let account_did = Did::new_static(did).expect("a valid did");
    ClientSessionData {
        account_did: account_did.clone(),
        session_id: SmolStr::new_static(session_id),
        host_url: Uri::parse("https://pds.example.com")
            .expect("a valid uri")
            .to_owned(),
        authserver_url: SmolStr::new_static("https://issuer.example.com"),
        authserver_token_endpoint: SmolStr::new_static("https://issuer.example.com/token"),
        authserver_revocation_endpoint: None,
        scopes: Scopes::empty(),
        dpop_data: DpopClientData {
            dpop_key: generate_key(&[SmolStr::new_static("ES256")]).expect("a dpop key"),
            dpop_authserver_nonce: SmolStr::default(),
            dpop_host_nonce: SmolStr::default(),
        },
        token_set: TokenSet {
            iss: SmolStr::new_static("https://issuer.example.com"),
            sub: account_did,
            aud: SmolStr::new_static("https://pds.example.com"),
            scope: None,
            refresh_token: Some(SmolStr::new_static("refresh-token")),
            access_token: SmolStr::new_static("access-token"),
            token_type: OAuthTokenType::DPoP,
            expires_at: None,
        },
        resolved_scopes: None,
    }
}

fn auth_request(state: &'static str) -> AuthRequestData {
    AuthRequestData {
        state: SmolStr::new_static(state),
        authserver_url: SmolStr::new_static("https://issuer.example.com"),
        account_did: Some(Did::new_static("did:plc:alice").expect("a valid did")),
        scopes: Scopes::empty(),
        request_uri: SmolStr::new_static("urn:ietf:params:oauth:request_uri:abc"),
        authserver_token_endpoint: SmolStr::new_static("https://issuer.example.com/token"),
        authserver_revocation_endpoint: None,
        pkce_verifier: SmolStr::new_static("pkce-verifier"),
        dpop_data: DpopReqData {
            dpop_key: generate_key(&[SmolStr::new_static("ES256")]).expect("a dpop key"),
            dpop_authserver_nonce: None,
        },
    }
}

/// The raw at-rest bytes of a session row, read straight from the column.
async fn raw_session(pool: &PgPool, did: &str, session_id: &str) -> Vec<u8> {
    sqlx::query_scalar(
        "SELECT data FROM atproto_oauth.client_session WHERE account_did = $1 AND session_id = $2",
    )
    .bind(did)
    .bind(session_id)
    .fetch_one(pool)
    .await
    .expect("the row is present")
}

#[tokio::test]
async fn a_client_session_upserts_gets_and_deletes() {
    let (bridge, _pool, _db) = fresh_bridge().await;
    let did: Did = Did::new_static("did:plc:alice").expect("a valid did");

    let session = client_session("did:plc:alice", "session-1");
    bridge
        .upsert_session(session.clone())
        .await
        .expect("upsert");

    // The full record — token set and DPoP private key — round-trips exactly.
    let loaded = bridge
        .get_session(&did, "session-1")
        .await
        .expect("get")
        .expect("the session is present after upsert");
    assert_eq!(
        loaded, session,
        "the stored session must round-trip exactly"
    );

    // Upsert replaces in place: a rotated access token, which is what refresh
    // writes.
    let mut rotated = session.clone();
    rotated.token_set.access_token = SmolStr::new_static("access-token-2");
    bridge.upsert_session(rotated).await.expect("upsert");
    let reloaded = bridge
        .get_session(&did, "session-1")
        .await
        .expect("get")
        .expect("the session is present after the rotation");
    assert_eq!(reloaded.token_set.access_token.as_str(), "access-token-2");

    // delete_session is the "this grant ended honestly" path.
    bridge
        .delete_session(&did, "session-1")
        .await
        .expect("delete");
    assert!(
        bridge
            .get_session(&did, "session-1")
            .await
            .expect("get")
            .is_none(),
        "the session must be gone after delete"
    );
}

#[tokio::test]
async fn an_auth_request_saves_gets_and_deletes() {
    let (bridge, _pool, _db) = fresh_bridge().await;

    let request = auth_request("state-xyz");
    bridge.save_auth_req_info(&request).await.expect("save");

    let loaded = bridge
        .get_auth_req_info("state-xyz")
        .await
        .expect("get")
        .expect("the auth request is present after save");
    assert_eq!(loaded, request, "the auth request must round-trip exactly");

    bridge
        .delete_auth_req_info("state-xyz")
        .await
        .expect("delete");
    assert!(
        bridge
            .get_auth_req_info("state-xyz")
            .await
            .expect("get")
            .is_none(),
        "the auth request must be gone after delete"
    );
}

/// The callback path end to end: the sealed record decodes on the FIRST read and
/// is consumed by it, so a second callback replaying the same `state` — the
/// racing-callback case jacquard's get-then-delete leaves open — finds nothing
/// rather than a second copy of the PKCE verifier and DPoP key.
#[tokio::test]
async fn an_auth_request_is_single_use_through_the_bridge() {
    let (bridge, _pool, _db) = fresh_bridge().await;
    let request = auth_request("state-race");
    bridge.save_auth_req_info(&request).await.expect("save");

    let first = bridge
        .get_auth_req_info("state-race")
        .await
        .expect("get")
        .expect("the first callback gets the record");
    assert_eq!(
        first, request,
        "consuming the row must not cost the exact round-trip"
    );

    assert!(
        bridge
            .get_auth_req_info("state-race")
            .await
            .expect("get")
            .is_none(),
        "a replayed callback must find the request already consumed"
    );

    // jacquard deletes right after its get; against a consumed row that is a
    // no-op and must not error, or the callback fails after a good login.
    bridge
        .delete_auth_req_info("state-race")
        .await
        .expect("the follow-up delete stays a no-op");
}

#[tokio::test]
async fn a_missing_session_reads_as_none() {
    let (bridge, _pool, _db) = fresh_bridge().await;
    let did: Did = Did::new_static("did:plc:nobody").expect("a valid did");
    assert!(
        bridge
            .get_session(&did, "absent")
            .await
            .expect("get")
            .is_none(),
        "an absent session must read as None, not error"
    );
}

/// The whole point: what lands in `client_session.data` is ciphertext, not the
/// plaintext JSON. The DPoP private key and tokens must not be recoverable from
/// a raw column read.
#[tokio::test]
async fn the_stored_session_bytes_are_not_plaintext_json() {
    let (bridge, pool, _db) = fresh_bridge().await;
    let session = client_session("did:plc:alice", "session-1");
    bridge
        .upsert_session(session.clone())
        .await
        .expect("upsert");

    let raw = raw_session(&pool, "did:plc:alice", "session-1").await;

    let plaintext_json = serde_json::to_vec(&session).expect("json");
    assert_ne!(
        raw, plaintext_json,
        "the at-rest bytes must not be the plaintext JSON"
    );
    for needle in [
        b"refresh-token".as_slice(),
        b"access-token".as_slice(),
        b"did:plc:alice".as_slice(),
    ] {
        assert!(
            !raw.windows(needle.len()).any(|window| window == needle),
            "the secret/identifier {:?} leaked into the at-rest bytes",
            std::str::from_utf8(needle).unwrap()
        );
    }
    assert!(
        serde_json::from_slice::<ClientSessionData>(&raw).is_err(),
        "the ciphertext must not deserialize as a session"
    );
}

/// The in-flight request is sealed too — the PKCE verifier and DPoP key must not
/// sit in the clear either.
#[tokio::test]
async fn the_stored_auth_request_bytes_are_not_plaintext_json() {
    let (bridge, pool, _db) = fresh_bridge().await;
    bridge
        .save_auth_req_info(&auth_request("state-xyz"))
        .await
        .expect("save");

    let raw: Vec<u8> =
        sqlx::query_scalar("SELECT data FROM atproto_oauth.auth_request WHERE state = $1")
            .bind("state-xyz")
            .fetch_one(&pool)
            .await
            .expect("the row is present");

    for needle in [b"pkce-verifier".as_slice(), b"did:plc:alice".as_slice()] {
        assert!(
            !raw.windows(needle.len()).any(|window| window == needle),
            "the secret/identifier {:?} leaked into the at-rest bytes",
            std::str::from_utf8(needle).unwrap()
        );
    }
    assert!(
        serde_json::from_slice::<AuthRequestData>(&raw).is_err(),
        "the ciphertext must not deserialize as an auth request"
    );
}

/// A value that is not valid ciphertext under this vault — here a legacy
/// plaintext-JSON row written straight into the column — must fail CLOSED on
/// read: an error, never a silent downgrade that hands back the plaintext.
#[tokio::test]
async fn a_non_sealed_row_fails_closed_on_read() {
    let (bridge, pool, _db) = fresh_bridge().await;
    let session = client_session("did:plc:alice", "session-1");
    let plaintext_json = serde_json::to_vec(&session).expect("json");

    sqlx::query(
        "INSERT INTO atproto_oauth.client_session (account_did, session_id, data) \
         VALUES ($1, $2, $3)",
    )
    .bind("did:plc:alice")
    .bind("session-1")
    .bind(&plaintext_json)
    .execute(&pool)
    .await
    .expect("insert the plaintext row");

    let did: Did = Did::new_static("did:plc:alice").expect("a valid did");
    assert!(
        bridge.get_session(&did, "session-1").await.is_err(),
        "a non-sealed value must fail closed, not pass through as plaintext"
    );
}

/// The associated data is wired to the actual row key: a sealed blob grafted
/// onto a different `(account_did, session_id)` fails the tag check, so an
/// attacker with database WRITE access cannot move one session's secret onto
/// another row.
#[tokio::test]
async fn a_sealed_session_is_bound_to_its_row_key() {
    let (bridge, pool, _db) = fresh_bridge().await;
    bridge
        .upsert_session(client_session("did:plc:alice", "session-1"))
        .await
        .expect("upsert");

    // Lift the sealed blob and graft it onto a second session id for the same DID.
    let raw = raw_session(&pool, "did:plc:alice", "session-1").await;
    sqlx::query(
        "INSERT INTO atproto_oauth.client_session (account_did, session_id, data) \
         VALUES ($1, $2, $3)",
    )
    .bind("did:plc:alice")
    .bind("session-2")
    .bind(&raw)
    .execute(&pool)
    .await
    .expect("graft the blob onto session-2");

    let did: Did = Did::new_static("did:plc:alice").expect("a valid did");
    assert!(
        bridge.get_session(&did, "session-2").await.is_err(),
        "a blob grafted onto another row key must fail the associated-data check"
    );
    assert!(
        bridge
            .get_session(&did, "session-1")
            .await
            .expect("get")
            .is_some(),
        "the legitimate row still opens"
    );
}
