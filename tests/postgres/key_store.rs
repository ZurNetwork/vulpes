//! Round-trips [`PgKeyStore`] against a throwaway PostgreSQL container, proving
//! the migration-created `account_keys` table (1) round-trips a sealed custody
//! bundle and (2) stores it **encrypted** — the plaintext scalars never appear in
//! the column.

use zurid::postgres::PgKeyStore;
use zurid::{CustodyEnvelope, CustodyKeys, Did, KeyStore, SecretKey, SecretVault};

use crate::pg::fresh_pool;

fn keys() -> CustodyKeys {
    CustodyKeys {
        cold_recovery: SecretKey::new(vec![0xAA; 32]),
        operational: SecretKey::new(vec![0xBB; 32]),
        signing: SecretKey::new(vec![0xCC; 32]),
    }
}

fn vault() -> SecretVault {
    SecretVault::from_bytes(&[9u8; 32]).expect("a 32-byte test root key")
}

#[tokio::test]
async fn put_then_get_round_trips_the_keys() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool, vault());
    let did = Did::new("did:plc:alice");

    assert!(
        store.get(&did).await.unwrap().is_none(),
        "an unknown DID reads as None, not an error"
    );
    store.put(&did, &keys()).await.unwrap();
    assert_eq!(store.get(&did).await.unwrap().unwrap(), keys());
}

#[tokio::test]
async fn keys_are_encrypted_at_rest_not_plaintext() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool.clone(), vault());
    let did = Did::new("did:plc:bob");
    store.put(&did, &keys()).await.unwrap();

    // Read the raw stored bytes and assert none of the three plaintext runs
    // appears — the column holds ciphertext, never the secp256k1 scalars.
    let wrapped: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_keys FROM account_keys WHERE did = $1")
            .bind(did.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    for byte in [0xAAu8, 0xBB, 0xCC] {
        let run = vec![byte; 32];
        assert!(
            !wrapped.windows(32).any(|window| window == run.as_slice()),
            "plaintext key bytes ({byte:#x}) found in wrapped_keys — not encrypted at rest"
        );
    }
}

// The DID is the AEAD associated data, so a blob lifted onto another identity's
// row fails to open: an attacker with database WRITE access cannot move custody
// between identities.
#[tokio::test]
async fn a_blob_grafted_onto_another_did_fails_to_open() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool.clone(), vault());
    let owner = Did::new("did:plc:owner");
    store.put(&owner, &keys()).await.unwrap();

    let wrapped: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_keys FROM account_keys WHERE did = $1")
            .bind(owner.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO account_keys (did, wrapped_keys, key_version, created_at) \
         VALUES ($1, $2, $3, now())",
    )
    .bind("did:plc:thief")
    .bind(&wrapped)
    // The SAME envelope the legitimate row records — so what this proves is the
    // associated-data binding, not a version mismatch.
    .bind(i32::from(CustodyEnvelope::CURRENT))
    .execute(&pool)
    .await
    .unwrap();

    assert!(
        store.get(&Did::new("did:plc:thief")).await.is_err(),
        "a grafted custody blob must fail the associated-data check"
    );
    assert!(
        store.get(&owner).await.unwrap().is_some(),
        "the legitimate row still opens"
    );
}

// A wrong root key must fail closed — an error, never a silent `None` that a
// caller could read as "this identity has no custody".
#[tokio::test]
async fn a_wrong_root_key_fails_closed() {
    let (pool, _db) = fresh_pool().await;
    let did = Did::new("did:plc:carol");
    PgKeyStore::new(pool.clone(), vault())
        .put(&did, &keys())
        .await
        .unwrap();

    let other_vault = SecretVault::from_bytes(&[1u8; 32]).unwrap();
    assert!(
        PgKeyStore::new(pool, other_vault).get(&did).await.is_err(),
        "the wrong root key must error, not read as absent"
    );
}

// A `key_version` this build does not know — a row written by a NEWER zurid,
// met during a rolling deploy or after a rollback — is an explicit error. The
// alternative is opening the blob under a guessed scheme, which at best fails
// the AEAD tag and at worst hands back bytes that were never these keys.
#[tokio::test]
async fn an_unknown_key_version_is_refused() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool.clone(), vault());
    let did = Did::new("did:plc:future");
    store.put(&did, &keys()).await.unwrap();

    // Stamp the row as a scheme from the future, leaving the blob untouched.
    sqlx::query("UPDATE account_keys SET key_version = 9999 WHERE did = $1")
        .bind(did.as_str())
        .execute(&pool)
        .await
        .unwrap();

    let failure = store
        .get(&did)
        .await
        .expect_err("an unknown key_version must be refused, not guessed at");
    assert!(
        failure.to_string().contains("9999"),
        "the failure should name the version it did not understand, got: {failure}"
    );
}

// The version written is the one the reader is told to expect — the round trip
// that makes changing the scheme possible at all.
#[tokio::test]
async fn custody_records_the_current_envelope_version() {
    let (pool, _db) = fresh_pool().await;
    let did = Did::new("did:plc:versioned");
    PgKeyStore::new(pool.clone(), vault())
        .put(&did, &keys())
        .await
        .unwrap();

    let stored: i32 = sqlx::query_scalar("SELECT key_version FROM account_keys WHERE did = $1")
        .bind(did.as_str())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, i32::from(CustodyEnvelope::CURRENT));
}

// One DID mints once: the primary key makes a second custody write an error
// rather than an overwrite that would strand the original keys.
#[tokio::test]
async fn custody_is_written_at_most_once() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool, vault());
    let did = Did::new("did:plc:dave");

    store.put(&did, &keys()).await.unwrap();
    assert!(
        store.put(&did, &keys()).await.is_err(),
        "a second custody write for the same DID must be rejected"
    );
}
