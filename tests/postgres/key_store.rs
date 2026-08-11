//! Round-trips [`PgKeyStore`] against a throwaway PostgreSQL container.
//!
//! Since S7 the store trades in **sealed blobs** ([`SealedKeys`]): it seals
//! nothing and opens nothing, so what it proves is the storage contract — the
//! opaque bytes round-trip, the ciphertext is what lands on disk, custody is
//! written at most once, and the envelope version survives the round trip. The
//! sealing and opening — and their fail-closed behaviour — live with the vault
//! and are proven in `keys.rs` and in the minter's end-to-end lifecycle test.

use vulpes::postgres::PgKeyStore;
use vulpes::{
    CustodyEnvelope, CustodyKeys, Did, KeyRole, KeyStore, SealedKeys, SecretKey, SecretVault,
};

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

/// The custody bundle sealed the way the minter would hand it to the store.
fn sealed() -> SealedKeys {
    keys()
        .seal_current(&vault(), &Did::new("did:plc:alice"))
        .expect("seal")
}

#[tokio::test]
async fn put_then_get_round_trips_the_sealed_blob() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool);
    let did = Did::new("did:plc:alice");

    assert!(
        store.get(&did).await.unwrap().is_none(),
        "an unknown DID reads as None, not an error"
    );

    let sealed = sealed();
    store.put(&did, &sealed).await.unwrap();
    let loaded = store.get(&did).await.unwrap().expect("custody is held");
    assert_eq!(loaded, sealed, "the sealed blob round-trips byte for byte");

    // And it opens back to the original keys — the store held ciphertext, the
    // vault turns it back into custody.
    let envelope = CustodyEnvelope::try_from(loaded.version()).unwrap();
    let reopened = CustodyKeys::open(&vault(), &did, loaded.blob(), envelope).unwrap();
    assert_eq!(reopened, keys());
}

#[tokio::test]
async fn keys_are_encrypted_at_rest_not_plaintext() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool.clone());
    let did = Did::new("did:plc:alice");
    store.put(&did, &sealed()).await.unwrap();

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

// The store round-trips the blob opaquely — the DID-binding defense lives in the
// opener. A blob grafted onto another identity's row still fails to open under
// the moved-to DID, so an attacker with database WRITE access cannot move
// custody between identities; the check just now happens at the vault, not the
// store.
#[tokio::test]
async fn a_blob_grafted_onto_another_did_fails_to_open() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool.clone());
    let owner = Did::new("did:plc:owner");
    let owner_sealed = keys()
        .seal_current(&vault(), &owner)
        .expect("seal for owner");
    store.put(&owner, &owner_sealed).await.unwrap();

    // Graft the owner's blob onto a thief row, same version.
    sqlx::query(
        "INSERT INTO account_keys (did, wrapped_keys, key_version, created_at) \
         VALUES ($1, $2, $3, now())",
    )
    .bind("did:plc:thief")
    .bind(owner_sealed.blob())
    .bind(owner_sealed.version())
    .execute(&pool)
    .await
    .unwrap();

    let thief = Did::new("did:plc:thief");
    let grafted = store
        .get(&thief)
        .await
        .unwrap()
        .expect("the row is present");
    let envelope = CustodyEnvelope::try_from(grafted.version()).unwrap();
    assert!(
        CustodyKeys::open(&vault(), &thief, grafted.blob(), envelope).is_err(),
        "a grafted custody blob must fail the associated-data check when opened"
    );

    // The legitimate row still opens.
    let legit = store.get(&owner).await.unwrap().expect("owner row present");
    let envelope = CustodyEnvelope::try_from(legit.version()).unwrap();
    assert!(CustodyKeys::open(&vault(), &owner, legit.blob(), envelope).is_ok());
}

// The version written is the one the reader is told to expect — the round trip
// that makes changing the scheme possible at all.
#[tokio::test]
async fn custody_records_the_current_envelope_version() {
    let (pool, _db) = fresh_pool().await;
    let did = Did::new("did:plc:versioned");
    PgKeyStore::new(pool.clone())
        .put(&did, &sealed())
        .await
        .unwrap();

    let stored: i32 = sqlx::query_scalar("SELECT key_version FROM account_keys WHERE did = $1")
        .bind(did.as_str())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, i32::from(CustodyEnvelope::CURRENT));
}

// BACK-COMPAT. Custody written before the associated data gained its
// domain-separation tag is stamped `key_version = 1`. The store round-trips it,
// and it still opens under V1 — these are the private keys behind live
// identities, and a scheme change that stranded them would take the identities
// with it.
#[tokio::test]
async fn a_legacy_v1_row_still_opens() {
    let (pool, _db) = fresh_pool().await;
    let did = Did::new("did:plc:legacy");

    // Written exactly as pre-tag vulpes would have: bare-DID associated data,
    // stamped version 1.
    let mut plaintext = Vec::new();
    for role in [
        KeyRole::ColdRecovery,
        KeyRole::Operational,
        KeyRole::Signing,
    ] {
        plaintext.extend_from_slice(keys().role(role).expose());
    }
    let legacy = vault().seal(did.as_str().as_bytes(), &plaintext).unwrap();
    sqlx::query(
        "INSERT INTO account_keys (did, wrapped_keys, key_version, created_at) \
         VALUES ($1, $2, 1, now())",
    )
    .bind(did.as_str())
    .bind(&legacy)
    .execute(&pool)
    .await
    .unwrap();

    let loaded = PgKeyStore::new(pool)
        .get(&did)
        .await
        .unwrap()
        .expect("the legacy row is present");
    assert_eq!(loaded.version(), 1, "the stored version round-trips");
    let envelope = CustodyEnvelope::try_from(loaded.version()).unwrap();
    assert_eq!(
        CustodyKeys::open(&vault(), &did, loaded.blob(), envelope).unwrap(),
        keys(),
        "a pre-tag custody row must keep opening under its recorded version"
    );
}

// One DID mints once: the primary key makes a second custody write an error
// rather than an overwrite that would strand the original keys.
#[tokio::test]
async fn custody_is_written_at_most_once() {
    let (pool, _db) = fresh_pool().await;
    let store = PgKeyStore::new(pool);
    let did = Did::new("did:plc:dave");

    store.put(&did, &sealed()).await.unwrap();
    assert!(
        store.put(&did, &sealed()).await.is_err(),
        "a second custody write for the same DID must be rejected"
    );
}
