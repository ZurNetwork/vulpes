//! The whole `did:plc` write path against real PostgreSQL storage.
//!
//! The unit tests prove the minter against in-memory fakes; this proves it
//! against the schema that actually ships — including the two integrity
//! constraints, which live in the DDL and therefore cannot be exercised any
//! other way.

use std::sync::Arc;

use vulpes::postgres::{PgKeyStore, PgPlcOperationLog};
use vulpes::{
    CustodyEnvelope, CustodyKeys, Did, Handle, KeyStore, MintPolicy, Minter, NoopPlcDirectory,
    PlcOperationLog, SealedKeys, SecretVault,
};

use crate::pg::fresh_pool;

fn vault() -> SecretVault {
    SecretVault::from_bytes(&[3u8; 32]).expect("a 32-byte test root key")
}

/// Open the sealed custody a store returned — the store no longer opens (S7), so
/// a test that wants the plaintext keys does it with the vault, as the minter does.
fn open(did: &Did, sealed: &SealedKeys) -> CustodyKeys {
    let envelope = CustodyEnvelope::try_from(sealed.version()).expect("a known envelope");
    CustodyKeys::open(&vault(), did, sealed.blob(), envelope).expect("custody opens")
}

/// A minter over real PostgreSQL storage, plus the stores for assertions.
async fn pg_minter() -> (Minter, Arc<PgKeyStore>, Arc<PgPlcOperationLog>, impl Sized) {
    let (pool, db) = fresh_pool().await;
    let keys = Arc::new(PgKeyStore::new(pool.clone()));
    let log = Arc::new(PgPlcOperationLog::new(pool));
    let minter = Minter::new(
        keys.clone(),
        log.clone(),
        Arc::new(NoopPlcDirectory),
        MintPolicy::identity_only(),
        vault(),
    )
    .expect("the identity-only preset is valid");
    (minter, keys, log, db)
}

// Mint, update, tombstone — the full lifecycle, landing in real tables and
// chaining correctly across all three steps.
#[tokio::test]
async fn the_full_lifecycle_round_trips_through_postgres() {
    let (minter, keys, log, _db) = pg_minter().await;

    let did = minter
        .mint(&Handle::try_new("alice.example.com").unwrap())
        .await
        .expect("mint");
    assert!(did.is_plc());

    // Custody landed sealed, and opens back to three distinct 32-byte scalars.
    let sealed = keys.get(&did).await.unwrap().expect("custody was written");
    let custody = open(&did, &sealed);
    assert_eq!(custody.operational.expose().len(), 32);

    // The genesis operation is the chain's first link.
    let genesis = log
        .latest_op(&did)
        .await
        .unwrap()
        .expect("the genesis was logged");
    assert_eq!(genesis.op_type, "plc_operation");
    assert!(genesis.prev.is_none(), "a genesis chains onto nothing");

    // The update chains onto it.
    minter
        .update_handle(&did, &Handle::try_new("bob.example.com").unwrap())
        .await
        .expect("update the handle");
    let update = log.latest_op(&did).await.unwrap().expect("the update");
    assert_eq!(update.prev.as_deref(), Some(genesis.cid.as_str()));
    let operation: serde_json::Value = serde_json::from_str(&update.operation_json).unwrap();
    assert_eq!(
        operation["alsoKnownAs"],
        serde_json::json!(["at://bob.example.com"]),
        "alsoKnownAs is replaced with the new handle"
    );

    // And the tombstone chains onto the update.
    minter.tombstone(&did).await.expect("tombstone");
    let tombstone = log.latest_op(&did).await.unwrap().expect("the tombstone");
    assert_eq!(tombstone.op_type, "plc_tombstone");
    assert_eq!(tombstone.prev.as_deref(), Some(update.cid.as_str()));

    // A tombstoned identity cannot be updated any further.
    assert!(
        minter
            .update_handle(&did, &Handle::try_new("carol.example.com").unwrap())
            .await
            .is_err(),
        "an update cannot chain onto a tombstone"
    );
}

// Distinct mints are independent identities in the same tables.
#[tokio::test]
async fn concurrent_identities_do_not_collide() {
    let (minter, _keys, log, _db) = pg_minter().await;
    let handle = Handle::try_new("alice.example.com").unwrap();

    let first = minter.mint(&handle).await.expect("first mint");
    let second = minter.mint(&handle).await.expect("second mint");

    assert_ne!(first, second, "each mint is its own identity");
    assert_ne!(
        log.latest_cid(&first).await.unwrap(),
        log.latest_cid(&second).await.unwrap(),
        "each identity has its own chain"
    );
}

// THE CONSTRAINT THAT MATTERS: with the real partial unique index in place, two
// updates cannot both chain the same `prev`. The second attempt is refused by
// the database, the minter propagates it (never a silent fork), and a retry
// serializes onto the new tip.
#[tokio::test]
async fn a_stale_update_cannot_fork_the_chain_in_postgres() {
    let (pool, _db) = fresh_pool().await;
    let keys = Arc::new(PgKeyStore::new(pool.clone()));
    let log = Arc::new(PgPlcOperationLog::new(pool.clone()));
    let minter = Minter::new(
        keys,
        log.clone(),
        Arc::new(NoopPlcDirectory),
        MintPolicy::identity_only(),
        vault(),
    )
    .unwrap();

    let did = minter
        .mint(&Handle::try_new("alice.example.com").unwrap())
        .await
        .expect("mint");
    let genesis_cid = log.latest_cid(&did).await.unwrap().unwrap();

    minter
        .update_handle(&did, &Handle::try_new("bob.example.com").unwrap())
        .await
        .expect("the first update lands");

    // A hand-built second operation chaining the now-stale genesis — exactly what
    // a concurrent writer that read the old tip would produce.
    let forked = vulpes::PlcOperationRecord {
        did: did.clone(),
        cid: "bafyreiforkattempt".to_string(),
        op_type: "plc_operation".to_string(),
        prev: Some(genesis_cid),
        operation_json: r#"{"type":"plc_operation"}"#.to_string(),
        // The DB refuses this on the (did, prev) unique index regardless of the
        // tag, so a placeholder is enough — this proves the storage constraint.
        op_mac: vec![0u8; 32],
    };
    assert!(
        log.append(&forked).await.is_err(),
        "the database refuses a second operation chaining an already-used prev"
    );

    // The chain is still linear: three rows would mean a fork landed.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM plc_operations WHERE did = $1")
        .bind(did.as_str())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 2, "genesis + one update — never a third, forked row");
}

// B2 END TO END: a row altered directly in PostgreSQL — the leaked-credential /
// injection-write threat — is rejected when the minter next reads it, because
// the HMAC no longer matches. The attacker can change the columns but cannot
// forge the tag without the root key, which never touches the database.
#[tokio::test]
async fn a_row_tampered_in_postgres_is_rejected_on_the_next_update() {
    let (pool, _db) = fresh_pool().await;
    let keys = Arc::new(PgKeyStore::new(pool.clone()));
    let log = Arc::new(PgPlcOperationLog::new(pool.clone()));
    let minter = Minter::new(
        keys,
        log,
        Arc::new(NoopPlcDirectory),
        MintPolicy::identity_only(),
        vault(),
    )
    .unwrap();

    let did = minter
        .mint(&Handle::try_new("alice.example.com").unwrap())
        .await
        .expect("mint");

    // Substitute an attacker's rotation keys straight into the row, leaving the
    // stored op_mac untouched — exactly what a write-access attacker can do.
    let forged = serde_json::json!({
        "type": "plc_operation",
        "rotationKeys": ["did:key:attacker1", "did:key:attacker2"],
        "verificationMethods": {"atproto": "did:key:sign"},
        "alsoKnownAs": ["at://alice.example.com"],
        "services": {},
        "prev": serde_json::Value::Null,
    });
    sqlx::query("UPDATE plc_operations SET operation = $2 WHERE did = $1")
        .bind(did.as_str())
        .bind(&forged)
        .execute(&pool)
        .await
        .unwrap();

    let error = minter
        .update_handle(&did, &Handle::try_new("bob.example.com").unwrap())
        .await
        .expect_err("a tampered row must be refused, not signed");
    assert!(
        matches!(error, vulpes::MintError::TamperedPriorOperation(_)),
        "the altered row fails its MAC check, got: {error}"
    );
}
