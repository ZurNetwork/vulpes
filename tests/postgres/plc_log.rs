//! Round-trips [`PgPlcOperationLog`] against a throwaway PostgreSQL container:
//! appends chain in submission order, the reads return the DID's tip, and — the
//! part that matters — both integrity constraints hold at the storage layer.

use vulpes::postgres::PgPlcOperationLog;
use vulpes::{Did, PlcOperationLog, PlcOperationRecord};

use crate::pg::fresh_pool;

fn record(did: &Did, cid: &str, op_type: &str, prev: Option<&str>) -> PlcOperationRecord {
    PlcOperationRecord {
        did: did.clone(),
        cid: cid.to_string(),
        op_type: op_type.to_string(),
        prev: prev.map(str::to_string),
        operation_json: format!(r#"{{"type":"{op_type}"}}"#),
        // This suite proves the STORAGE contract, not MAC verification (that is
        // the minter's, tested against the vault). A fixed 32-byte tag stands in
        // for a real one, so what is checked here is that `op_mac` round-trips.
        op_mac: vec![0xEE; 32],
    }
}

// The log chains in submission order: after a genesis then a tombstone,
// `latest_cid` returns the tombstone's CID. Empty for an unknown DID, and scoped
// per DID.
#[tokio::test]
async fn append_then_latest_cid_returns_the_most_recent_per_did() {
    let (pool, _db) = fresh_pool().await;
    let log = PgPlcOperationLog::new(pool);
    let did = Did::new("did:plc:oplog-a");

    assert!(
        log.latest_cid(&did).await.unwrap().is_none(),
        "no operations logged yet"
    );

    log.append(&record(&did, "bafyreigenesis", "plc_operation", None))
        .await
        .expect("append the genesis");
    assert_eq!(
        log.latest_cid(&did).await.unwrap().as_deref(),
        Some("bafyreigenesis")
    );

    log.append(&record(
        &did,
        "bafyreitombstone",
        "plc_tombstone",
        Some("bafyreigenesis"),
    ))
    .await
    .expect("append the tombstone");
    assert_eq!(
        log.latest_cid(&did).await.unwrap().as_deref(),
        Some("bafyreitombstone"),
        "the latest op is now the tombstone"
    );

    let other = Did::new("did:plc:oplog-b");
    assert!(
        log.latest_cid(&other).await.unwrap().is_none(),
        "a different DID's log is independent"
    );
}

// An update (a `plc_operation` with a non-null `prev`) round-trips and becomes
// the tip the NEXT operation must chain onto — and replaying the identical
// operation (same content, same cid) is rejected by the unique index, the
// storage half of the idempotency contract.
#[tokio::test]
async fn an_update_becomes_the_tip_and_a_replay_is_rejected() {
    let (pool, _db) = fresh_pool().await;
    let log = PgPlcOperationLog::new(pool);
    let did = Did::new("did:plc:oplog-update");

    log.append(&record(&did, "bafyreigenesis2", "plc_operation", None))
        .await
        .expect("append the genesis");
    log.append(&record(
        &did,
        "bafyreiupdate",
        "plc_operation",
        Some("bafyreigenesis2"),
    ))
    .await
    .expect("append the update");

    assert_eq!(
        log.latest_cid(&did).await.unwrap().as_deref(),
        Some("bafyreiupdate"),
        "the update is now the DID's tip"
    );
    assert!(
        log.append(&record(
            &did,
            "bafyreiupdate",
            "plc_operation",
            Some("bafyreigenesis2"),
        ))
        .await
        .is_err(),
        "an identical replay is rejected by the unique cid index"
    );
}

// NO CHAIN FORK: a given `prev` may be chained onto at most once, so two
// DIFFERENT operations (distinct cids, which UNIQUE(cid) does NOT catch) cannot
// both land. This is what stops concurrent handle updates forking the chain.
#[tokio::test]
async fn two_different_operations_cannot_chain_the_same_prev() {
    let (pool, _db) = fresh_pool().await;
    let log = PgPlcOperationLog::new(pool);
    let did = Did::new("did:plc:oplog-fork");

    log.append(&record(&did, "bafyreigenesis3", "plc_operation", None))
        .await
        .expect("append the genesis");
    log.append(&record(
        &did,
        "bafyreiupdatex",
        "plc_operation",
        Some("bafyreigenesis3"),
    ))
    .await
    .expect("the first update chains onto the genesis");

    assert!(
        log.append(&record(
            &did,
            "bafyreiupdatey",
            "plc_operation",
            Some("bafyreigenesis3"),
        ))
        .await
        .is_err(),
        "a SECOND, different op chaining the same prev is rejected — the chain cannot fork"
    );
}

// Two DIFFERENT DIDs may each have a genesis (`prev IS NULL`) — the no-fork
// index is partial precisely so it does not collapse every genesis into one row.
#[tokio::test]
async fn genesis_operations_are_exempt_from_the_no_fork_index() {
    let (pool, _db) = fresh_pool().await;
    let log = PgPlcOperationLog::new(pool);

    for (did, cid) in [
        ("did:plc:oplog-g1", "bafyreig1"),
        ("did:plc:oplog-g2", "bafyreig2"),
    ] {
        log.append(&record(&Did::new(did), cid, "plc_operation", None))
            .await
            .expect("each DID may have its own genesis");
    }
}

// `latest_op` returns the tip in full (cid, type, prev, JSON) so an update can
// carry the prior operation's public fields forward without decrypting custody.
#[tokio::test]
async fn latest_op_returns_the_full_most_recent_record() {
    let (pool, _db) = fresh_pool().await;
    let log = PgPlcOperationLog::new(pool);
    let did = Did::new("did:plc:oplog-latestop");

    assert!(
        log.latest_op(&did).await.unwrap().is_none(),
        "no operations logged yet"
    );

    log.append(&record(&did, "bafyreigenesis4", "plc_operation", None))
        .await
        .expect("append the genesis");
    log.append(&record(
        &did,
        "bafyreiupdatez",
        "plc_operation",
        Some("bafyreigenesis4"),
    ))
    .await
    .expect("append the update");

    let latest = log
        .latest_op(&did)
        .await
        .unwrap()
        .expect("an operation is logged");
    assert_eq!(latest.did, did);
    assert_eq!(latest.cid, "bafyreiupdatez", "the most recent operation");
    assert_eq!(latest.op_type, "plc_operation");
    assert_eq!(latest.prev.as_deref(), Some("bafyreigenesis4"));
    let json: serde_json::Value =
        serde_json::from_str(&latest.operation_json).expect("operation_json is valid JSON");
    assert_eq!(
        json["type"], "plc_operation",
        "the stored operation body round-trips"
    );
    assert_eq!(
        latest.op_mac,
        vec![0xEE; 32],
        "the integrity tag round-trips — the minter needs it back to verify"
    );
}

// The unique cid index rejects a duplicate append outright — a content-addressed
// operation is logged at most once, whatever its type claims.
#[tokio::test]
async fn a_duplicate_cid_is_rejected() {
    let (pool, _db) = fresh_pool().await;
    let log = PgPlcOperationLog::new(pool);
    let did = Did::new("did:plc:oplog-dup");

    log.append(&record(&did, "bafyreidup", "plc_operation", None))
        .await
        .expect("the first append");
    assert!(
        log.append(&record(&did, "bafyreidup", "plc_tombstone", None))
            .await
            .is_err(),
        "the unique cid index rejects a duplicate"
    );
}
