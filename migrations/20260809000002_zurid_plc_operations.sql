-- zurid: the append-only log of PLC operations submitted for each minted
-- did:plc.
--
-- A did:plc is a chain of operations: every non-genesis operation references the
-- CID of the DID's most recent operation as its `prev`. This log is the
-- operator's own record of what was published — enough to chain the next
-- operation and to audit against the canonical directory later.
--
-- seq        Monotonic insertion order; the DID's latest operation is its
--            highest `seq`. A surrogate key, so the same `cid` can never wedge
--            an insert.
-- did        The did:plc this operation belongs to. Deliberately NO foreign key:
--            the genesis operation is logged during minting, before any
--            application row exists, and a tombstone is logged as that row is
--            being deleted.
-- cid        The content id (CIDv1 / dag-cbor / sha-256, base32 `b…`) of the
--            signed operation — the value a subsequent operation references as
--            its `prev`. Globally unique by construction.
-- type       The operation `type` discriminant: `plc_operation` or
--            `plc_tombstone`.
-- prev       The CID this operation chained onto, or NULL for a genesis
--            operation.
-- operation  The signed operation as submitted, JSON. Kept for audit and replay;
--            it never contains private key material (only public keys, handles,
--            and a signature).
-- created_at When the operation was logged. Application-supplied.
CREATE TABLE plc_operations (
    seq        bigserial   PRIMARY KEY,
    did        text        NOT NULL,
    cid        text        NOT NULL UNIQUE,
    type       text        NOT NULL,
    prev       text,
    operation  jsonb       NOT NULL,
    created_at timestamptz NOT NULL
);

-- The hot path is "the DID's most recent operation" (the `prev` for the next
-- one): filter by did, take the highest seq.
CREATE INDEX plc_operations_did_seq ON plc_operations (did, seq DESC);

-- NO CHAIN FORK. A minted did:plc is a strictly LINEAR chain: every non-genesis
-- operation chains onto exactly one `prev`, and a given operation may be chained
-- onto AT MOST ONCE.
--
-- Without this, two concurrent handle updates both read the same `latest_cid` as
-- their `prev`, build DIFFERENT operations (different `cid`, so the UNIQUE(cid)
-- constraint does not catch them), and both append — forking the local chain.
-- `latest_cid` would then return whichever landed last, and the log would
-- permanently disagree with the canonical directory's real tip: the directory
-- accepts only the first operation chaining a given `prev`, and because the fork
-- is signed by the same key there is no higher-authority override to resolve it.
-- Every subsequent handle change would be wedged.
--
-- A partial UNIQUE index over (did, prev) makes a non-genesis fork
-- UNREPRESENTABLE: the losing concurrent writer's INSERT fails, zurid's
-- benign-replay guard (which returns Ok only when the log's tip already IS its
-- own operation) sees a DIFFERENT tip, propagates the error, and the caller's
-- retry re-reads the new tip and chains onto it — serializing concurrent writers
-- into one linear chain.
--
-- Scoped `WHERE prev IS NOT NULL`: a genesis operation has `prev = NULL` and is
-- already one-per-DID by construction (its hash defines the DID), and PostgreSQL
-- treats NULLs as distinct, so genesis rows are correctly exempt.
CREATE UNIQUE INDEX plc_operations_did_prev_unique
    ON plc_operations (did, prev)
    WHERE prev IS NOT NULL;
