-- vulpes: custody store for the private keys behind a minted did:plc.
--
-- When an identity is minted, per-identity secp256k1 keypairs are generated (a
-- cold-recovery key, an operational key, and a signing key backing the atproto
-- verification method) and the private halves must be kept so the DID can be
-- operated later. These are the most sensitive rows the library writes, so they
-- are NEVER stored in the clear: every bundle is envelope-encrypted under a root
-- key held OUTSIDE the database (see vulpes::SecretVault). A database compromise
-- alone therefore yields no usable key material.
--
-- did           The identity's did:plc — the natural, unique key. There is
--               deliberately NO foreign key to any application table: custody is
--               written DURING minting, before the application's own row can
--               exist (the DID is derived from the very operation these keys
--               sign). One DID mints once, so the PRIMARY KEY also enforces
--               "custody written at most once".
-- wrapped_keys  The AEAD ciphertext: a random per-row nonce followed by the
--               sealed bundle of the three 32-byte secp256k1 private scalars,
--               with the DID bound in as associated data so a blob cannot be
--               lifted onto another row. Opaque bytes; only a holder of the root
--               key can open it.
-- key_version   The envelope scheme / root-key generation, so keys can be
--               re-wrapped under a new root key (or a KMS) later without a
--               data-migration guess.
-- created_at    When custody was taken. Application-supplied (no DEFAULT now()).
CREATE TABLE account_keys (
    did          text        PRIMARY KEY,
    wrapped_keys bytea       NOT NULL,
    key_version  integer     NOT NULL DEFAULT 1,
    created_at   timestamptz NOT NULL
);
