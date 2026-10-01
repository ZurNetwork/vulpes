# vulpes

**The ACP (Attested Claims Protocol) on AT Protocol, and the `did:plc` write path it binds.**

Reading an atproto identity is well served in Rust. *Operating* one is not.
Minting a `did:plc`, custodying its keys, re-pointing its handle and tombstoning
it are a byte-exact signing problem with a durability problem wrapped around it,
and every server that has needed it so far has written its own. vulpes is that
code, extracted from a production service and made reusable.

It is deliberately narrow. vulpes enforces the ACP — claim and attestation
records, signing, status lists, verification — and does the identity work the
protocol binds: mint, update, tombstone, custody, handle syntax. It carries no
transport or framework of its own: storage and the network arrive through traits
you implement. And it holds no product policy: no reserved-name lists, no rate
limits, no quarantine windows. Those are yours.

```toml
[dependencies]
vulpes = { git = "https://github.com/ZurNetwork/vulpes", tag = "v0.1.0" }
```

Not published to crates.io; consume it as a tag-pinned git dependency.

---

## What it does

```rust
use std::sync::Arc;
use vulpes::{Handle, MintPolicy, Minter, NoopPlcDirectory};

// `vault` is the SecretVault: the minter seals custody and MACs the log with it.
let minter = Minter::new(keys, log, Arc::new(NoopPlcDirectory), MintPolicy::identity_only(), vault)?;

let did = minter.mint(&Handle::try_new("alice.example.com")?).await?;
minter.update_handle(&did, &Handle::try_new("alice.example.org")?).await?;
minter.tombstone(&did).await?;
```

Under that: three secp256k1 keypairs generated, a canonical DAG-CBOR genesis
operation built from an explicit policy and signed with the right rotation key,
the DID derived from that operation's own hash, the private halves sealed and
stored, the operation logged so the next one knows its `prev`, and the whole
thing submitted to a PLC directory as a separate retryable step.

The byte pipeline is pinned to a real published vector
(`did:plc:ewvi7nxzyoun6zhxrhs64oiz`) — DID derivation *and* CID computation. If
canonical ordering, the hash, the base32 or the truncation ever drift, the suite
fails before anything ships.

---

## Features

| feature | default | brings |
|---|---|---|
| *(core)* | always | the `did:plc` operation format, `Did`, `Handle`, `SecretVault`, `CustodyKeys`, the storage traits, `MintPolicy`, `PlcDirectory` / `NoopPlcDirectory` |
| `minter` | ✅ | `Minter` — key generation, mint / update-handle / tombstone |
| `acp` | | the Attested Claims Protocol — records, signing, status lists, the verifier over caller-implemented ports |

Every feature compiles alone, and `--no-default-features` leaves a pure
protocol core with no crypto and no I/O.

### core — the operation format

```rust
use vulpes::plc::{PlcDocument, PlcOperation, derive_did};

let document = PlcDocument::identity_only(rotation_keys, signing_key, "alice.example.com");
let operation = PlcOperation::genesis(document);
let signature = your_key.sign(&operation.signing_bytes()?)?;      // ECDSA-SHA256, low-S
let signed = operation.into_signed(base64url_no_pad(&signature));

let did = signed.did()?;   // did:plc:…  — the hash of these very bytes
let cid = signed.cid()?;   // bafyrei…   — what the next operation chains onto
```

Two serializations, deliberately different: `signing_bytes()` omits `sig`,
`did()`/`cid()` include it. Hashing the wrong one derives an identity nobody
signed, so the two are separate methods with separate tests.

### `minter` — the write path

`Minter::new(key_store, op_log, directory, policy, vault)`. The vault is what
makes the minter the one place that seals custody before it reaches a `KeyStore`
and MACs each logged operation — so a store never holds a plaintext key or an
unauthenticated row. Ordering is the durability story, and the two directions
are not an accident:

- **mint** — custody keys → log the genesis → submit. Keys land before anything
  is published, so a failed submission never orphans an identity.
- **update / tombstone** — submit → log. A failed submission must not advance the
  local chain, so a retry re-reads the same `prev` and re-signs the *same*
  operation.

Signing is RFC 6979 deterministic, which is what makes a replayed update *or
tombstone* detectable (it collides on `UNIQUE(cid)`) and a blind retry safe:
both treat "the identical operation already landed" as success, so a caller
unsure whether an append committed can retry without erroring or double-writing.

### Submitting operations

`PlcDirectory` is the seam a signed operation goes out through. Implement it over
your own HTTP client — its timeouts and egress policy are yours; vulpes ships no
client. A `did` reaches `submit` as a `&str`: parse it as a `Did` before it goes
into a URL. `NoopPlcDirectory` accepts every operation and publishes nothing, so
you can exercise the whole path without registering identities you do not mean
to keep.

### Storage — yours

vulpes owns no database. `KeyStore` and `PlcOperationLog` are the two roles it
persists through; implement them over whatever you store with. A `KeyStore` only
ever receives `SealedKeys` — sealing lives in the minter — so it stores bytes. A
`PlcOperationLog` must enforce the two integrity properties its trait documents;
in SQL that is a `UNIQUE(cid)` constraint and a partial
`UNIQUE(did, prev) WHERE prev IS NOT NULL` index.

---

## The policy preset

Everything about a genesis operation that is a *choice* lives in `MintPolicy`,
never hard-coded:

```rust
pub struct MintPolicy {
    pub rotation_keys: Vec<KeyRole>,                    // descending authority, 1–5, no duplicates
    pub signer: KeyRole,                                // must be a listed rotation key
    pub verification_methods: BTreeMap<String, KeyRole>,
    pub services: BTreeMap<String, PlcService>,
}
```

`MintPolicy::identity_only()` is the named preset — a valid, resolvable
`did:plc` with **no** repository behind it, the pattern feed generators and
labelers use:

- `rotationKeys = [cold-recovery, operational]`, descending authority. Index 0 is
  left to the coldest key so a *user-held* recovery key can be enrolled above the
  platform's own later.
- The **operational** key signs. Any listed rotation key may sign, and using the
  lower-authority one keeps the recovery key off the signing path from birth.
- One `atproto` verification method.
- No services.

It is validated at `Minter::new`, against the spec's own limits (1–5 rotation
keys with no duplication, at most 10 verification methods), so a
misconfiguration fails at boot rather than at the first mint.

A policy that *does* declare a PDS works the same way, and can update the
identities it mints — the update carries the prior operation's public document
fields forward verbatim and refuses any shape the policy does not describe,
rather than rebuilding a default that would silently drop a service binding.

---

## Security posture

**Envelope encryption.** One 32-byte root key (`SecretVault`) wraps custody keys
at rest with XChaCha20-Poly1305. A database compromise alone yields nothing
usable. **The root key's custody is yours**: a
config or environment variable is fine for development and is *not* a hardware
boundary. For real identities, keep it in a KMS or HSM. The seam is one type
wide, so that swap is not a schema change.

**Associated data binds a blob to its row, and the family is tagged.** Custody
is sealed under `vulpes.custody\0` + its DID. An attacker with database *write*
access cannot lift one identity's keys onto another DID, or a blob sealed for
another purpose under the same root key onto a custody row — the tag check
fails. Which scheme sealed a custody
blob is recorded per row (`key_version`) and **read back**: an unknown version is
an error, never a guess.

**Fails closed.** A value that will not open is an error, never a `None`. A
legacy plaintext row, a tampered blob, the wrong root key — all error at the
read. Absence and failure are kept apart on purpose: conflating them turns a
database fault into "these keys do not exist".

**Keys are zeroized and redacted.** `SecretKey` wipes on drop, and so does
`SecretVault`'s root key — every clone independently, since each holds its own
copy. That matters most for the root key: it is the one whose disclosure loses
every other secret at once, so leaving it in freed heap for a crash dump to pick
up would undo the envelope model. Both types' `Debug` prints `<redacted>`. A
routine update decrypts exactly one private key, the signer; the rest of custody
stays sealed.

**The operation log is authenticated.** An update carries a prior operation's
rotation keys, verification methods and services forward into an operation the
custody key then *signs* — so an attacker who can *write* your operation log
could otherwise choose what gets signed. Every row carries an HMAC-SHA256
tag over its `(did, cid, prev, operation)`, keyed by a subkey HKDF-derived from
the root key (so the AEAD key stays single-purpose), and the minter verifies it
before trusting a prior row. The tag key is not in the database, so a write-access
attacker cannot forge it: a tampered row fails the check and is refused, not
signed. Custody itself is never trusted from a store either — it is sealed
(`SealedKeys`) and only the minter opens it.

**The chain cannot fork.** Two concurrent updates would otherwise read the same
tip, build *different* operations (different CIDs, so uniqueness on `cid` does
not catch them) and both land — after which your log permanently disagrees with
the directory, which accepted only the first, and every future handle change is
wedged. The `PlcOperationLog` contract has your store refuse a second operation
chaining the same `prev`, which makes that unrepresentable; the loser's write
fails, the error propagates, and the retry serializes onto the new tip.

**No unsafe code**, enforced by `#![forbid(unsafe_code)]`.

**Dependency advisories are a CI gate.** `cargo deny --all-features check
advisories` runs on every PR, and nothing is allow-listed today. A new advisory
fails the job until it is fixed, or allow-listed in `deny.toml` with why it is
not exploitable here and what would retire the entry.

---

## Testing

```bash
cargo test --all-features
```

Pure unit tests: no services, no containers. The storage contract is exercised
against in-memory fakes that enforce the same integrity properties a real store
must.

---

## Status

Pre-1.0 and honest about it. The API will move. `FORKS.md` records every judgment
call made during the extraction that the original code did not settle, including
the ones still open.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
