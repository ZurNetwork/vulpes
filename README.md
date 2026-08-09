# zurid

**AT Protocol identity for Rust servers — the `did:plc` write path.**

Reading an atproto identity is well served in Rust. *Operating* one is not.
Minting a `did:plc`, custodying its keys, re-pointing its handle and tombstoning
it are a byte-exact signing problem with a durability problem wrapped around it,
and every server that has needed it so far has written its own. zurid is that
code, extracted from a production service and made reusable.

It is deliberately narrow. zurid does identity — mint, update, tombstone, custody,
handle syntax, OAuth session storage — and nothing else. It holds no product
policy: no reserved-name lists, no rate limits, no quarantine windows. Those are
yours.

```toml
[dependencies]
zurid = { git = "https://github.com/ZurNetwork/zurid", tag = "v0.1.0" }
```

Not published to crates.io; consume it as a tag-pinned git dependency.

---

## What it does

```rust
use std::sync::Arc;
use zurid::{Handle, MintPolicy, Minter, NoopPlcDirectory};

let minter = Minter::new(keys, log, Arc::new(NoopPlcDirectory), MintPolicy::identity_only())?;

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
| *(core)* | always | the `did:plc` operation format, `Did`, `Handle`, `SecretVault`, `CustodyKeys`, the storage traits, `MintPolicy`, `NoopPlcDirectory` |
| `minter` | ✅ | `Minter` — key generation, mint / update-handle / tombstone |
| `directory` | ✅ | `HttpPlcDirectory` — submission over HTTP (`reqwest`) |
| `oauth` | | `oauth::Authenticator` and the sealed, durable state bridge (`jacquard`) |
| `postgres` | | sqlx implementations of every storage trait, plus the migration SQL |
| `axum` | | `/.well-known/atproto-did` as a mountable router |

Every feature compiles alone, and `--no-default-features` leaves a pure
protocol core with no crypto and no I/O.

### core — the operation format

```rust
use zurid::plc::{PlcDocument, PlcOperation, derive_did};

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

`Minter::new(key_store, op_log, directory, policy)`. Ordering is the durability
story, and the two directions are not an accident:

- **mint** — custody keys → log the genesis → submit. Keys land before anything
  is published, so a failed submission never orphans an identity.
- **update / tombstone** — submit → log. A failed submission must not advance the
  local chain, so a retry re-reads the same `prev` and re-signs the *same*
  operation.

Signing is RFC 6979 deterministic, which is what makes a replayed update
detectable (it collides on `UNIQUE(cid)`) and a blind retry safe.

### `directory` — submitting operations

```rust
let directory = zurid::HttpPlcDirectory::canonical();   // https://plc.directory
```

Or `NoopPlcDirectory` while you are building — it accepts every operation and
publishes nothing, so you can exercise the whole path without registering
identities you do not mean to keep.

### `postgres` — storage, included

```rust
zurid::postgres::migrate(&pool).await?;

let keys = Arc::new(zurid::postgres::PgKeyStore::new(pool.clone(), vault));
let log  = Arc::new(zurid::postgres::PgPlcOperationLog::new(pool.clone()));
let oauth_state = zurid::postgres::PgOAuthStateStore::new(pool);
```

The migrations ship two ways: embedded (call `migrate`) or as files under
`migrations/`, to copy into your own directory if you would rather own the
versioning. Pick one.

The DDL is plain `CREATE TABLE`, not `CREATE TABLE IF NOT EXISTS`: zurid's names
are unprefixed and could collide with a table you already own, and `IF NOT
EXISTS` would record that collision as a *successful* migration that created
nothing — after which zurid reads and writes a schema it does not control. Each
migration runs in a transaction, so a collision fails the call, records nothing,
and leaves your table untouched.

### `oauth` — sign-in over atproto

```rust
let auth = zurid::oauth::Authenticator::new(
    zurid::oauth::OAuthConfig::loopback(redirect_uri)?,   // http://127.0.0.1 or http://[::1]
    oauth_state,
    vault,
)?;

let handle = Handle::try_new("alice.example.com")?;
let url = auth.start(&handle).await?;                                  // redirect here
let did = auth.complete(code, state, iss).await?;                      // at your callback
```

`jacquard` does the protocol; zurid makes its state durable *and* encrypted, and
keeps the protocol library behind one seam. Currently builds a loopback client —
see [FORKS.md](FORKS.md) F13.

> **⚠ SSRF: install a guarded connector.** `start` takes a validated `Handle`,
> never a string, so an attacker cannot pass `https://169.254.169.254/…` and
> reach the resolver's "this input is a service URL, fetch it" branch. That is
> the only part zurid closes. Once a handle is accepted, `jacquard` fetches
> `https://<handle>/.well-known/atproto-did`, then whatever `serviceEndpoint`
> the DID document names — **with no host or scheme guard of its own**, on names
> the visitor controls and which may resolve to a loopback or link-local address
> (including on a re-resolve, i.e. DNS rebinding). zurid's default client sets
> connect and request timeouts but filters no addresses. Supply your own via
> `Authenticator::with_client(config, store, vault, client)` — a `reqwest::Client`
> whose connector refuses private, loopback, link-local and unique-local
> destinations. Which ranges are private is a deployment fact this crate cannot
> know, so it does not guess.

### `axum` — serving handle resolution

```rust
Router::new()
    .merge(zurid::axum::atproto_did_router(resolver, HandleDomain::try_new("example.com")?))
```

Serves `GET /.well-known/atproto-did`, answering only for subdomains of the
namespace you name — at a real label boundary, so `evil-example.com` is not a
subdomain of `example.com`. Mount it outside your CSRF and session layers; a
resolver carries neither.

The authority is read from the request URI (HTTP/2 and HTTP/3 send no `Host`
header — it rides `:authority`) with the `Host` header as the fallback, so the
same handle resolves over every protocol version. Because the answer depends on
the authority rather than the path, every response carries `Vary: Host` and
`Cache-Control: no-store`.

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

**Envelope encryption.** One 32-byte root key (`SecretVault`) wraps every at-rest
secret with XChaCha20-Poly1305 — custody keys and OAuth state alike. A database
compromise alone yields nothing usable. **The root key's custody is yours**: a
config or environment variable is fine for development and is *not* a hardware
boundary. For real identities, keep it in a KMS or HSM. The seam is one type
wide, so that swap is not a schema change.

**Associated data binds a blob to its row, and each family is tagged.** Custody
is sealed under `zurid.custody\0` + its DID; OAuth state under a table-name tag
+ its primary key, length-prefixed so the same bytes cannot be re-split into a
different key. An attacker with database *write* access cannot lift one
identity's keys onto another DID, one user's session onto another row, or a blob
of one family onto another — the tag check fails. Which scheme sealed a custody
blob is recorded per row (`key_version`) and **read back**: an unknown version is
an error, never a guess.

**Fails closed.** A value that will not open is an error, never a `None`. A
legacy plaintext row, a tampered blob, the wrong root key — all error at the
read. Absence and failure are kept apart on purpose: conflating them turns a
database fault into "this session does not exist".

**Keys are zeroized and redacted.** `SecretKey` wipes on drop, and so does
`SecretVault`'s root key — every clone independently, since each holds its own
copy. That matters most for the root key: it is the one whose disclosure loses
every other secret at once, so leaving it in freed heap for a crash dump to pick
up would undo the envelope model. Both types' `Debug` prints `<redacted>`. A
routine update decrypts exactly one private key, the signer; the rest of custody
stays sealed.

**The chain cannot fork.** Two concurrent updates would otherwise read the same
tip, build *different* operations (different CIDs, so uniqueness on `cid` does
not catch them) and both land — after which your log permanently disagrees with
the directory, which accepted only the first, and every future handle change is
wedged. A partial `UNIQUE(did, prev) WHERE prev IS NOT NULL` index makes that
unrepresentable; the loser's write fails, the error propagates, and the retry
serializes onto the new tip.

**No unsafe code**, enforced by `#![forbid(unsafe_code)]`.

---

## Testing

```bash
cargo test --all-features     # needs a container runtime for the PostgreSQL suite
cargo test                    # core + minter + directory, no containers
```

The PostgreSQL suite boots throwaway containers via `testcontainers` (pinned to
`postgres:16-alpine`) and clones a migrated template per test, so every test gets
a pristine database for tens of milliseconds. `DOCKER_HOST` is honored — podman
works.

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
