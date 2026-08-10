# FORKS — judgment calls made during the extraction

Every decision here is one the source code did not settle: a name, a module
boundary, an error shape, a packaging choice. Each was resolved by the rule the
extraction was given — **choose the option that keeps the originating service's
later consumption diff smallest** — except where that rule pointed at something
actively wrong for a public library, in which case the reasoning is spelled out.

Nothing here changes protocol behaviour. The one place where a behavioural fork
appeared is **F8**, and it is left open for the Engineer rather than decided.

Source: `zurfur/backend/crates/{adapter-atproto,adapter-pg,domain,api}`.
Spec facts cited below were verified against
<https://web.plc.directory/spec/v0.1/did-plc> and the W3C DID Core ABNF, not
recalled.

---

## Open — needs an Engineer call

### F32. `time` 0.3.47 would fix RUSTSEC-2026-0009 but costs the 1.85 MSRV

**Where:** `deny.toml`, the `RUSTSEC-2026-0009` entry.

The advisory (stack exhaustion parsing RFC 2822 dates) reaches zurid only as a
**dev-dependency**, through `testcontainers → bollard → time 0.3.45`. It is
never in a consumer's build, and nothing here parses RFC 2822 at all.

A fix exists — `time` 0.3.47 — and `cargo update -p time --precise 0.3.47`
resolves cleanly. It requires **Rust 1.88**, and the manifest promises
`rust-version = "1.85"`. Taking it would raise the version needed to run the
test suite while leaving the library's own MSRV untouched, which is a
compatibility promise to change deliberately rather than as a side effect of an
audit. Allow-listed with this note instead; the Engineer's call.

### F31. Migration files are edited in place, pre-1.0

**Where:** `migrations/`.

The three migrations were **modified after they were first written** (the
`IF NOT EXISTS` removal, the `auth_request.created_at` index). sqlx checksums
migration files, so any database that already applied an older copy will fail
`migrate` with a version mismatch rather than silently diverging — which is the
correct behaviour, and safe while zurid is unreleased and unadopted. From the
first tagged release, a change to shipped DDL must be a **new** migration
instead. Called out here rather than assumed.

---

## Ruled by the Engineer

### F8. An update refuses a prior operation the policy does not describe — **strict, ruled**

**Where:** `src/minter.rs`, `Minter::carry_forward`.

The source refuses to build a handle update when the DID's latest operation is
not identity-only, with the comment *"carrying those forward is not
implemented"* and an error naming verbatim carry-forward as the extension point.
That guard was hard-coded to one shape, which a parameterized library cannot
keep: a `MintPolicy` that declares a PDS would mint operations its own updater
then refuses.

**Shipped:** the guard is generalized, not removed. An update carries the prior
operation's `rotationKeys`, `verificationMethods` and `services` forward
**verbatim**, but first checks that the prior shape is the one this policy mints
(verification-method IDs equal, services equal). Anything else is refused.

- Under `MintPolicy::identity_only()` — the preset the source runs — behaviour is
  **identical**, including the refusal of a PDS-bearing prior.
- A PDS-bearing policy can now update the identities it mints, which the
  hard-coded guard could not express.

**Ruled (Engineer): keep strict.** An update never carries an *arbitrary* prior
shape forward — one the operator's policy does not describe. A richer DID is a
richer `MintPolicy`, never a bypass of the shape check: to operate identities
with a PDS or extra verification methods, configure a policy that declares them,
and the same-shape check then passes. The permissive alternative — carry whatever
the row declares, so a binding added out of band silently survives an operation
the operator believes they control — is not offered. The `#[ignore]`d
placeholder test that held its place is deleted.

### F29. `Authenticator::start` takes a `Handle`, and the connector is the caller's

**Where:** `src/oauth/mod.rs`, `Authenticator::{start, with_client}`.

The source passes the raw login string straight to jacquard. jacquard's resolver
treats an input beginning `https://` as a PDS/entryway URL and **fetches it
directly**, so a raw string is an attacker-steered outbound request — the
classic SSRF shape. `start` therefore takes a validated `Handle`: a handle's
charset (`[a-z0-9-]` plus dots) cannot spell a scheme, so that branch is
unreachable by construction rather than by a check that can be forgotten.

That closes the *input*, not the *fetches the protocol requires*. jacquard still
resolves `https://<handle>/.well-known/atproto-did` and then whatever
`serviceEndpoint` the DID document names, with no host or scheme guard of its
own. `Authenticator::with_client` was added (mirroring
`HttpPlcDirectory::with_client`) so a deployment can install an SSRF-guarded
connector; the default client sets connect and request timeouts but deliberately
filters no addresses, because which ranges are private is a deployment fact.
Documented prominently on the module and in the README.

Consumption impact: `auth.start(&handle)` instead of `auth.start(&str)` — the
call site almost always already has a `Handle`.

### F13. OAuth clients are loopback-only — **ruled for v0.1.0**

**Where:** `src/oauth/mod.rs`, `OAuthConfig`.

The source builds `AtprotoClientMetadata::new_localhost`, deriving the
`client_id` from the redirect URI list. That is the localhost-development shape
of an atproto OAuth client; a public deployment eventually serves a hosted
`client_metadata.json` instead.

**Ruled (Engineer): loopback-only is deliberate for v0.1.0.** No hosted
public/confidential client is built now. `OAuthConfig::loopback` validates the
redirect against the two loopback literals (S1), and that is the whole surface
for this release. A hosted-metadata variant is a purely **additive** change to
`OAuthConfig` — a new constructor beside `loopback`, no reshape — gated on a
consumer actually needing it, so it is not speculatively built. Documented as a
limitation on the type and in the README.

---

## Naming

### F1. Error taxonomy: closed enums, plus two opaque wrappers

The source uses `anyhow::Result` throughout. A library returning `anyhow` gives
callers nothing to match on, so zurid uses `thiserror` enums per concern —
`HandleError`, `DidError`, `VaultError`, `PlcError`, `PolicyError`, `MintError`,
`oauth::AuthError` — each naming its own failure modes.

Two errors *cannot* be closed, because the implementation is the caller's:
`StorageError` and `DirectoryError` are opaque newtypes over
`Box<dyn Error + Send + Sync>` with a `new` constructor and the cause preserved
as `source()`. `anyhow::Error` converts into that box, so an implementation
written in the source's style is a `.map_err(StorageError::new)` away.

Consumption impact: every zurid error implements `std::error::Error`, so `?` into
an `anyhow` context works unchanged.

### F2. `Did` drops `Deref`, gains the std conversions

The source's `Did` derefs to `String`, which leaks `String`'s whole API onto a
domain type (`did.push_str(…)` compiles). Replaced with `as_str`, `Display`,
`AsRef<str>`, `Borrow<str>`, `From<Did> for String`.

`Did::new` is kept unchecked, for values from trusted sources — re-validating
what the network already accepted can only reject data that legitimately exists.
`FromStr` / `TryFrom<&str>` / `TryFrom<String>` were **added**, validating the
W3C DID Core ABNF, for untrusted input.

Consumption impact: a handful of `.as_str()` insertions where `Deref` was doing
the work.

### F3. `AccountKeys` → `CustodyKeys`, and `KeyRole` is new

"Account" is the originating service's entity, meaningless in a library that
knows only identities. The three fields (`cold_recovery`, `operational`,
`signing`) and their order are unchanged, so the sealed on-disk format is
byte-identical. `KeyRole` is new: `MintPolicy` needs to name a key without
positional indexing.

Consumption impact: one line —
`pub use zurid::CustodyKeys as AccountKeys;` — if the old name is wanted.

### F4. One vault type, two callers

`adapter-atproto::secret_vault::SecretVault` and
`adapter-pg::key_vault::RootKey` were the same XChaCha20-Poly1305 envelope
written twice, flagged in-source as wanting unification. Unified as
`SecretVault` (the better name: it describes the thing, not its key), with the
generic `seal(aad, plaintext)` / `open(aad, blob)` pair.

`RootKey::wrap`/`unwrap` — which also did the three-scalar bundling — became
`CustodyKeys::seal(&vault, &did)` / `CustodyKeys::open(&vault, &did, blob)`. The
bundling lives with the type it bundles, so a non-PostgreSQL `KeyStore` gets it
for free rather than reimplementing it.

Blob format, nonce length, AAD binding and the on-disk bytes are unchanged.

### F6. `PlcDocument` is new; `identity_only` / `update_handle` became
`genesis` / `update`

The source's `PlcOperation::identity_only(...)` and `::update_handle(...)` bake
one document shape into the constructor names. Split into a `PlcDocument` value
(the public fields an operation asserts) and `PlcOperation::genesis(document)` /
`::update(document, prev)` — which is also what makes the update's
carry-forward expressible as data rather than as a second constructor.
`PlcDocument::identity_only(...)` preserves the convenience of the old call.

### F7. The preset is named for its shape, not its first consumer

The ruling asked for the originating behaviour as a *named preset*.
`MintPolicy::identity_only()` names what it produces; `MintPolicy::zurfur()`
would name who asked for it, which ages badly in a public crate. `Default` is
`identity_only()`. The doc comment states it is exactly the shipped
configuration of the service this came from.

### F22. `HandleDomain` is a newtype

The source carries the well-known route's namespace as a bare `String` on its
config struct. A library taking `&str` there would silently never match on a
typo or an uppercased value, so `HandleDomain::try_new` validates and normalizes
through the same `Handle` rules — a misconfiguration fails at construction.

### F26. `HandleResolver` is a new trait

The route was written against the service's own `AccountStore`. Generalized to a
one-method `HandleResolver` trait, which is what the `axum` feature actually
needs.

---

## Module layout

### F14. The OAuth split: storage stores bytes, the bridge does the sealing

The source's `AtprotoAuthStore` implemented jacquard's `ClientAuthStore`
*directly* over PostgreSQL, doing serialization, sealing and SQL in one type.
zurid splits it:

- `OAuthStateStore` (core, no jacquard) — opaque byte blobs, six methods.
- `oauth::JacquardAuthStore<S>` — implements `ClientAuthStore` over any
  `OAuthStateStore`, and owns the JSON encoding and the sealing.
- `postgres::PgOAuthStateStore` — the SQL, and nothing else.

Two reasons: a storage backend can be written with no OAuth knowledge, and the
encryption exists in exactly one place, so a new backend cannot forget it. It
also keeps the feature graph simple — `postgres` alone compiles without
`jacquard`.

The AAD construction (table-name domain separation, the length-prefixed DID) is
carried over byte-for-byte.

### F33. `KeyStore` trades in sealed blobs, not plaintext (security review S7)

**Where:** `src/store.rs` (`KeyStore`), `src/keys.rs` (`SealedKeys`),
`src/postgres/key_store.rs`, `src/minter.rs`.

The extraction left one asymmetry: the OAuth store (F14) never saw a plaintext
secret, but the `KeyStore` took plaintext `CustodyKeys` and `PgKeyStore` did the
sealing — so a `KeyStore` implementation *could* write plaintext scalars, the
exact footgun F14 removed for tokens. Engineer ruled the reshape.

`KeyStore` now trades in `SealedKeys` — an opaque newtype over the AEAD
ciphertext plus its `CustodyEnvelope` version. The `Minter` (which now holds the
`SecretVault`) owns seal-before-put and open-after-get; `PgKeyStore` holds no
vault and never opens a blob, so a plaintext custody store is unrepresentable,
the same as a plaintext OAuth store. The H4 unknown-version rejection moved with
the opening — it now fires in the `Minter`, not the store. The on-disk columns
(`wrapped_keys`, `key_version`) and the sealed bytes are unchanged, so existing
rows are untouched.

Consumption impact: `Minter::new` gains a `vault` argument; `PgKeyStore::new`
drops its `vault` argument.

### F30. Operation-log integrity — HMAC (security review B2, Engineer ruled)

**Where:** `src/store.rs` (`op_mac`, `mac_message`), `src/vault.rs`
(`oplog_mac`), `src/minter.rs` (`maced` / `verify_mac`), migration
`20260809000004`.

`update_handle` reads the DID's latest logged operation and carries its
`rotationKeys`, `verificationMethods` and `services` forward into an operation it
then **signs**. Nothing authenticated that row, so whoever could write
`plc_operations` chose what the custody key signs — the signing oracle B2 named.
Of the candidate mitigations (HMAC column / verify the stored `sig` / re-derive
from custody), the **Engineer ruled HMAC**.

Each row carries an `op_mac`: HMAC-SHA256 over a length-prefixed
`(did, cid, prev, operation)`, keyed by a subkey HKDF-derived from the vault root
key (label `zurid.oplog.mac.v1`) — a *dedicated* subkey, so the AEAD root key
stays single-purpose. The minter writes it on every append and **verifies it
before trusting a prior row** (in `carry_forward` and in `tombstone`, which reads
the prior for its `prev`). A row altered by a write-access attacker fails the tag
and is refused rather than signed. The operation is canonicalized (re-serialized
sorted-key JSON) so the tag survives the `jsonb` round-trip.

This is what H8's `check_prior_rotation_keys` is *not*: H8 is an availability
guard (a malformed-but-genuine row must not wedge the identity) that now runs
after the MAC has already established authenticity.

Fresh crate, so no backfill: `op_mac` is nullable and a NULL (a row from before
the column) reads back as an empty tag that fails verification — fail closed.
**Zurfur's adoption ticket owns backfilling its existing `plc_operations`
rows**; a fresh install never has any.

### F15. `Authenticator` is a struct, not a trait

The source implements its own `domain::ports::Authenticator` port. zurid ships a
concrete `oauth::Authenticator` with `start`/`complete` and no trait — nothing
consumes it polymorphically here. A consumer implements its own port by
delegating, which is a three-line impl.

### F16. Collaborators are `Arc<dyn …>`, not `Box<dyn …>`

The source passes `Box<dyn PlcDirectory>`. `Arc` for all three of the minter's
collaborators means one minter can be shared and a test can hold a handle on the
fake it injected (which several tests need).

### F19. In-memory fakes are test-only

`MemoryKeyStore` / `MemoryPlcOperationLog` / `MemoryOAuthStateStore` exist under
`#[cfg(test)]`. Shipping them publicly (behind, say, a `testing` feature) would
help consumers whose own in-memory adapters must now implement zurid's traits —
but that is a new feature, outside the approved map, so it is **offered, not
taken**.

### F24. Directory selection by config was left behind

`DirectoryConfig` / `plc_directory_from_config` are composition-root concerns.
zurid ships `NoopPlcDirectory` and `HttpPlcDirectory::{new, canonical,
with_client}`; choosing between them from a config file is the application's job.

### F17 / F18. Deliberately not carried

- `StubDidMinter` — synthetic-DID test glue for the originating service, not a
  library concern.
- `tests/wipe_replay.rs` — despite being named in the brief, this test covers
  `AtprotoPublicRecords` and the `app.zurfur.feed.post` lexicon (records, not
  identity). Both are outside the approved feature map, so there is nothing here
  to port it against. The `auth_store` suite it was named alongside **is**
  ported, in `tests/postgres/oauth_bridge.rs`.
- Reserved-label namespaces, handle-change rate limiting and quarantine, the
  boot-time custody guard, login error-code contracts, session cookies, CSRF and
  user provisioning — all product policy, all left behind per the brief.

---

## Packaging

### F9. Table and column names are unchanged

`account_keys`, `plc_operations`, `atproto_oauth.client_session`,
`atproto_oauth.auth_request`, and every column, keep the source's names. A
`zurid_` prefix was considered and **rejected**: the originating service already
has these tables and rows in them, and the shipped SQL must line up with what is
there or adoption means a data migration.

Consequence for other consumers: the names are unprefixed and could collide.
Documented rather than solved; making them configurable is not worth the
machinery.

The DDL is therefore plain `CREATE TABLE` / `CREATE SCHEMA`, not
`… IF NOT EXISTS`. With `IF NOT EXISTS` a collision would be recorded as a
successful migration that created nothing — after which zurid reads and writes a
table it does not control and no later `migrate` ever creates the real one.
Each migration runs in a transaction, so the collision instead fails the call,
records nothing, and leaves the consumer's table untouched. Loud and recoverable
beats silent and permanent.

### F10. Three migrations, renumbered, with the fork index folded in

The source has four relevant migrations across two crates, one of which is a
follow-up adding the no-chain-fork index. zurid ships three
(`20260809000001`–`3`), the fork index folded into the `plc_operations`
migration it belongs to — a fresh install has no reason to replay the history of
a fix.

Versions are fresh, not the source's, so a consumer embedding both sets does not
collide on the migration primary key.

### F11. Migrations are embedded by `build.rs`, not `sqlx::migrate!`

`sqlx::migrate!` lives behind sqlx's `macros` feature. Enabling it here would
turn it on for **every crate in a consumer's build** through feature
unification — and the originating service deliberately retired `macros` so that
reintroducing a compile-time query macro is a compile error by construction.
zurid must not quietly re-arm that. `build.rs` generates the same
`(version, description, sql)` table the macro would, and `postgres::migrator()`
builds an identical `Migrator` with matching checksums, so a ledger written by
the sqlx CLI over the same files stays valid.

### F12. SQL lives in files; the codegen does not come along

The source generates typed query functions with `sqlx-rust-codegen`, a
tag-pinned build tool. Carrying that would make zurid depend on the originating
project's toolchain. The convention it enforces is kept — every statement lives
in `queries/**.sql` and is `include_str!`-ed, so the SQL that runs is reviewable
as SQL — but the wrappers are hand-written.

### F20 / F21. Lockfile committed; publishing disabled in the manifest

`Cargo.lock` is committed and CI builds `--locked`, so a dependency cannot move
under the crate between a green run and a consumer's build. `publish = false`
enforces the no-crates.io ruling in the manifest rather than in a person's
memory.

### F25. Default features are `minter` + `directory`

The write path is the crate's reason to exist, so it is on by default;
`postgres`, `oauth` and `axum` pull heavy dependencies and are opt-in.
`--no-default-features` leaves the pure protocol core.

### F27 / F28. Small additions

- `key_version` is a `CustodyEnvelope` rather than an inlined literal, and is
  **read back**: `PgKeyStore::get` decodes the column and refuses a value it does
  not know instead of opening the blob under a guessed scheme. `V1` is the
  source's format (bare-DID associated data); `V2` — what zurid writes — prefixes
  the associated data with `zurid.custody\0`, domain-separating custody from
  every other family sealed under the same root key. **V1 rows still open**, so
  the originating service's existing `account_keys` are not stranded; they are
  simply never written again.
- `Did` and `Handle` are `Serialize`/`Deserialize` with `#[serde(transparent)]`,
  which the source's were not. Both are values that cross API boundaries;
  transparent means a DID is `"did:plc:…"` on the wire, never a tuple wrapper.
  **Both** `Deserialize` impls are hand-written and validating: a derived one
  would be `Did::new` with extra steps, so every JSON body and cached record
  could route around the grammar and the newtype would prove nothing about its
  contents. Deserialization is an untrusted boundary, so it parses. The wire
  shape is unchanged in both directions.

  For `Handle` this is load-bearing rather than tidy. `Authenticator::start`
  takes a `Handle` *instead of* a string specifically so jacquard's
  fetch-this-service-URL branch is unreachable (F29) — which is only true if
  every door into the type validates. A derived `Deserialize` would have handed
  back a `Handle` holding `https://169.254.169.254/…` straight from a JSON login
  body, the likeliest way a handle actually arrives, and walked it into the very
  fetch the type exists to prevent. Caught by cold review of the F29 change; the
  SSRF test now exercises both doors.

---

## Verified, not assumed

Recorded because the extraction turned three of them into enforced checks:

| fact | source |
|---|---|
| `rotationKeys` must hold 1–5 keys, no duplication | did:plc spec v0.1 — enforced in `MintPolicy::validate` |
| any listed rotation key may sign an operation | did:plc spec v0.1 — the preset signs with the lower-authority key on purpose |
| at most 10 `verificationMethods` per DID | did:plc spec v0.1 — enforced in `MintPolicy::validate` |
| a genesis `prev` is present with value `null`, not omitted | did:plc spec v0.1 — pinned by `genesis_prev_is_an_explicit_null` |
| DID = `base32(sha256(dag-cbor(signed op)))[..24]` | did:plc spec v0.1 — pinned to a published vector |
| signature = ECDSA-SHA256, low-S, 64-byte r‖s, base64url no-pad | did:plc spec v0.1 — asserted in the minter tests |
| `plc_tombstone` carries only `type`, `prev`, `sig` | did:plc spec v0.1 — pinned by `tombstone_shape_and_signing_bytes` |
| DID syntax ABNF (`method-name`, `method-specific-id`, `idchar`) | W3C DID Core — implemented in `Did::parse` |
