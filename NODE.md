---
path: .
charted: 2026-08-23
fs:
  - name: src/
    role: the vulpes crate — did:plc substrate + the ACP reference implementation
    node: true
  - name: docs/
    role: the ruling documents — spec (acp.md), plan (ROADMAP.md), handoff, rationale
    node: true
  - name: tests/
    role: the Postgres-backed integration suite (testcontainers; Docker required)
    node: true
  - name: lexicons/
    role: net.got-paws.acp.* record schemas (claim, attestation, statusList)
    node: false
  - name: migrations/
    role: four numbered SQL migrations, embedded by build.rs (F10, F11)
    node: false
  - name: queries/
    role: SQL files per store/<op> (F12) — key_store, oauth_state, plc_log
    node: false
  - name: .github/workflows/
    role: ci.yml — fmt · clippy · test · features · advisories · docs
    node: false
  - name: CLAUDE.md
    role: working contract, ruling docs list, branch/commit rules
    node: false
  - name: FORKS.md
    role: judgment calls the rulings don't cover (F-numbers)
    node: false
  - name: justfile
    role: `just gate` = everything CI runs
    node: false
  - name: Cargo.toml
    role: MSRV 1.88 · edition 2024 · features: minter+directory default; acp, oauth, postgres, vc, axum
    node: false
  - name: build.rs
    role: embeds migrations/ into the binary
    node: false
  - name: deny.toml
    role: cargo-deny advisories config
    node: false
---
**Is:** AT Protocol identity for Rust servers and the reference implementation of the ACP (Attested Claims Protocol); the shipped v0.1.0 substrate (did:plc writes, key custody, OAuth state) plus the in-flight ACP public lane.

**Reading this tree:** to understand any path, read every `NODE.md` from this root down to that directory; each node only adds what its ancestors haven't said. Entries marked `node: false` are fully described by their `fs` line here.

**Conventions:** the one law is the kill test — no operator's death may be a breaking factor. The plan is `docs/ROADMAP.md` (no tickets); judgment calls land in `FORKS.md`; rulings live in Confluence VU. Green `just gate` locally = green CI.

**Entry points:** `docs/ROADMAP.md` → `docs/CONTINUE-HERE.md` → `src/lib.rs`.

**Refs:** CLAUDE.md; Confluence VU Ruling Record 49184769, ACP pointer 49905665; memory `project-file-system-map`.
