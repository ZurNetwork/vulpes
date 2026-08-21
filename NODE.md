---
path: .
charted: 2026-08-21
fs:
  - name: src/
    role: the `vulpes` crate — did:plc substrate + the ACP core
    node: true
  - name: tests/postgres/
    role: testcontainers integration suite (Docker)
    node: true
  - name: docs/
    role: the ACP spec, manifesto, design record, roadmap, handoff
    node: true
  - name: lexicons/
    role: the three `net.got-paws.acp.{claim,attestation,relationship}` schemas (JSON)
    node: false
  - name: migrations/
    role: 4 sqlx migrations `20260809_*` (key custody, plc ops, oauth state, op MAC); edited in place pre-1.0 (F31); embedded by build.rs (F11)
    node: false
  - name: queries/
    role: SQL files per store — key_store/, oauth_state/, plc_log/ (F12)
    node: false
  - name: .github/workflows/
    role: ci.yml — fmt · clippy · test · features matrix · advisories · docs
    node: false
  - name: Cargo.toml
    role: single crate, features default=minter+directory; oauth, postgres, axum, vc, acp
    node: false
  - name: justfile
    role: `just gate` = fmt-check lint test features deny doc (mirrors CI)
    node: false
  - name: build.rs
    role: embeds migrations/
    node: false
  - name: deny.toml
    role: cargo-deny advisories
    node: false
  - name: FORKS.md
    role: numbered judgment calls (F1…F41) referenced from code comments
    node: false
  - name: CLAUDE.md
    role: working contract, branch/commit rules, the kill test
    node: false
  - name: .understand/
    role: cached briefings (chart-ignored)
    node: false
---
**Is:** `vulpes` — AT Protocol identity for Rust servers (did:plc write path, key custody, OAuth state, shipped as v0.1.0) and the reference implementation of the ACP (Attested Claims Protocol), the active lane.

**Reading this tree:** to understand a path, read every `NODE.md` from the root down to that directory; each node states only what its ancestors haven't. Entries with `node: false` are fully described by their `fs` line. `/familiarize` diffs `fs:` against `ls` to spot staleness; `/chart` refreshes.

**Conventions:** edition 2024, MSRV 1.88, git-dep only (never crates.io). Every feature must pass the kill test before shipping. `FNN` in a comment = an entry in `FORKS.md`. Feature-gated modules are `pub mod` behind `#[cfg(feature = …)]`.

**Entry points:** `src/lib.rs` (crate docs + module map), `docs/ROADMAP.md` (what's in flight), `docs/CONTINUE-HERE.md` (handoff).

**Refs:** CLAUDE.md · FORKS.md · Confluence VU (Ruling Record 49184769, ACP pointer 49905665, Guide to Jira Tickets 50692097) · memory `project-file-system-map`.
