---
path: .
charted: 2026-08-21
fs:
  - name: src/
    role: the crate — did:plc substrate + ACP core, feature-gated
    node: true
  - name: tests/
    role: Postgres-backed integration suite (testcontainers)
    node: true
  - name: docs/
    role: the ruling documents — ACP spec, roadmap, handoff, design record
    node: true
  - name: lexicons/
    role: the three net.got-paws.acp.* record schemas (claim, attestation, relationship)
    node: false
  - name: migrations/
    role: four sqlx migrations (key custody, plc operations, oauth state, plc op MAC); edited in place pre-1.0 (F31)
    node: false
  - name: queries/
    role: one .sql file per store op — key_store/, oauth_state/, plc_log/ — loaded by src/postgres
    node: false
  - name: .github/workflows/ci.yml
    role: fmt · clippy · test · features matrix · advisories · docs
    node: false
  - name: .understand/
    role: /understand + /remember briefings (chartignored)
    node: false
  - name: Cargo.toml
    role: features — default [minter, directory]; oauth, postgres, axum, vc, acp; publish=false
    node: false
  - name: build.rs
    role: embeds migrations/ at compile time (stand-in for sqlx::migrate!)
    node: false
  - name: justfile
    role: `just gate` mirrors CI
    node: false
  - name: deny.toml
    role: cargo-deny advisories config
    node: false
  - name: FORKS.md
    role: numbered judgment calls (F1…F41), Engineer-ruled
    node: false
  - name: CLAUDE.md
    role: working contract, rulebooks, branch/commit rules
    node: false
  - name: .chartignore
    role: dirs not worth a node
    node: false
---
**Is:** `vulpes` — a single Rust crate (edition 2024, MSRV 1.88, git-dep only): AT Protocol identity for servers (did:plc write path, key custody, OAuth state) and the reference implementation of the ACP (Attested Claims Protocol).

**Reading this tree:** to understand a path, read every `NODE.md` from the root down to that directory; each node states only what its ancestors haven't. Entries marked `node: false` are fully described by their `fs` line.

**Conventions:** everything optional is a Cargo feature; `--no-default-features` is the pure protocol core. Closed error enums (F1). Every feature must pass the kill test before shipping. Gate = `just gate`; Docker required for tests.

**Entry points:** `src/lib.rs` (feature map), `docs/ROADMAP.md` (what's in flight), `docs/CONTINUE-HERE.md` (handoff).

**Refs:** CLAUDE.md; FORKS.md; Confluence VU space (Ruling Record 49184769, ACP pointer 49905665, Guide to Jira Tickets 50692097); memory `zuri-leads-vulpes-acp`.
