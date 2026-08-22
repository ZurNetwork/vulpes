---
path: tests
charted: 2026-08-21
fs:
  - name: postgres/
    role: one integration binary (main.rs) — pg.rs shared-container harness; migrations, key_store, plc_log, oauth_state, oauth_bridge, minter suites
    node: false
---
**Is:** the integration suite; everything here needs Docker (testcontainers boots one Postgres per test process via `pg.rs`).

**Conventions:** each file is a feature's end-to-end story against a real database; unit tests stay in `src/`. Run by `just test` (`cargo test --all-features --locked`).
