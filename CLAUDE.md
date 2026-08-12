# vulpes

AT Protocol identity for Rust servers, and the reference implementation of the
**ACP (Attested Claims Protocol)**. The `v0.1.0` substrate (did:plc write path,
key custody, OAuth state) is shipped; current work is the ACP public lane
(Jira epic VUL-9).

## Working contract

Zuri is lead stakeholder **and** lead coder here. Claude guides — briefs,
drafts, reviews, flags forks — but Zuri makes the calls and writes most of the
code. Prefer worksheets, skeletons, and reviews over unprompted finished code.

## The documents that rule this repo

- `docs/acp.md` — the ACP spec (record shapes, signing, verification, the kill
  test). Where a design choice looks arbitrary, `docs/manifesto.md` is why.
- `docs/explainer.md` — the worked walkthrough.
- `docs/identity-model.md` — the design interview record.
- `FORKS.md` — judgment calls the rulings don't cover get recorded here.
- Confluence **VU** space — design source of truth (Ruling Record 49184769,
  ACP pointer page 49905665). Jira project **VUL**.
- `docs/CONTINUE-HERE.md` — session handoff state; single-writer (one session
  maintains it).

## The one law

**The kill test**: the death of any operator — attestor, custodian, or the
reference instance — is an inconvenience, never a breaking factor. Every
feature must pass it before shipping.

## Build & gate

- `just gate` runs everything CI runs (fmt-check, clippy, test, features
  matrix, cargo-deny advisories, docs). Green locally = green in CI.
- Tests that need Postgres boot testcontainers; Docker must be running.
- MSRV 1.88 · edition 2024 · not published to crates.io (git-dep only, by
  ruling).

## Branch Strategy

- `main` — stable; the only long-lived branch. All PRs target it. **Never push
  directly to `main`** (a GitHub ruleset enforces this).
- `feature/*` — a unit of new work, branched from `main`
  (e.g. `feature/vul-NN-short-slug`).
- `bug/*` — a bug fix, branched from `main`.
- `chore/*`, `docs/*`, `hotfix/*` — maintenance, documentation, urgent fixes.

## Commits

- PRs merge via **Squash and merge** only (other methods are disabled), so
  `main` keeps **one commit per PR**; the branch itself may carry several
  granular commits. Merged branches auto-delete.
- Required CI checks (`fmt` · `clippy` · `test` · `advisories` · `docs`) must
  pass before merge; the `features` matrix runs but isn't a required context.
- Local `/understand` + `/remember` briefings live in `.understand/`
  (tracked in the repo).
