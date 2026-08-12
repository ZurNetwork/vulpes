# vulpes — task runner. `just` alone lists recipes; `just gate` = everything CI runs.

default:
    @just --list

# --- the gate (mirror of .github/workflows/ci.yml) ---

# Run every check CI runs. Green here = green there.
gate: fmt-check lint test features deny doc

# --- individual recipes ---

# Format the tree in place.
fmt:
    cargo fmt --all

# CI's `fmt` job: fail on unformatted code.
fmt-check:
    cargo fmt --all --check

# CI's `clippy` job.
lint:
    cargo clippy --all-features --all-targets --locked -- -D warnings

# CI's `test` job. The Postgres suite boots throwaway containers via
# testcontainers — a running Docker daemon is the only prerequisite.
test:
    cargo test --all-features --locked

# CI's `features` matrix: every feature compiles alone and combined.
features:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in "" "minter" "directory" "oauth" "postgres" "axum" "minter,postgres" "oauth,postgres" "axum,postgres"; do
        echo "--- features: '${f}'"
        cargo check --no-default-features --features "${f}" --all-targets --locked
    done
    cargo check --all-features --all-targets --locked

# CI's `advisories` job (needs cargo-deny: `cargo install cargo-deny`).
deny:
    cargo deny check advisories --all-features

# CI's `docs` job: broken intra-doc links are errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
