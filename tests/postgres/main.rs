//! vulpes's PostgreSQL-backed integration suite.
//!
//! One test binary so the whole suite shares a single container (see
//! [`pg`]); each test still gets its own pristine database, cloned from a
//! migrated template.
//!
//! **Requires a container runtime socket** (`DOCKER_HOST` is honored) and the
//! `postgres` feature. Run it with `cargo test --all-features`.

#![cfg(feature = "postgres")]

mod pg;

mod key_store;
mod migrations;
mod oauth_state;
mod plc_log;

#[cfg(feature = "minter")]
mod minter;

#[cfg(feature = "oauth")]
mod oauth_bridge;
