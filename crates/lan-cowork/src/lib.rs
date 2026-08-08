//! LAN Cowork — peer pairing, fleet dispatch and cross-node cowork routes.
//!
//! This crate does not depend on `yu-server`. Everything it needs from the
//! host process is reached through the `LanCoworkHost` trait, so the crate
//! builds and tests on its own and can be reviewed as a separate unit.
//!
//! Two files stay on the `yu-server` side by design:
//!
//! - `lan_cowork_host_impl.rs` — `impl LanCoworkHost for AppState`. The orphan
//!   rule forbids it here, since neither the trait's `AppState` nor several of
//!   the types it converts are owned by this crate.
//! - `lan_cowork_split_integration_tests.rs` — tests that exercise the auth
//!   middleware, `check_static_bypass` and the CSRF layer, none of which this
//!   crate owns.
//!
//! Security note for reviewers: authorization is *declared* per route but
//! *enforced* in the route body. Read the body, not the declaration. See
//! `docs/development/development_docs/LAN_COWORK_SECURITY_REVIEW.md`.
//!
//! See `docs/superpowers/plans/2026-08-06-lan-cowork-s4-crate-split.md` for
//! the split plan and the dependency-graph findings recorded against S4.

// Async tests intentionally hold the global seam lock to serialize process-wide state.
#![cfg_attr(test, allow(clippy::await_holding_lock))]

pub mod auth;
pub mod path_guard;
pub mod routes;
pub mod schema;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
pub(crate) mod state {
    pub(crate) use crate::test_support::{
        semantic_test_state, semantic_test_state_with, semantic_test_state_with_root, SharedState,
    };
}
