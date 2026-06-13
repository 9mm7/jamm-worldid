//! World ID 4.0 Relying-Party (RP) helpers for Jàmm's sybil-resistant voting.
//!
//! Standalone crate — no Jàmm core dependencies — so it can live in the public
//! `jamm-worldid` repo and be tested on its own against the official World ID
//! test vectors (see `docs/rp-signature.md`).
//!
//! Spec: <https://docs.world.org/world-id/idkit/signatures>

mod signature;

pub use signature::{compute_rp_signature_message, hash_to_field};
