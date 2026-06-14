//! Nullifier normalization + defensive location (the security-critical choke
//! point). The Developer Portal proves a proof is cryptographically valid; WE
//! enforce one-human-one-vote by normalizing the nullifier to a canonical
//! 32-byte form and persisting it under `UNIQUE(election_id, nullifier)`.
//!
//! Two inputs vary and must collapse to one canonical key:
//!   1. encoding (mixed case, `0x` prefix, short hex with implied leading zeros)
//!   2. which response shape carried it (v3 `nullifier_hash`, v4 `nullifier`,
//!      v4 session `session_nullifier`).
//!
//! Because the proof is forwarded by the client, [`locate_nullifier`] collects
//! EVERY recognized nullifier in the tree and requires them to collapse to one
//! canonical value — a second distinct value is an injection attempt and is
//! rejected, never silently preferred over the value the Portal validated.

use serde_json::Value;
use std::collections::BTreeSet;

/// A nullifier wasn't a normalizable 32-byte hex value.
#[derive(Debug, PartialEq, Eq)]
pub enum NullifierError {
    /// empty after stripping the `0x` prefix.
    Empty,
    /// more than 64 hex chars (doesn't fit in 32 bytes).
    TooLong,
    /// non-hex characters present.
    NotHex,
}

impl std::fmt::Display for NullifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NullifierError::Empty => write!(f, "empty nullifier"),
            NullifierError::TooLong => write!(f, "nullifier exceeds 32 bytes"),
            NullifierError::NotHex => write!(f, "nullifier is not hex"),
        }
    }
}
impl std::error::Error for NullifierError {}

/// Normalize a nullifier to its canonical 32-byte big-endian form, regardless
/// of `0x` prefix, case, or omitted leading zeros. This is the SINGLE choke
/// point — store and compare only the output of this function.
///
/// # Errors
/// Returns [`NullifierError`] if `raw` is empty, exceeds 32 bytes, or contains
/// non-hex characters.
pub fn normalize_nullifier(raw: &str) -> Result<[u8; 32], NullifierError> {
    let s = raw.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return Err(NullifierError::Empty);
    }
    if s.len() > 64 {
        return Err(NullifierError::TooLong);
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NullifierError::NotHex);
    }
    // Left-pad with zeros to 64 hex chars, lowercase, decode.
    let padded = format!("{s:0>64}").to_lowercase();
    let bytes = hex::decode(padded).map_err(|_| NullifierError::NotHex)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Lowercase hex (no `0x`) of a canonical nullifier — the form persisted and
/// anchored on the chain.
#[must_use]
pub fn nullifier_hex(n: &[u8; 32]) -> String {
    hex::encode(n)
}

/// Where the nullifier search landed in a Portal-accepted proof.
#[derive(Debug, PartialEq, Eq)]
pub enum NullifierLookup {
    /// Exactly one canonical nullifier across every recognized location.
    Found([u8; 32]),
    /// No recognized nullifier anywhere.
    Absent,
    /// Two or more DISTINCT nullifiers — a forged/ambiguous proof. A genuine
    /// verification proof carries exactly one; a second distinct value is the
    /// signature of a `nullifier`-injection attempt and must be rejected.
    Conflict,
}

const NULLIFIER_KEYS: [&str; 3] = ["nullifier", "nullifier_hash", "session_nullifier"];

/// Max JSON nesting [`collect_canonical`] descends. A real IDKit proof carries
/// the nullifier at depth ≤3 (`responses[].nullifier`); this cap only stops
/// pathological/hostile nesting from overflowing the stack. The HTTP path is
/// already bounded by serde_json's parse-recursion limit, but this crate is
/// public and could be handed a programmatically-built `Value`.
const MAX_PROOF_DEPTH: u32 = 32;

/// Recursively collect every *canonical* nullifier under any recognized key,
/// anywhere in the proof tree (top level, inside `responses[]`, wrappers), up
/// to [`MAX_PROOF_DEPTH`] levels deep.
fn collect_canonical(v: &Value, depth: u32, out: &mut BTreeSet<[u8; 32]>) {
    if depth >= MAX_PROOF_DEPTH {
        return;
    }
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if NULLIFIER_KEYS.contains(&k.as_str()) {
                    if let Some(n) = val.as_str().and_then(|s| normalize_nullifier(s).ok()) {
                        out.insert(n);
                    }
                }
                collect_canonical(val, depth + 1, out);
            }
        }
        Value::Array(arr) => arr
            .iter()
            .for_each(|el| collect_canonical(el, depth + 1, out)),
        _ => {}
    }
}

/// Locate THE nullifier in a Portal-accepted proof, defensively. The proof is
/// the client-forwarded IDKit result, so a value injected at a location the
/// Portal never validated (e.g. a top-level `nullifier` while the real one is in
/// `responses[].nullifier`) must NOT win over the real one. We collect every
/// recognized nullifier and require them to collapse to a single canonical
/// value; a second distinct value ⇒ [`NullifierLookup::Conflict`] (rejected).
#[must_use]
pub fn locate_nullifier(proof: &Value) -> NullifierLookup {
    let mut set = BTreeSet::new();
    collect_canonical(proof, 0, &mut set);
    let mut it = set.into_iter();
    match (it.next(), it.next()) {
        (None, _) => NullifierLookup::Absent,
        (Some(n), None) => NullifierLookup::Found(n),
        (Some(_), Some(_)) => NullifierLookup::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── normalization: everything collapses to one canonical key ──────────
    #[test]
    fn prefix_case_and_short_hex_all_normalize_equal() {
        let canonical = normalize_nullifier("0xabc").unwrap();
        assert_eq!(normalize_nullifier("abc").unwrap(), canonical);
        assert_eq!(normalize_nullifier("0xABC").unwrap(), canonical);
        assert_eq!(normalize_nullifier("0X0abc").unwrap(), canonical);
        assert_eq!(normalize_nullifier("  0xAbC  ").unwrap(), canonical);
        // explicit full-width form with leading zeros
        let full = format!("{:0>64}", "abc");
        assert_eq!(normalize_nullifier(&full).unwrap(), canonical);
    }

    #[test]
    fn full_32_byte_value_round_trips() {
        let raw = "0x14f693175773aed912852a601e9c0fd30f2afe2738d31388316232ce6f64ae9e";
        let n = normalize_nullifier(raw).unwrap();
        assert_eq!(
            nullifier_hex(&n),
            "14f693175773aed912852a601e9c0fd30f2afe2738d31388316232ce6f64ae9e"
        );
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(normalize_nullifier("0x"), Err(NullifierError::Empty));
        assert_eq!(normalize_nullifier(""), Err(NullifierError::Empty));
        assert_eq!(normalize_nullifier("xyz"), Err(NullifierError::NotHex));
        assert_eq!(
            normalize_nullifier(&"a".repeat(65)),
            Err(NullifierError::TooLong)
        );
    }

    #[test]
    fn distinct_nullifiers_stay_distinct() {
        assert_ne!(
            normalize_nullifier("0x01").unwrap(),
            normalize_nullifier("0x02").unwrap()
        );
    }

    // ── location: collect every nullifier, collapse or reject ─────────────
    #[test]
    fn locate_finds_single_nested_responses_nullifier() {
        let p = json!({ "protocol_version": "4.0", "responses": [{ "nullifier": "0xdead" }] });
        assert_eq!(
            locate_nullifier(&p),
            NullifierLookup::Found(normalize_nullifier("0xdead").unwrap())
        );
    }
    #[test]
    fn locate_finds_top_level_legacy_nullifier_hash() {
        let p = json!({ "nullifier_hash": "0x01" });
        assert_eq!(
            locate_nullifier(&p),
            NullifierLookup::Found(normalize_nullifier("01").unwrap())
        );
    }
    #[test]
    fn locate_collapses_same_value_in_two_places() {
        let p = json!({ "nullifier": "0xdead", "responses": [{ "nullifier": "0x00dead" }] });
        assert_eq!(
            locate_nullifier(&p),
            NullifierLookup::Found(normalize_nullifier("dead").unwrap())
        );
    }
    #[test]
    fn locate_rejects_injected_conflicting_nullifier() {
        let p = json!({ "nullifier": "0x01", "responses": [{ "nullifier": "0xdead" }] });
        assert_eq!(locate_nullifier(&p), NullifierLookup::Conflict);
    }
    #[test]
    fn locate_absent_when_no_nullifier() {
        assert_eq!(
            locate_nullifier(&json!({ "success": true })),
            NullifierLookup::Absent
        );
    }
    #[test]
    fn locate_ignores_non_hex_value() {
        let p = json!({ "nullifier": "not-hex", "responses": [{ "nullifier": "0xdead" }] });
        assert_eq!(
            locate_nullifier(&p),
            NullifierLookup::Found(normalize_nullifier("dead").unwrap())
        );
    }
    #[test]
    fn locate_caps_recursion_on_pathological_nesting() {
        // A nullifier buried far deeper than any real proof is ignored (the depth
        // cap prevents unbounded recursion); a shallow one is still found. The
        // Portal would never 2xx a proof hiding its nullifier this deep anyway.
        let mut deep = json!({ "nullifier": "0xdead" });
        for _ in 0..80 {
            deep = json!({ "wrap": deep });
        }
        assert_eq!(locate_nullifier(&deep), NullifierLookup::Absent);
        assert_eq!(
            locate_nullifier(&json!({ "responses": [{ "nullifier": "0xbeef" }] })),
            NullifierLookup::Found(normalize_nullifier("beef").unwrap())
        );
    }
}
