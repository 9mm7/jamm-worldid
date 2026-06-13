//! Nullifier normalization + defensive extraction (the security-critical choke
//! point). The Developer Portal proves a proof is cryptographically valid; WE
//! enforce one-human-one-vote by normalizing the nullifier to a canonical
//! 32-byte form and persisting it under `UNIQUE(election_id, nullifier)`.
//!
//! Two inputs vary and must collapse to one canonical key:
//!   1. encoding (mixed case, `0x` prefix, short hex with implied leading zeros)
//!   2. which response shape carried it (v3 `nullifier_hash`, v4 `nullifier`,
//!      v4 session `session_nullifier`).

use serde_json::Value;

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
pub fn nullifier_hex(n: &[u8; 32]) -> String {
    hex::encode(n)
}

/// Defensively pull the nullifier out of a Portal verify response, whichever of
/// the three shapes arrived. Checks, in order: v4 uniqueness `nullifier`, v3
/// legacy `nullifier_hash`, v4 session `session_nullifier` — at the top level
/// and one level down (the uniqueness proof can arrive wrapped). Returns the
/// raw string (un-normalized); pass it through [`normalize_nullifier`].
pub fn extract_nullifier(resp: &Value) -> Option<String> {
    const KEYS: [&str; 3] = ["nullifier", "nullifier_hash", "session_nullifier"];

    fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
    }

    // Top level.
    for k in KEYS {
        if let Some(s) = str_at(resp, k) {
            return Some(s.to_string());
        }
    }
    // One level down: common wrappers ("proof", "result", "data") or any object
    // / first array element carrying one of the keys.
    if let Some(obj) = resp.as_object() {
        for (_, v) in obj {
            let candidate = if v.is_array() {
                v.as_array().and_then(|a| a.first())
            } else {
                Some(v)
            };
            if let Some(inner) = candidate {
                for k in KEYS {
                    if let Some(s) = str_at(inner, k) {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
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

    // ── extraction: the 3 response shapes ─────────────────────────────────
    #[test]
    fn extracts_v4_uniqueness_nullifier() {
        let r = json!({ "success": true, "nullifier": "0xaaaa", "verification_level": "orb" });
        assert_eq!(extract_nullifier(&r).as_deref(), Some("0xaaaa"));
    }

    #[test]
    fn extracts_v3_legacy_nullifier_hash() {
        let r = json!({ "success": true, "nullifier_hash": "0xbbbb" });
        assert_eq!(extract_nullifier(&r).as_deref(), Some("0xbbbb"));
    }

    #[test]
    fn extracts_v4_session_nullifier() {
        let r = json!({ "success": true, "session_nullifier": "0xcccc", "session_id": "s-1" });
        assert_eq!(extract_nullifier(&r).as_deref(), Some("0xcccc"));
    }

    #[test]
    fn extracts_from_wrapped_proof_object() {
        let r = json!({ "success": true, "proof": { "nullifier": "0xdddd" } });
        assert_eq!(extract_nullifier(&r).as_deref(), Some("0xdddd"));
    }

    #[test]
    fn extracts_from_proof_array() {
        let r = json!({ "proofs": [ { "nullifier": "0xeeee" } ] });
        assert_eq!(extract_nullifier(&r).as_deref(), Some("0xeeee"));
    }

    #[test]
    fn none_when_no_nullifier_present() {
        let r = json!({ "success": false, "code": "invalid_proof" });
        assert_eq!(extract_nullifier(&r), None);
    }

    #[test]
    fn extracted_then_normalized_is_canonical() {
        let r = json!({ "nullifier_hash": "0xABC" });
        let raw = extract_nullifier(&r).unwrap();
        assert_eq!(
            normalize_nullifier(&raw).unwrap(),
            normalize_nullifier("abc").unwrap()
        );
    }
}
