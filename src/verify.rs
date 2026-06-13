//! Server-side proof verification against the World ID Developer Portal.
//!
//! Validation happens here, NEVER on the client: the IDKit result is forwarded
//! to `POST {base}/api/v4/verify/{rp_id}` and the response is classified. The
//! Portal proves cryptographic validity; uniqueness is enforced elsewhere
//! (`nullifier` + `UNIQUE(election_id, nullifier)`).

use crate::nullifier::{extract_nullifier, normalize_nullifier, nullifier_hex};
use serde_json::Value;

/// Result of a Portal verify call.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Portal accepted the proof. Canonical 64-hex nullifier (no `0x`).
    Verified { nullifier_hex: String },
    /// Portal rejected it (bad/expired proof, wrong action, quota, …).
    Rejected { code: String },
    /// 2xx but no usable nullifier — never treat as success.
    Malformed,
}

/// Classify a Portal verify response from its HTTP-2xx-ness + parsed body.
/// Pure (no I/O) so it can be pinned to the documented response shapes.
pub fn classify(http_ok: bool, body: &Value) -> VerifyOutcome {
    let code = || {
        body.get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string()
    };
    if !http_ok {
        return VerifyOutcome::Rejected { code: code() };
    }
    // A 2xx with an explicit `success: false` is still a rejection.
    if body.get("success") == Some(&Value::Bool(false)) {
        return VerifyOutcome::Rejected { code: code() };
    }
    match extract_nullifier(body).and_then(|raw| normalize_nullifier(&raw).ok()) {
        Some(n) => VerifyOutcome::Verified {
            nullifier_hex: nullifier_hex(&n),
        },
        None => VerifyOutcome::Malformed,
    }
}

/// Forward an IDKit result to the Portal's v4 verify endpoint and classify the
/// response. `base` is e.g. `https://developer.world.org/api/v4/verify`; the
/// `rp_id` is appended. **This is the `/v4/verify` call — server-side only.**
pub async fn verify_with_portal(
    base: &str,
    rp_id: &str,
    idkit_result: &Value,
) -> Result<VerifyOutcome, String> {
    let url = format!("{}/{}", base.trim_end_matches('/'), rp_id);
    // The Portal sits behind a WAF that 403s requests with no `User-Agent`
    // (reqwest sends none by default), so set one explicitly.
    let resp = reqwest::Client::new()
        .post(&url)
        .header(
            reqwest::header::USER_AGENT,
            concat!("jamm-worldid/", env!("CARGO_PKG_VERSION")),
        )
        .json(idkit_result)
        .send()
        .await
        .map_err(|e| format!("portal request failed: {e}"))?;
    let status = resp.status();
    let http_ok = status.is_success();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    // Log the Portal's verdict so a rejection is diagnosable (the body carries
    // the `code`/`detail`, e.g. invalid_merkle_root, max_verifications_reached).
    if !http_ok || body.get("success") == Some(&Value::Bool(false)) {
        log::warn!("World ID Portal verify -> HTTP {status} body={body}");
    } else {
        log::info!("World ID Portal verify -> HTTP {status} (accepted)");
    }
    Ok(classify(http_ok, &body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn success_with_nullifier_is_verified_and_canonical() {
        let b = json!({ "success": true, "nullifier": "0xABC", "verification_level": "orb" });
        assert_eq!(
            classify(true, &b),
            VerifyOutcome::Verified {
                nullifier_hex: format!("{:0>64}", "abc")
            }
        );
    }

    #[test]
    fn legacy_nullifier_hash_shape_is_verified() {
        let b = json!({ "nullifier_hash": "0x01" });
        assert_eq!(
            classify(true, &b),
            VerifyOutcome::Verified {
                nullifier_hex: format!("{:0>64}", "01")
            }
        );
    }

    #[test]
    fn non_2xx_is_rejected_with_code() {
        let b = json!({ "code": "invalid_proof", "detail": "…" });
        assert_eq!(
            classify(false, &b),
            VerifyOutcome::Rejected {
                code: "invalid_proof".into()
            }
        );
    }

    #[test]
    fn success_false_is_rejected() {
        let b = json!({ "success": false, "code": "max_verifications_reached" });
        assert_eq!(
            classify(true, &b),
            VerifyOutcome::Rejected {
                code: "max_verifications_reached".into()
            }
        );
    }

    #[test]
    fn ok_but_no_nullifier_is_malformed() {
        let b = json!({ "success": true });
        assert_eq!(classify(true, &b), VerifyOutcome::Malformed);
    }
}
