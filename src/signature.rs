//! RP proof-request signing (World ID 4.0).
//!
//! Implemented from the official spec + test vectors (Plan B — there is no
//! Rust IDKit crate). Every primitive here is pinned to an official vector.

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};

/// Default time-to-live of a signed proof request, in seconds.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Errors from RP signing.
#[derive(Debug)]
pub enum SignError {
    /// signing_key wasn't 32 bytes of hex (with or without `0x`).
    BadKey,
    /// system clock is before the unix epoch.
    Clock,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::BadKey => write!(f, "invalid signing key (need 32-byte hex)"),
            SignError::Clock => write!(f, "system clock before unix epoch"),
        }
    }
}
impl std::error::Error for SignError {}

/// A signed RP proof request, ready to hand to the IDKit client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RpSignature {
    /// `0x` + hex of `r(32) ‖ s(32) ‖ v(1)` (v = recovery_id + 27).
    pub sig: String,
    /// `0x` + hex of the 32-byte nonce field element.
    pub nonce: String,
    pub created_at: u64,
    pub expires_at: u64,
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(input);
    k.finalize(&mut out);
    out
}

/// World ID `hash_to_field`: `keccak256(input)` interpreted as a big-endian
/// uint256, shifted right by 8 bits, re-encoded big-endian — so the result
/// always starts with `0x00` (a valid BN254 field element).
///
/// `>> 8` on a 256-bit big-endian number drops the least-significant byte and
/// shifts everything one byte to the right, i.e. `[0x00, h[0], …, h[30]]`.
pub fn hash_to_field(input: &[u8]) -> [u8; 32] {
    let h = keccak256(input);
    let mut out = [0u8; 32];
    out[0] = 0x00;
    out[1..32].copy_from_slice(&h[0..31]);
    out
}

/// Build the canonical pre-image signed by the RP:
/// `version(0x01) ‖ nonce(32) ‖ created_at(8 BE) ‖ expires_at(8 BE) ‖ [action_hash(32)]`.
/// 49 bytes without an action, 81 with.
pub fn compute_rp_signature_message(
    nonce: &[u8; 32],
    created_at: u64,
    expires_at: u64,
    action: Option<&str>,
) -> Vec<u8> {
    let size = if action.is_some() { 81 } else { 49 };
    let mut msg = vec![0u8; size];
    msg[0] = 0x01; // version
    msg[1..33].copy_from_slice(nonce);
    msg[33..41].copy_from_slice(&created_at.to_be_bytes());
    msg[41..49].copy_from_slice(&expires_at.to_be_bytes());
    if let Some(a) = action {
        msg[49..81].copy_from_slice(&hash_to_field(a.as_bytes()));
    }
    msg
}

/// Parse a signing key (32-byte hex, optional `0x`) into an ECDSA key.
fn parse_signing_key(hex_key: &str) -> Result<SigningKey, SignError> {
    let s = hex_key.trim().strip_prefix("0x").unwrap_or(hex_key.trim());
    let bytes = hex::decode(s).map_err(|_| SignError::BadKey)?;
    SigningKey::from_slice(&bytes).map_err(|_| SignError::BadKey)
}

/// Deterministic signing core (random + clock injected) — the unit it's worth
/// pinning to the official vectors. `random` is the 32 raw bytes hashed into
/// the nonce; `created_at`/`expires_at` are explicit.
fn sign_with(
    key: &SigningKey,
    action: Option<&str>,
    random: &[u8; 32],
    created_at: u64,
    expires_at: u64,
) -> RpSignature {
    let nonce = hash_to_field(random);
    let msg = compute_rp_signature_message(&nonce, created_at, expires_at, action);

    // EIP-191: keccak256("\x19Ethereum Signed Message:\n" + dec(len) + msg).
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut preimage = prefix.into_bytes();
    preimage.extend_from_slice(&msg);
    let digest = keccak256(&preimage);

    // Recoverable ECDSA secp256k1 (RFC-6979 deterministic, low-S normalized).
    let (sig, recid): (Signature, RecoveryId) = key
        .sign_prehash_recoverable(&digest)
        .expect("prehash is 32 bytes");
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(&sig.to_bytes());
    sig65[64] = recid.to_byte() + 27; // v = recovery_id + 27

    RpSignature {
        sig: format!("0x{}", hex::encode(sig65)),
        nonce: format!("0x{}", hex::encode(nonce)),
        created_at,
        expires_at,
    }
}

/// Sign an RP proof request. `action` should be `Some("jamm-election-{id}")`
/// for a uniqueness proof, or `None` for a plain session proof. Generates a
/// fresh random nonce and uses the system clock; `ttl` defaults to
/// [`DEFAULT_TTL_SECS`] when `None`.
pub fn sign_request(
    signing_key_hex: &str,
    action: Option<&str>,
    ttl: Option<u64>,
) -> Result<RpSignature, SignError> {
    let key = parse_signing_key(signing_key_hex)?;
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignError::Clock)?
        .as_secs();
    let expires_at = created_at + ttl.unwrap_or(DEFAULT_TTL_SECS);
    Ok(sign_with(&key, action, &random, created_at, expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> String {
        hex::encode(hash_to_field(s.as_bytes()))
    }

    // Official vectors — https://docs.world.org/world-id/idkit/signatures
    #[test]
    fn hash_to_field_matches_official_vectors() {
        assert_eq!(
            h(""),
            "00c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4"
        );
        assert_eq!(
            h("test_signal"),
            "00c1636e0a961a3045054c4d61374422c31a95846b8442f0927ad2ff1d6112ed"
        );
        assert_eq!(
            h("hello"),
            "001c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36dea"
        );
    }

    #[test]
    fn hash_to_field_raw_bytes_vector() {
        assert_eq!(
            hex::encode(hash_to_field(&[0x01, 0x02, 0x03])),
            "00f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92"
        );
    }

    #[test]
    fn hash_to_field_always_starts_with_zero() {
        for s in ["", "a", "jamm-election-42", "\u{00e9}\u{00e8}"] {
            assert_eq!(hash_to_field(s.as_bytes())[0], 0x00);
        }
    }

    #[test]
    fn message_without_action_matches_official_vector() {
        let nonce = hex::decode("008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd")
            .unwrap();
        let mut n = [0u8; 32];
        n.copy_from_slice(&nonce);
        let msg = compute_rp_signature_message(&n, 1_700_000_000, 1_700_000_300, None);
        assert_eq!(msg.len(), 49);
        assert_eq!(
            hex::encode(&msg),
            "01008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd000000006553f100000000006553f22c"
        );
    }

    #[test]
    fn message_with_action_matches_official_vector() {
        let nonce = hex::decode("008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd")
            .unwrap();
        let mut n = [0u8; 32];
        n.copy_from_slice(&nonce);
        let msg =
            compute_rp_signature_message(&n, 1_700_000_000, 1_700_000_300, Some("test-action"));
        assert_eq!(msg.len(), 81);
        assert_eq!(
            hex::encode(&msg),
            "01008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd000000006553f100000000006553f22c00aa0ce59768ae5b1c52f07a9387f14f09f277422c0d2f8a268c7bad0c60a46a"
        );
    }

    // Deterministic sign vectors: random = [0x00,0x01,…,0x1f], created_at fixed.
    const TEST_KEY: &str = "0xabababababababababababababababababababababababababababababababab";

    fn deterministic_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = i as u8;
        }
        r
    }

    #[test]
    fn nonce_derivation_matches_official_vector() {
        // nonce = hash_to_field([0x00,0x01,…,0x1f])
        assert_eq!(
            hex::encode(hash_to_field(&deterministic_random())),
            "008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd"
        );
    }

    #[test]
    fn sign_request_without_action_matches_official_vector() {
        let key = parse_signing_key(TEST_KEY).unwrap();
        let out = sign_with(
            &key,
            None,
            &deterministic_random(),
            1_700_000_000,
            1_700_000_300,
        );
        assert_eq!(
            out.nonce,
            "0x008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd"
        );
        assert_eq!(
            out.sig,
            "0x14f693175773aed912852a601e9c0fd30f2afe2738d31388316232ce6f64ae9e4edbfb19d81c4229ba9c9fca78ede4b28956b7ba4415f08d957cbc1b3bdaa4021b"
        );
    }

    #[test]
    fn sign_request_with_action_matches_official_vector() {
        let key = parse_signing_key(TEST_KEY).unwrap();
        let out = sign_with(
            &key,
            Some("test-action"),
            &deterministic_random(),
            1_700_000_000,
            1_700_000_300,
        );
        assert_eq!(
            out.sig,
            "0x05594adb6c1495768a38d523d7d6ee6356b2c31231919198794ed022ade7d08f73753f83bd167067d99c9b969d28e9222315837c66af25867b041273a6d5056f1b"
        );
    }

    #[test]
    fn parse_signing_key_accepts_with_and_without_0x() {
        assert!(parse_signing_key(TEST_KEY).is_ok());
        assert!(parse_signing_key(TEST_KEY.trim_start_matches("0x")).is_ok());
        assert!(matches!(
            parse_signing_key("0x1234"),
            Err(SignError::BadKey)
        ));
        assert!(matches!(
            parse_signing_key("nothex"),
            Err(SignError::BadKey)
        ));
    }

    #[test]
    fn sign_request_public_path_produces_well_formed_output() {
        let out = sign_request(TEST_KEY, Some("jamm-election-7"), Some(120)).unwrap();
        assert!(out.sig.starts_with("0x") && out.sig.len() == 2 + 130); // 65 bytes
        assert!(out.nonce.starts_with("0x") && out.nonce.len() == 2 + 64);
        assert_eq!(out.expires_at - out.created_at, 120);
    }
}
