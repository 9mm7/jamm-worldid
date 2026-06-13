//! RP proof-request signing (World ID 4.0).
//!
//! Implemented from the official spec + test vectors (Plan B — there is no
//! Rust IDKit crate). Every primitive here is pinned to an official vector.

use tiny_keccak::{Hasher, Keccak};

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
}
