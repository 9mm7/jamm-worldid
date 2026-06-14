# worldid

World ID 4.0 **relying-party (RP) helpers** for sybil-resistant voting — the
crate behind [Jàmm](https://github.com/9mm7)'s "one verified human = one vote
per ballot". Standalone: no Jàmm core dependencies, so it can be audited and
reused on its own.

It does three things, all server-side:

1. **Sign a proof request** (`sign_request`) so the IDKit client can obtain a
   World ID uniqueness proof for a given action.
2. **Verify a proof** (`verify_with_portal`) by forwarding the IDKit result to
   the World Developer Portal's `/api/v4/verify/{rp_id}` endpoint — the client's
   own verdict is never trusted.
3. **Extract the nullifier** (`locate_nullifier`) — the per-human unique value —
   in canonical form, defensively, so it can key a `UNIQUE(election, nullifier)`
   constraint in the consumer's database.

This crate provides the cryptographic and parsing pieces. **It does not store
anything** — uniqueness is enforced by the consumer persisting the canonical
nullifier under a UNIQUE constraint.

## Security model

- **Validation is server-side only.** `verify_with_portal` is the sole source of
  truth; a client cannot self-certify.
- **The signing key never leaves the server.** It is passed to `sign_request` as
  a hex string and used only to sign; it is never serialized, logged, or
  returned. Keep it out of the client, the repo, and your logs.
- **Nullifier normalization is a single choke point.** `normalize_nullifier`
  collapses every encoding (`0x` prefix, case, omitted leading zeros) to one
  canonical 32-byte value, so two encodings of the same human cannot both pass a
  UNIQUE constraint.
- **Injection-resistant extraction.** The proof is forwarded by the client, so
  `locate_nullifier` does **not** trust the first `nullifier`-keyed field it
  finds. It collects *every* recognized nullifier in the proof and requires them
  to collapse to a single canonical value; a second, distinct value (the
  signature of an injection attempt where a chosen nullifier is planted at a
  location the Portal never validated) is rejected as a conflict. Recursion into
  the proof is depth-bounded.
- **No PII in logs.** The verified nullifier is never logged; only the Portal's
  HTTP verdict (and, on rejection, its error body) is.

## RP signature

There is no official Rust IDKit SDK, so the RP signature is reimplemented from
the [official spec](https://docs.world.org/world-id/idkit/signatures) and pinned
byte-for-byte to the published test vectors:

- `keccak256` (not SHA3) via `tiny-keccak`
- `hash_to_field` — `keccak256` interpreted big-endian, `>> 8`, re-encoded (so
  it always starts with `0x00`, a valid BN254 field element)
- EIP-191 personal-message prefix
- recoverable ECDSA secp256k1 (`k256`), RFC-6979 deterministic, low-S normalized,
  `v = recovery_id + 27`

See [`docs/rp-signature.md`](docs/rp-signature.md) and the vector tests in
[`src/signature.rs`](src/signature.rs).

## Status — honest scope

Built for **ETHGlobal NYC 2026** (hackathon). It has been exercised end-to-end
against **World ID staging via the simulator** (`simulator.worldcoin.org`) — it
has **not** been tested against a physical Orb. The verification path itself is
production-shaped (server-side `/v4/verify`, canonical nullifier, UNIQUE), and
this crate was written with substantial assistance from Claude Code; the RP
signature was validated against the official vectors rather than a reference SDK.

## Usage sketch

```rust
use worldid::{sign_request, verify_with_portal, locate_nullifier, NullifierLookup};

// 1. Sign a proof request for a ballot's action (server-side; key from env).
let rp = sign_request(&signing_key_hex, Some("jamm-election-42"), None)?;
// → hand rp.{sig, nonce, created_at, expires_at} to IDKit as rp_context.

// 2. Verify the IDKit result the client returns (server-side).
match verify_with_portal("https://developer.world.org/api/v4/verify", rp_id, &idkit_result).await? {
    worldid::VerifyOutcome::Verified { nullifier_hex } => {
        // persist nullifier_hex under UNIQUE(election, nullifier)
    }
    worldid::VerifyOutcome::Rejected { code } => { /* 400 */ }
    worldid::VerifyOutcome::Malformed => { /* 502 — unusable Portal response */ }
}
```

## Tests

```bash
cargo test -p worldid        # unit + official signature vectors
cargo clippy -p worldid --all-targets -- -D warnings
```

## License

AGPL-3.0-or-later.
