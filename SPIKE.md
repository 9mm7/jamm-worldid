# S0 — Spike: RP signature in Rust? (timebox 1h)

**Question:** is the Rust core crate from `worldcoin/idkit` usable directly for
Relying-Party (RP) proof-request signing?

**Finding:** No official Rust crate for IDKit RP signing. Official SDKs:
- JS/TS: `@worldcoin/idkit-server`
- Go: `github.com/worldcoin/idkit/go/idkit` ← reference implementation

**Decision: Plan B** — implement the RP signature in Rust from the spec, using
the official test vectors as TDD fixtures (red → green). Rust secp256k1 +
Keccak-256 are well-supported (`k256` / `tiny-keccak`), so no Node sidecar
(Plan C) is needed.

**Algorithm (from the docs — see `docs/rp-signature.md`):**
ECDSA secp256k1 (recoverable, `r‖s‖v` = 65 bytes) over an EIP-191-prefixed
Keccak-256 hash of the canonical message:
`version(0x01) ‖ nonce(32) ‖ created_at(8, BE u64) ‖ expires_at(8, BE u64) ‖ [action_hash(32)]`
where `action_hash = hash_to_field(utf8(action))`.

**⚠️ S1 must confirm before implementing** (the doc was fetched via a
summariser; the test vectors came back truncated and the crypto details are
security-critical):
- exact full test vectors (key + nonce → expected sig), and
- the exact `hash_to_field` definition,
sourced from the **Go reference** (`worldcoin/idkit/go/idkit`) as the source of
truth. Do not ship signing code that doesn't reproduce an official test vector.

**Next:** S1 — `crates/worldid` signature module, tests = official vectors.
