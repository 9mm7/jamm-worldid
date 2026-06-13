# World ID — Slice Plan (spec-driven, TDD)

> Derived from the internal implementation plan. Private-core file paths are
> genericized (this public repo is the World ID feature only — the Jàmm core
> stays in a separate private repo). The publishing step is just: feature
> artifacts are mirrored to this public repo; the core is never pushed.
>
> Legend for genericized locations:
> - **worldid crate** — `crates/worldid/...` (this public repo)
> - **server** — the private Axum backend (opt-in HTTP server)
> - **core** — the private Rust core (DB migrations, integrity chain, state)
> - **web client** — the private member SPA (React/TS)

**Goal:** one verified human = one ballot per election, with the proof validated
server-side and each verification anchored into a tamper-evident chain.

**Architecture:** the backend signs an RP proof request (key from env), the
client runs IDKit, the backend forwards the IDKit result to the World Developer
Portal `POST /api/v4/verify/{rp_id}`, then normalizes the nullifier, enforces
`UNIQUE(election_id, nullifier)`, and appends a `world_id_verified` chain block.

**Tech:** Rust (`k256` secp256k1, `tiny-keccak`), Axum, SQLite/SQLCipher,
React + `@worldcoin/idkit`.

---

## Status snapshot (committed on `feat/world-id`)

- S0 spike → Plan B (reimplement RP signing in Rust; no usable Rust IDKit crate)
- S1 `hash_to_field` + canonical RP message + `sign_request` (official vectors)
- S2 `/api/worldid/rp-signature` (signs OPEN elections only)
- nullifier normalization + 3-shape extraction
- S3 verify core (`classify`) + `/api/worldid/verify` (forward to Portal)
- S5 IDKit widget gating the member vote
- S4 (persistence + chain event + ballot gate) and S6 (E2E) — pending; see
  `GATE_LOG.md` for the honest per-slice status.

---

## File structure (what each unit owns)

- **worldid crate** `src/signature.rs` — RP signature: `hash_to_field`,
  canonical message, `sign_request` (secp256k1 recoverable, EIP-191, v=recid+27).
- **worldid crate** `src/nullifier.rs` — `normalize_nullifier` (canonical
  32-byte), `extract_nullifier` (defensive, 3 response shapes).
- **worldid crate** `src/verify.rs` — pure verify-response handling: `classify`
  success/failure, `verify_with_portal` (the `/v4/verify` call). No DB.
- **server** `handlers/worldid.rs` — `rp-signature` + `verify` HTTP handlers.
- **server** `worldid_store.rs` (S4) — insert verification row (UNIQUE), append
  the `world_id_verified` chain block, "is (election, member) verified?" read.
- **core** migration (S4) — `worldid_verifications` table + UNIQUE index.
- **web client** member voting route (S5) — IDKit widget + success/error states.

---

## Task 1 — S3 verify-response core (pure, no HTTP) · worldid crate

Files: `crates/worldid/src/verify.rs` (create), `src/lib.rs` (modify).

TDD: write the table-driven tests first (they fail to compile), then implement.

```rust
/// Outcome of a Portal verify call (already-parsed HTTP body + status).
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Verified { nullifier_hex: String },
    Rejected { code: String },
    Malformed,
}

/// Map (HTTP-ok, parsed body) → outcome. Pure; unit-tested against fixtures
/// for all three response shapes (v3 `nullifier_hash`, v4 `nullifier`,
/// v4 session `session_nullifier`) plus error bodies.
pub fn classify(http_ok: bool, body: &serde_json::Value) -> VerifyOutcome { /* … */ }
```

Steps: (1) failing tests for success-each-shape + rejected + malformed →
(2) implement `classify` reusing `extract_nullifier`/`normalize_nullifier` →
(3) `verify_with_portal(base, rp_id, idkit_result)` does the POST and calls
`classify` → (4) green → (5) commit.

## Task 2 — S3 `/api/worldid/verify` HTTP handler · server

Forward the IDKit result verbatim to the Portal; never trust the client verdict.

- Guard: the election must be OPEN (reject otherwise).
- `Verified` → 200 `{ success, nullifier }`; `Rejected` → 400; `Malformed` → 500.
- Smoke-tested against a **mock Portal** (a one-route Axum server on a random
  port) so the test suite never calls the real Portal.
- Config injected (signing key, rp_id, verify URL) via server config loaded
  from env — tests inject the official test key; the real key is env-only.

## Task 3 — S4 verification table + persistence + chain event · core + server

- **core** migration: `worldid_verifications(election_id, nullifier BLOB, …)`
  with `UNIQUE(election_id, nullifier)`. Forward-only; pre-migration backup.
- **server** `worldid_store.rs`:
  - `record_verification` — insert the row, then append a `world_id_verified`
    block to the core integrity chain (`election_id`, `nullifier`, `verified_at`
    — no personal data). The UNIQUE violation is the duplicate-vote signal.
  - `has_verification(election, member)` — read used by the ballot gate.
- TDD: duplicate insert returns a typed "already verified" error (property test
  over mixed-case / short-hex nullifiers, since normalization is the choke point).

## Task 4 — S4 ballot-submission gate · server

Ballot submission requires an existing verification for (election, member
session). Tests: cast without verification → rejected; cast after verification →
accepted; second cast → rejected.

## Task 5 — S5 IDKit widget in the voting flow · web client

- Fetch the server-signed `rp_context` (`{rp_id, nonce, created_at, expires_at,
  signature}`) plus the public `app_id` from `/api/worldid/rp-signature`.
- Launch `IDKitRequestWidget` (`environment: "staging"`, `allow_legacy_proofs`,
  `proofOfHuman` preset, action `jamm-election-{ballot_id}`).
- `onSuccess` → POST the IDKit result to `/api/worldid/verify` (server-side
  validation) → cast only on a Portal 2xx.
- Type-check passes; granular commit.

## Task 6 — S6 E2E + Python verifier + demo

- E2E: vote succeeds; duplicate verification rejected; the independent Python
  chain verifier validates the chain **including** the new `world_id_verified`
  event.
- Record the demo video Saturday night.

---

## Self-review checklist

- Every slice is one red→green→commit unit.
- Proof validation is server-side only; the signing key is env-only.
- The nullifier is normalized at exactly one choke point before any compare.
- No scope creep — off-plan items go to `LATER.md`.
