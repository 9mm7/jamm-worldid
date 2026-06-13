# Gate Log — World ID feature (per slice)

Honest per-slice status. "Gate" = the concrete check that had to pass before the
slice was considered done. Commit SHAs reference the `feat/world-id` history.
Where something is not yet done, it says so — this log is a transparency
artifact, not a victory lap.

| Slice | What | Commits | Gate | Status |
|-------|------|---------|------|--------|
| S0 | Spike: is there a usable Rust IDKit crate? | `7f85c1c` | Decision recorded (Plan B — reimplement in Rust) before any code | ✅ done |
| Setup | `.env` gitignored + `.env.example` | `a196c25` | Signing key loaded from env, never committed | ✅ done |
| S1a | `hash_to_field` + canonical RP message | `832fa50` | Reproduces all official `hash_to_field` + message vectors byte-for-byte | ✅ done |
| S1b | `sign_request` (secp256k1 recoverable) | `4ea8b07` | Reproduces both official signature vectors (incl. `v = recid + 27`) | ✅ done |
| S2 | `/api/worldid/rp-signature` | `96c9b85`, `221bf32`, `3a9aff5` | Signs OPEN elections only; returns the `rp_context` shape + public `app_id`; smoke-tested | ✅ done |
| nullifier | normalize + 3-shape extraction | `6e65de6` | Property tests over mixed-case / short-hex; extracts from v3/v4/session bodies | ✅ done |
| S3 | verify core + `/api/worldid/verify` | `8d851eb`, `442d8c5` | `classify` covers all 3 shapes + errors; rejects non-open elections; mock-Portal smoke test | ✅ done |
| WAF fix | `User-Agent` on the `/v4/verify` call | `4bad7a9` | The Portal WAF 403s UA-less requests (reqwest sends none); setting a UA reaches the Portal app | ✅ done |
| S5 | IDKit widget in the vote flow | `38d2735` | Widget fetches the server-signed `rp_context`, posts the proof to the server-side verify; wasm served correctly | ✅ done |
| **Live Portal 2xx** | real proof verified end-to-end | live (simulator) | Server log: `World ID Portal verify -> HTTP 200 OK (accepted)`, then the vote is recorded | ✅ **done** |
| S4·2 | verifications table + `UNIQUE(election,nullifier)` | `c779448` | A second verification by the same human for the same election is rejected (`AlreadyVerified`) | ✅ done |
| S4·3 | `worldid.verified` chain event | `6cc1a70` | Block appended (payload = election, nullifier, time — no identity) + back-linked; unit-tested | ✅ done |
| S4·4 | record-on-verify + ballot gate | `ba1ac7a` | Gate blocks a cast without a verification; second verification rejected; smoke-tested | ✅ done |
| chain | canonical v2 for public hash recompute | `6012a02` | `scripts/verify-chain.py` recomputes `BLAKE3(SHA-256)` of every block (incl. `worldid.verified`): **Hash OK 2/2** | ✅ done |

## Proven end to end (real conditions)

Rust RP signature → World's connect API accepts it → simulator proof →
`/api/worldid/verify` → **Developer Portal returns 200** → verification recorded
under `UNIQUE(election_id, nullifier)` → `worldid.verified` block anchored in the
integrity chain (v2) → ballot cast → the independent Python verifier recomputes
the chain hashes cleanly, the World ID event included. A second verification by
the same human is rejected (400). 56 server tests + 26 worldid-crate tests green;
`fmt` + `clippy -D warnings` clean.

## Not yet done (honest)

- **Per-election action `jamm-election-{ballot_id}`.** The live flow uses a fixed,
  pre-registered action (`test-verify`). Sybil resistance already holds today via
  our `UNIQUE(election_id, nullifier)` constraint (one human, one vote per
  election); the per-election action only adds **cross-election unlinkability**
  and depends on World ID **dynamic-action** configuration, which we're clarifying
  with World. The persistence, uniqueness, chain anchoring, and gate are
  action-agnostic — they work identically whichever action string is signed.
- **S6 — Playwright E2E + recorded demo video.**

## Verification the author performed

- Confirmed the S1 tests compare against World's **official** test vectors, not
  self-generated ones.
- Did not let the feature claim "works" until the **Developer Portal returned a
  real 200** — which it now does, end to end.
- Required server-side-only proof validation and an env-only signing key.
- Confirmed the public chain export + `verify-chain.py` recompute every block hash
  (canonical v2), so the verifications are auditable without trusting Jàmm or World.
