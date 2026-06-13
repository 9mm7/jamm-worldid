# Gate Log — World ID feature (per slice)

Honest per-slice status. "Gate" = the concrete check that had to pass before the
slice was considered done. Commit SHAs are on the `feat/world-id` history.
Where a slice is not yet done, it says so — this log is a transparency artifact,
not a victory lap.

| Slice | What | Commits | Gate | Status |
|-------|------|---------|------|--------|
| S0 | Spike: is there a usable Rust IDKit crate? | `7f85c1c` | Decision recorded (Plan B — reimplement in Rust) before any code | ✅ done |
| Setup | `.env` gitignored + `.env.example` | `a196c25` | Signing key loaded from env, never committed | ✅ done |
| S1a | `hash_to_field` + canonical RP message | `832fa50` | Reproduces all official `hash_to_field` + message vectors byte-for-byte | ✅ done |
| S1b | `sign_request` (secp256k1 recoverable) | `4ea8b07` | Reproduces both official signature vectors (incl. `v = recid + 27`) | ✅ done |
| S2 | `/api/worldid/rp-signature` | `96c9b85`, `221bf32`, `3a9aff5` | Signs OPEN elections only; returns the `rp_context` shape + public `app_id`; smoke-tested | ✅ done |
| nullifier | normalize + 3-shape extraction | `6e65de6` | Property tests over mixed-case / short-hex; extracts from v3/v4/session bodies | ✅ done |
| S3 | verify core + `/api/worldid/verify` | `8d851eb`, `442d8c5` | `classify` covers all 3 shapes + errors; handler forwards to a **mock Portal** in tests; rejects non-open elections | ✅ done |
| S5 | IDKit widget gates the vote | `38d2735` | Widget fetches server-signed `rp_context`, posts proof to the server-side verify; type-check green | ✅ done (widget) |
| e2e seed | linked member + open ballot | `8922ecc` | Member portal + vote path exercisable against the disposable e2e stack | ✅ done |

## Not yet done (honest)

- **Live Portal 2xx** — the RP signature reproduces the official vectors and the
  `rp-signature` endpoint returns a real signature live, but a real proof has
  **not yet been accepted by the Developer Portal** end-to-end via the simulator.
  This is the next milestone.
- **S4 — persistence + chain anchoring + ballot gate.** The
  `worldid_verifications` table (UNIQUE), the `world_id_verified` chain event,
  and the "must be verified to cast" gate are **planned, not yet committed**.
  Until S4 lands, the chain-anchoring claim is a design intent, not shipped code.
- **S6 — E2E + Python verifier recognizing the new event + demo video.**

## Verification I (the author) performed

- Confirmed the S1 tests compare against World's **official** test vectors, not
  self-generated ones.
- Tracked whether the **Developer Portal returned a 2xx** before letting the
  feature claim "works" (see "Not yet done").
- Required server-side-only proof validation and an env-only signing key.
