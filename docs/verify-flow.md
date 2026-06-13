# Reference: World ID 4.0 verify flow (from the migration guide)

> Saved during S3 from https://docs.world.org/world-id/4-0-migration .
> The exact verify request/response JSON lives at
> /api-reference/developer-portal/verify (still to capture — WebFetch summarises
> it). This file records what the migration guide DOES pin down.

## Client ↔ our backend ↔ Portal

```
client: rpContext = fetch("/api/worldid/rp-context")        // OUR backend (S2)
client: req = IDKit.verify/createSession({ app_id, rp_context }).constraints(orb)
client: completion = req.pollUntilCompletion()
client: fetch("/api/worldid/verify", { body: completion.result })  // OUR backend (S3)
backend: POST https://developer.world.org/api/v4/verify/{rp_id}  (forward result)
```

`rp_context = { rp_id, nonce, created_at, expires_at, signature }`.
**Note for S5:** our S2 endpoint currently returns `{sig, nonce, created_at,
expires_at}` and is named `rp-signature`. IDKit expects an `rp-context` shaped
`{rp_id, nonce, created_at, expires_at, signature}` — add `rp_id` and rename
`sig`→`signature` (or add an `/api/worldid/rp-context` alias) when wiring S5.

## Proof types (the 3-shape gotcha)

| Proof type | nullifier field | stable id |
|------------|-----------------|-----------|
| v3 legacy (allow_legacy_proofs) | `nullifier_hash` | — |
| v4 uniqueness | `nullifier` (one-time-use) | — |
| v4 session | `session_nullifier` (per-proof) | `session_id` |

For Jàmm's **one human = one ballot per scrutin** we use **uniqueness proofs**
(action `jamm-election-{ballot_id}`). The nullifier (whichever of the three
fields arrives) is what we normalize + enforce `UNIQUE(election_id, nullifier)`
on. `allow_legacy_proofs: true` ⇒ a v3 `nullifier_hash` may arrive instead.

## Still to capture (paste the api-reference/verify page)
- [ ] exact POST body to /api/v4/verify/{rp_id}
- [ ] exact success + error response JSON (all 3 shapes)
- [ ] error codes / `code` field values
