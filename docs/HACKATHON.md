# HACKATHON.md — ETHGlobal NYC 2026 · World ID feature for Jàmm

> Context file for Claude Code. Read this first. This drives the next ~36 hours.

## Mission

Ship **sybil-resistant voting** into Jàmm by integrating **World ID 4.0 (IDKit)**.
Goal: one verified human = one ballot **per election**. This is the
ETHGlobal NYC "Continuity / Ship a Feature" track. The feature code must be
written DURING the event and pushed to a **public** repo with frequent commits.

## Hard constraints (do not violate)

- **Public repo, granular commits.** Judges manually review the git history.
  One commit per TDD slice (red → green), clear messages. NO large squashed
  dumps. The commit history is the proof of authorship and the AI-attribution
  alibi.
- **First commit is dated from the event** (Fri 13:00+). This repo
  (`jamm-worldid`) did not exist before the hackathon.
- **Proof validation happens server-side only.** Never validate a World ID
  proof on the client. This is a World Track B qualification requirement.
- **No scope creep.** Anything outside the slice plan below goes to `LATER.md`.
  No exceptions. The author's known failure mode is stalling at ~95% by
  expanding scope — actively resist it.
- **The author must understand every diff before merge.** If a slice is
  non-trivial, explain it in plain language before committing. The author is
  presenting this to judges Sunday and did not hand-write most of the code.
- **Stay local-first.** The core stays offline. Only the World ID verification
  makes an outbound call (to the World Developer Portal). Don't introduce new
  cloud dependencies.

## Credentials (already provisioned)

- `app_id` — public
- `rp_id` — public (World ID 4.0 Relying Party id)
- `signing_key` — SECRET. Server-only. Goes in `.env` (gitignored BEFORE first
  commit). Never in client code, never in the repo, never logged.

→ First action: confirm `.env` is gitignored and the signing key is loaded from
env, not hardcoded.

## Architecture decisions (locked)

- **Action format:** `jamm-election-{election_id}` → nullifier is unique per
  human *and per election*; re-verification across elections stays unlinkable.
- **Backend signs the proof request** with `signing_key` (RP context:
  sig, nonce, created_at, expires_at). Only sign actions for elections that are
  actually OPEN — never sign arbitrary client-supplied actions.
- **Backend forwards the IDKit response as-is** to
  `POST https://developer.world.org/api/v4/verify/{rp_id}`. Non-2xx ⇒ reject.
- **Nullifier persistence (security-critical):** normalize the nullifier to a
  canonical 32-byte BLOB (strip `0x`, lowercase, left-pad to 64 hex, decode) at
  a SINGLE choke point, with property tests for mixed-case / short-hex inputs.
  Enforce `UNIQUE(election_id, nullifier)` in SQLite/SQLCipher. The Portal only
  proves cryptographic validity — WE enforce uniqueness.
- **Chain anchoring (the differentiator):** append a `world_id_verified` event
  (election_id, nullifier, verified_at — no personal data exists to leak) to the
  canonical integrity chain, so verifications are tamper-evident and visible to
  the independent Python verifier.
- **Ballot gate:** ballot submission requires an existing verification row for
  (election_id, member session).

## Response-shape gotcha

Because we set `allow_legacy_proofs: true`, the verify payload can arrive in
THREE shapes (3.0 legacy single-hex proof, 4.0 uniqueness proof-array, 4.0
session with `session_nullifier`). Parse defensively; extract the nullifier
from whichever shape arrives. Don't assume one schema.

## Slice plan (TDD)

- **S0 — SPIKE (timebox 1h, do this first):** is the Rust core crate from
  `worldcoin/idkit` usable directly for RP request signing?
  - Plan A: yes → use it natively.
  - Plan B: no → implement signing in Rust from
    https://docs.world.org/world-id/idkit/signatures (it ships pseudocode AND
    test vectors → use them as TDD fixtures).
  - Plan C (only if time-pressed): tiny Node sidecar exposing `/rp-signature`.
  Decide, write the decision in a commit message, move on. Do NOT exceed 1h.
- **S1:** RP signature module. Tests = official test vectors.
- **S2:** `/api/worldid/rp-signature` endpoint. Validates election is OPEN
  before signing. Unit + smoke tests.
- **S3:** `/api/worldid/verify` endpoint. Forwards to Portal, handles all 3
  response shapes, maps errors. Tests against a mocked Portal.
- **S4:** nullifier normalization + persistence + `UNIQUE` enforcement +
  `world_id_verified` chain event + ballot-submission gate.
- **S5:** SPA — IDKit React widget in the voting flow. Staging env + simulator
  path. Success / duplicate / error states in the existing design system.
- **S6:** E2E — vote succeeds, duplicate verification rejected, Python verifier
  validates the chain INCLUDING the new event. **Record demo video Saturday
  night** (not Sunday).

## Demo (Sunday) — what the video / live judging must show

1. Org opens an election (desktop admin).
2. Member opens the SPA, verifies with World ID (QR → World App), votes.
3. Second verification attempt for the same election → rejected (same nullifier).
4. Run the independent Python verifier → chain valid, `world_id_verified` event
   visible. Tagline: "You don't have to trust Jàmm — or World — the chain
   proves it."

Video requirements: 2–4 min, ≥720p, clear voice narration, NO background music.

## Definition of done (for submission Sunday)

- [ ] Feature merged, all tests green (fmt + `clippy -D warnings`).
- [ ] Public repo with granular commit history from Fri 13:00+.
- [ ] README (feature) + AI-attribution section.
- [ ] Demo video recorded (Sat night) and linked.
- [ ] Submission "How it's made" text matches what actually shipped (if the
      spike landed on Plan C / Node sidecar, update the text — don't claim
      "Rust backend signing" if it isn't).
- [ ] Direct GitHub link to the `/v4/verify` call line (for the World prize form).

## Stretch (ONLY if World ID is fully done + video recorded + time left)

ENS naming for organizations/elections (e.g. `org.jamm.eth`). Scope it minimal
(naming only). If there isn't comfortable margin, DO NOT START — a clean single
integration beats two half-built ones. This is a reward, not a second front.

## Out of scope this weekend

- Anything outside the World ID feature — the rest of the application is
  frozen for the duration of the event.
