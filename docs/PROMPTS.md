# Prompts — how I directed the AI

This file records the key instructions I gave Claude Code to build the World ID
feature this weekend. It is a curated, secret-free selection (not the full chat):
the goal is to show **how the work was directed**, per ETHGlobal's spec-driven
transparency requirement. Quotes are faithful to what I wrote (mixed FR/EN);
each has a one-line English gloss. Nothing here contains keys, tokens, or
internal paths — the signing key was kept in `.env` and never typed into chat.

---

## 1. Kickoff
> « commence dans une branche `feat/world-id` … on commence »

→ Start in a `feat/world-id` branch; build World ID 4.0 sybil-resistant voting.

## 2. Public repo — feature only
> « on peut utiliser le repo public déjà créé `jamm-worldid` ? … on peut juste
> mettre cette portion du code dedans »
> « n'oublie pas, on a décidé de séparer »

→ Publish only the World ID feature to the public `jamm-worldid` repo. The Jàmm
core stays private — we deliberately separated them.

## 3. Security (non-negotiable)
> « la signing key est SECRET — ne la colle PAS dans le chat. Mets-la dans `.env` »
> « n'oublie pas les consignes »
> « repo public, push régulier »

→ The signing key is secret: it lives in `.env` (gitignored), never in chat,
never in the repo, never logged. Validate every proof **server-side only**.
Follow the constraints in `HACKATHON.md`. Public repo, frequent granular commits.

## 4. Spike must decide the approach
> « Le spike S0 a tranché quoi ? La signature RP, elle s'est faite en Rust natif
> (Plan A), réimplémentée en Rust (Plan B), ou sidecar Node (Plan C) ? »

→ Make S0 a real decision: is there a usable Rust IDKit crate (A), do we
reimplement the RP signature in Rust (B), or shell out to a Node sidecar (C)?
Decide, record it in the commit, move on.

## 5. Cryptographic verification (I checked the AI's work)
> « Plan B, et bien exécuté. Laisse-moi vérifier deux-trois points cryptographiques :
> 1. Les tests S1 comparent-ils aux vecteurs officiels ou juste à eux-mêmes ?
> 2. Le Portal a-t-il accepté une vérification (2xx) avec ta signature Rust ? »

→ Before trusting the reimplementation: do the S1 tests compare against World's
**official test vectors** (not self-referential), and has the **Developer Portal
actually returned a 2xx** for our Rust signature? Don't claim it works until both
are true.

## 6. Reorder slices to de-risk the live integration early
> « tire le 2xx live plus tôt. Ne suis pas l'ordre S3→S4→S5→S6 à la lettre :
> S3 endpoint verify → S5 minimal widget IDKit → 🎯 premier 2xx live →
> ensuite seulement S4 (persistance) et S6 (E2E).
> Tu veux atteindre ce jalon ce soir, pas dimanche. »

→ Pull the first live Portal 2xx forward: verify endpoint → minimal IDKit widget
→ live 2xx → only then nullifier persistence + chain anchoring + E2E. Hit the
risky external integration early, not the night before judging.

## 7. Simulator test path
> « simulator.worldcoin.org/select-id … choisis Orb d'abord (si rejet, réessaie
> en Device) »

→ Test with the World ID simulator; try the Orb identity first, fall back to
Device if rejected.

## 8. No scope creep
> « pas de scope creep → tout ce qui est hors-plan va dans `LATER.md` »

→ Park everything off-plan in `LATER.md`. My known failure mode is stalling at
95% by expanding scope — resist it.

## 9. Honesty about AI use
> « reste honnête sur l'utilisation de l'IA »

→ Be accurate about what the AI did vs. what I directed and verified. See
`AI_WORKFLOW.md`.
