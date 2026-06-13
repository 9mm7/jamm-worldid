# AI Workflow & Attribution

This World ID feature was built with Claude Code (Anthropic) under a
test-driven, spec-driven workflow. The implementation code was written by the
AI; I directed the work and own the design. I set the architecture and the
security model — server-side-only proof validation, the `jamm-election-{id}`
action scheme (one human, one ballot per election), nullifier normalization at
a single choke point with a `UNIQUE(election_id, nullifier)` constraint, and
anchoring each verification into a tamper-evident integrity chain — defined the
constraints and the TDD slice plan, and verified the security-critical code
myself: notably, the Rust RP-signature implementation is checked byte-for-byte
against World's official test vectors before it is trusted. The directing
context (`HACKATHON.md`), the slice spec (`SLICE_PLAN.md`), the prompts I used
(`PROMPTS.md`), and the per-slice gate log (`GATE_LOG.md`) are in this folder;
the granular commit history is the authorship trail.
