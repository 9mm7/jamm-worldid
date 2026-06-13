# Reference: World ID 4.0 RP signature spec

> Saved during the hackathon (S0) from https://docs.world.org/world-id/idkit/signatures
> via the WebFetch summariser. **Treat the test vectors below as UNVERIFIED /
> truncated** — re-confirm against the Go reference before implementing S1.

## Cryptographic primitive
- **ECDSA secp256k1**, recoverable signature `sig = r ‖ s ‖ v` (65 bytes), hex.
- Signing key: 32-byte hex string, optional `0x` prefix.
- Hash: **Keccak-256** (NOT SHA3-256 — different padding).

## Canonical message (pre-hash)
| field        | bytes | encoding                         |
|--------------|-------|----------------------------------|
| version      | 1     | `0x01`                           |
| nonce        | 32    | field element                    |
| created_at   | 8     | big-endian uint64 (unix seconds) |
| expires_at   | 8     | big-endian uint64 (unix seconds) |
| action_hash  | 32    | optional: `hash_to_field(utf8(action))` |

Total: 49 bytes (no action) or 81 bytes (with action).

## Signing
1. Build the canonical message bytes.
2. Apply **EIP-191** prefix: `"\x19Ethereum Signed Message:\n" + dec(len(msg))`.
3. Keccak-256 the prefixed message.
4. ECDSA secp256k1 sign → `r ‖ s ‖ v`.

## Output object
`{ sig: hex(65B), nonce: 32B field element, created_at: unix, expires_at: unix }`

## Official test vectors (TRUNCATED in fetch — RE-CONFIRM)
```
# Without action
signing_key: 0xabababababababababababababababababababababababababababababababab
nonce:       0x008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd
sig:         0x14f693175773aed912852a601e9c0fd30f2afe2738d31388316232ce6f64ae9e…1b

# With action "test-action"
sig:         0x05594adb6c1495768a38d523d7d6ee6356b2c31231919198794ed022ade7d08f7…1b
```

## SDKs (no Rust)
- JS/TS: `@worldcoin/idkit-server`
- Go: `github.com/worldcoin/idkit/go/idkit` (reference)

## Open items for S1
- [ ] Full untruncated test vectors (key+nonce+created_at+expires_at → sig).
- [ ] Exact `hash_to_field` (World ID / Semaphore field hashing) definition.
- [ ] Confirm EIP-191 vs raw-Keccak (the summariser may have conflated schemes).
- [ ] `created_at`/`expires_at` units (seconds) + nonce generation rules.
