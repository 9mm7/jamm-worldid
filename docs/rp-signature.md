# Reference: World ID 4.0 RP signature spec (AUTHORITATIVE)

> Source: https://docs.world.org/world-id/idkit/signatures (full spec pasted by
> the author during S1). The truncated WebFetch version is superseded by this.
> Test vectors below are CONFIRMED — `crates/worldid` reproduces them.

RP signatures prove a proof request genuinely comes from the app (anti-
impersonation). The backend signs every request with the `signing_key` from the
Developer Portal; World App verifies the signature before generating a proof.
Enforced for World ID 4.0 requests. **Never expose the signing key client-side.**

## Algorithm (pseudocode)

```text
// Use Keccak-256, NOT SHA3-256 (different padding).

function hash_to_field(input_bytes) -> bytes32:
    h = keccak256(input_bytes)           // 32 bytes
    n = big_endian_uint256(h) >> 8       // shift right 8 bits
    return uint256_to_32bytes_be(n)      // always starts with 0x00

function compute_rp_signature_message(nonce_bytes32, created_at_u64, expires_at_u64, action?) -> bytes:
    size = 81 if action else 49
    msg = new bytes(size)
    msg[0]      = 0x01                    // version byte
    msg[1..32]  = nonce_bytes32           // 32-byte field element
    msg[33..40] = u64_to_be(created_at)   // big-endian uint64
    msg[41..48] = u64_to_be(expires_at)   // big-endian uint64
    if action is not null:
        msg[49..80] = hash_to_field(utf8_encode(action))
    return msg

function sign_request(signing_key_hex, action?, ttl_seconds = 300):
    key         = parse_hex_32_bytes(signing_key_hex)   // accepts 0x prefix
    random      = crypto_random_bytes(32)
    nonce_bytes = hash_to_field(random)
    created_at  = unix_time_seconds()
    expires_at  = created_at + ttl_seconds
    msg = compute_rp_signature_message(nonce_bytes, created_at, expires_at, action)
    // EIP-191 prefix uses the DECIMAL byte length of msg (e.g. "49" or "81")
    prefix = "\x19Ethereum Signed Message:\n" + decimal_string(length(msg))
    digest = keccak256(prefix + msg)
    (r, s, recovery_id) = ecdsa_secp256k1_sign(digest, key)
    sig65 = r(32) + s(32) + byte(recovery_id + 27)      // v = recovery_id + 27
    return { sig: "0x"+hex(sig65), nonce: "0x"+hex(nonce_bytes), created_at, expires_at }
```

SDKs (no Rust): JS `@worldcoin/idkit-server` (`signRequest`), Go
`github.com/worldcoin/idkit/go/idkit` (`SignRequest` / `NewSigner`).

## Test vectors (CONFIRMED)

### hash_to_field
```
""            -> 0x00c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4
"test_signal" -> 0x00c1636e0a961a3045054c4d61374422c31a95846b8442f0927ad2ff1d6112ed
[0x01,0x02,0x03] -> 0x00f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92
"hello"       -> 0x001c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36dea
```

### compute_rp_signature_message
```
nonce=0x008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd
created_at=1700000000  expires_at=1700000300

no action (49B):
01008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd000000006553f100000000006553f22c

action "test-action" (81B):
…(above)…00aa0ce59768ae5b1c52f07a9387f14f09f277422c0d2f8a268c7bad0c60a46a
```

### sign_request (deterministic: random=[0x00,0x01,…,0x1f], created_at=1700000000, ttl=300)
```
signing_key=0xabababababababababababababababababababababababababababababababab
=> nonce=0x008ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd

no action (session proof), msg 49B:
sig=0x14f693175773aed912852a601e9c0fd30f2afe2738d31388316232ce6f64ae9e4edbfb19d81c4229ba9c9fca78ede4b28956b7ba4415f08d957cbc1b3bdaa4021b

action "test-action" (uniqueness proof), msg 81B:
sig=0x05594adb6c1495768a38d523d7d6ee6356b2c31231919198794ed022ade7d08f73753f83bd167067d99c9b969d28e9222315837c66af25867b041273a6d5056f1b
```

Note the deterministic-test detail: `nonce = hash_to_field(random)` where
`random = [0x00,0x01,…,0x1f]`, so `hash_to_field([0..32]) = 0x008ae1aa…` is
itself a usable vector. ECDSA is RFC-6979 deterministic, so the sigs reproduce.
