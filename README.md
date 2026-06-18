# AES-128 Implementation in C++

A from-scratch implementation of AES-128 in C++20, including CTR mode for arbitrary-length messages, with no external cryptography libraries. Verified against FIPS 197 test vectors and profiled for performance.

## Building

    chmod +x build.sh test.sh
    ./build.sh      # edit INPUT and KEY inside to try different values
    ./test.sh

## Usage

    #include "aes.hpp"

    std::array<uint8_t,16> key = { ... };
    auto ciphertext = aes128_encrypt_ctr_mode("hello world", key);
    std::string plaintext = aes128_decrypt_ctr_mode(ciphertext, key);

## Implementation

`aes128_encrypt_block` / `aes128_decrypt_block` implement the core 16-byte AES-128 transformation per FIPS 197: key expansion into 11 round keys (RotWord, SubWord, Rcon), an initial AddRoundKey, 9 main rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey), and a final round without MixColumns. Decryption mirrors this with inverse operations in reverse order.

The block cipher alone only handles exactly 16 bytes, and a fixed key always maps the same plaintext block to the same ciphertext block — insecure for real messages. **CTR mode** fixes this by encrypting a per-block counter and XORing the result with the plaintext:

    keystream_i  = AES_encrypt_block(nonce || counter_i, key)
    ciphertext_i = plaintext_i XOR keystream_i

An 8-byte random nonce (prepended to the output) plus an 8-byte counter form each block's input, so identical messages never produce identical ciphertext, and arbitrary-length input needs no padding. Each block's keystream is independent of the others, so this mode is also parallelizable.

## Test Coverage

- Core building blocks (xtime, gmul, S-box, ShiftRows, MixColumns, key expansion) against FIPS 197 values
- Full block encrypt/decrypt against the FIPS 197 Appendix B vector
- CTR mode round-trips: short, long, and empty messages
- Boundary lengths (15/16/17, 31/32/33 bytes) to catch block-chunking off-by-ones
- All 256 byte values including nulls, to catch signed/unsigned char bugs

## Performance

Profiled with manual timing harnesses (`perf` was unavailable in both WSL2 and GitHub Codespaces; all numbers below are from Codespaces for consistency, after laptop runs proved too noisy to trust).

| Finding | Fix | Result |
|---|---|---|
| MixColumns cost ~60% of total round time — used a branchy, runtime GF(2⁸) multiply (`gmul`) | Precomputed multiplication tables (`MUL2`, `MUL3`, etc.), generated at compile time via `constexpr` | ~2.5–3x faster MixColumns, verified against the original `gmul`-based version |
| Key expansion was recomputed on every block, more expensive than a full round | Block functions now take pre-expanded round keys; key expansion runs once per key, not per block | Larger of the two fixes — removes per-block overhead that scales with message size |
| Manually unrolled `ShiftRows`' loop, expecting a speedup | No measurable change | GCC at `-O3` already unrolls small fixed loops — a useful negative result on where optimization effort pays off |

**Net throughput** (chained single-block encryption, 10M iterations): ~31 MB/s → ~43 MB/s.

For reference, OpenSSL's AES-NI hits ~1200+ MB/s on comparable hardware — closing that gap further needs AES-NI intrinsics, not more software tuning.

## Requirements

C++20, g++.

## Security Note

Educational implementation, not audited, no side-channel protection. Use OpenSSL or libsodium for anything real.
