# AES-128 Implementation in C++

A from-scratch implementation of AES-128 in C++20, including CTR and CBC modes for arbitrary-length messages, with no external cryptography libraries. Verified against FIPS 197 test vectors and profiled for performance.

## Building

    chmod +x build.sh test.sh
    ./build.sh      # edit INPUT and KEY inside to try different values
    ./test.sh

## Usage

    #include "aes.hpp"

    std::array<uint8_t,16> key = { ... };

    // CTR mode — no padding, parallelizable
    auto ciphertext = aes128_encrypt_ctr_mode("hello world", key);
    std::string plaintext = aes128_decrypt_ctr_mode(ciphertext, key);

    // CBC mode — PKCS7 padding, sequential
    auto ciphertext = aes128_encrypt_cbc_mode("hello world", key);
    std::string plaintext = aes128_decrypt_cbc_mode(ciphertext, key);

## Implementation

`aes128_encrypt_block` / `aes128_decrypt_block` implement the core 16-byte AES-128 transformation per FIPS 197: key expansion into 11 round keys (RotWord, SubWord, Rcon), an initial AddRoundKey, 9 main rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey), and a final round without MixColumns. Decryption mirrors this with inverse operations in reverse order. The internal state is represented as four `uint32_t` words, matching how standard AES implementations are structured and enabling natural bitwise operations across 4 bytes at once.

The block cipher alone only handles exactly 16 bytes. Two modes wrap it for arbitrary-length messages:

**CTR mode** — encrypts a per-block counter and XORs the result with plaintext. No padding needed; each block's keystream is independent so the mode is parallelizable. An 8-byte random nonce is prepended to the ciphertext output so decrypt can recover it without a separate channel.

    keystream_i  = AES_encrypt_block(nonce || counter_i, key)
    ciphertext_i = plaintext_i XOR keystream_i

**CBC mode** — XORs each plaintext block with the previous ciphertext block before encrypting, chaining blocks together. Requires PKCS7 padding to align input to 16-byte boundaries. A random 16-byte IV is prepended to the ciphertext output. Unlike CTR, decryption requires `aes128_decrypt_block` and blocks must be processed sequentially.

    ciphertext_0 = AES_encrypt_block(plaintext_0 XOR IV, key)
    ciphertext_i = AES_encrypt_block(plaintext_i XOR ciphertext_{i-1}, key)

## Test Coverage

- Core building blocks (xtime, gmul, S-box, ShiftRows, MixColumns, key expansion) against FIPS 197 values
- Full block encrypt/decrypt against the FIPS 197 Appendix B vector
- CTR and CBC mode round-trips: short, long, and empty messages
- Boundary lengths (15/16/17, 31/32/33 bytes) to catch block-chunking off-by-ones
- All 256 byte values including nulls, to catch signed/unsigned char bugs
- PKCS7 padding edge cases: empty input, exactly-full block, one byte short, one byte over, multi-block

## Performance

Profiled with manual timing harnesses (`perf` was unavailable in both WSL2 and GitHub Codespaces; all numbers below are from Codespaces for consistency, after laptop runs proved too noisy to trust).

| Finding | Fix | Result |
|---|---|---|
| MixColumns cost ~60% of total round time — used a branchy, runtime GF(2⁸) multiply (`gmul`) | Precomputed multiplication tables (`MUL2`, `MUL3`, etc.), generated at compile time via `constexpr` | ~2.5–3x faster MixColumns in isolation |
| Key expansion was recomputed on every block, more expensive than a full round | Block functions now take pre-expanded round keys; key expansion runs once per key, not per block | Largest architectural fix — removes per-block overhead that scales with message length |
| Manually unrolled `ShiftRows` loop, expecting a speedup | No measurable change | GCC at `-O3` already unrolls small fixed loops — a useful negative result on where optimization effort pays off |
| Refactored internal `Word` type from `std::array<uint8_t,4>` to `uint32_t` | Cleaner bit manipulation, XOR across 4 bytes in one instruction, closer to standard AES implementations | No measurable throughput difference at `-O3` — compiler was already doing this implicitly |

**Net throughput** (chained single-block encryption, 10M iterations, Codespaces): ~31 MB/s → ~43 MB/s.

The remaining gap to OpenSSL's ~1200+ MB/s is not closeable with further software tuning — it requires AES-NI hardware intrinsics (`_mm_aesenc_si128`), which replace the entire software round function with a single CPU instruction.

## Requirements

C++20, g++.

## Security Note

Educational implementation, not audited, no side-channel protection. Use OpenSSL or libsodium for anything real.
