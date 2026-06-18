# AES-128 Implementation in C++

A from-scratch implementation of the AES-128 block cipher in C++20, including CTR mode for encrypting arbitrary-length messages, written without any external cryptography libraries.

## About

AES (Advanced Encryption Standard) is a symmetric block cipher that encrypts data in fixed 128-bit (16-byte) blocks. It is standardized by NIST in FIPS 197 and is the most widely used symmetric encryption algorithm today.

This implementation covers:
- GF(2^8) finite field arithmetic
- S-box substitution (SubBytes / InvSubBytes)
- Row shifting (ShiftRows / InvShiftRows)
- Column mixing (MixColumns / InvMixColumns)
- Key expansion (key schedule generation)
- The full AES-128 block encrypt/decrypt pipeline
- CTR mode, allowing encryption of messages of any length

## Project Structure

    aes-cpp/
    ├── include/
    │   └── aes.hpp       # Public interface
    ├── src/
    │   └── aes.cpp        # Implementation
    ├── tests/
    │   └── test.cpp       # Test suite
    ├── main.cpp           # CLI driver
    ├── build.sh            # Build and run
    └── test.sh             # Build and run tests

## Building

### Run with input

    chmod +x build.sh
    ./build.sh

Edit the INPUT and KEY variables in build.sh to try different messages and keys.

### Run tests

    chmod +x test.sh
    ./test.sh

## Usage

    #include "aes.hpp"

    std::array<uint8_t,16> key = { ... };
    auto ciphertext = aes128_encrypt_ctr_mode("hello world", key);
    std::string plaintext = aes128_decrypt_ctr_mode(ciphertext, key);

## Implementation Details

### Block Cipher Primitive

`aes128_encrypt_block` and `aes128_decrypt_block` implement the core AES-128 transformation on exactly one 16-byte block, following FIPS 197:

1. **Key Expansion** — derives 11 round keys (176 bytes total) from the original 16-byte key using RotWord, SubWord, and round constants (Rcon)
2. **Initial round** — AddRoundKey only
3. **9 main rounds** — SubBytes, ShiftRows, MixColumns, AddRoundKey
4. **Final round** — SubBytes, ShiftRows, AddRoundKey (no MixColumns)

Decryption mirrors this with the inverse operations in reverse order.

### CTR Mode

The block cipher alone only encrypts exactly 16 bytes at a time, and the same plaintext block always produces the same ciphertext block under a fixed key — which leaks patterns and is insecure for real messages. CTR (Counter) mode solves this by turning the block cipher into a stream cipher.

Instead of encrypting the plaintext directly, CTR mode encrypts a **counter block** and XORs the result with the plaintext:

    keystream_block_i = AES_encrypt_block(nonce || counter_i, key)
    ciphertext_block_i = plaintext_block_i XOR keystream_block_i

**Why the nonce matters**

The nonce (number used once) is an 8-byte random value generated fresh for every message. It is combined with an 8-byte big-endian counter to form the 16-byte input block fed into AES for each chunk. The counter increments by 1 for each successive 16-byte block of the message, while the nonce stays fixed for the entire message.

The nonce exists to guarantee that encrypting the same plaintext twice — even with the same key — produces different ciphertext each time, since a new random nonce is generated per call. Without it, identical messages would always produce identical ciphertext, leaking information to an observer.

This implementation prepends the 8-byte nonce to the front of the ciphertext output, so the decrypt function can extract it and regenerate the exact same keystream needed to reverse the XOR.

**Why CTR mode specifically**

- No padding required — unlike CBC or ECB, CTR mode encrypts a message of any length without rounding up to a block boundary
- Parallelizable — each block's keystream can be computed independently of the others, since the counter for block *i* doesn't depend on the ciphertext of block *i-1* (unlike CBC mode's chaining)

## Test Coverage

The test suite verifies:
- All core AES-128 building blocks (xtime, gmul, S-box, ShiftRows, MixColumns, key expansion) against official FIPS 197 values
- Full block encrypt/decrypt against the FIPS 197 Appendix B test vector
- CTR mode round trip correctness for short, long, and empty messages
- Boundary conditions at message lengths of 15, 16, 17, 31, 32, and 33 bytes (catching off-by-one errors in block chunking)
- Binary data containing all 256 possible byte values, including null bytes, to catch signed/unsigned char bugs

## Requirements

- C++20 or later
- g++ compiler

## Security Note

This is an educational implementation built to understand AES internals at the bit level. It has not been audited, includes no protection against timing side-channel attacks, and should not be used to protect real sensitive data. For production use, rely on audited libraries such as OpenSSL or libsodium.

## Performance Optimization

After the initial correct implementation, a profiling pass was done to identify and fix real bottlenecks rather than guessing.

### Methodology

Manual timing harnesses (`benchmark.cpp`, `profile2.cpp`) were used instead of `perf`, since `perf` was unavailable both in WSL2 (kernel mismatch) and GitHub Codespaces (no host kernel access in the container). All comparisons were run in GitHub Codespaces specifically, after the same benchmark on a local laptop produced inconsistent run-to-run results due to CPU frequency scaling and background load — a reminder that benchmarking on a noisy machine produces numbers you can't trust.

### Finding 1 — MixColumns was the single most expensive operation

Isolated timing of the four core round operations (SubBytes, ShiftRows, MixColumns, AddRoundKey) showed MixColumns consistently accounting for ~59-63% of their combined time, roughly 4x the cost of any other single operation. This was because MixColumns called a general-purpose GF(2^8) multiplication function (`gmul`) at runtime, which loops over 8 bits with a branch per bit.

**Fix:** Replaced runtime `gmul` calls with precomputed lookup tables (`MUL2`, `MUL3`, `MUL9`, `MUL11`, `MUL13`, `MUL14`), one per multiplication constant used in MixColumns/InvMixColumns. These tables are generated entirely at compile time using `constexpr` functions, so there is zero runtime cost to building them — the 256-entry tables are baked directly into the binary.

**Result:** ~2.5-3x speedup on MixColumns in isolation, verified for correctness against the original implementation (which is kept in the codebase for comparison) using both the FIPS 197 test vector and additional sample inputs.

### Finding 2 — key expansion was being redundantly recomputed

The original block encrypt/decrypt functions took the raw 16-byte key and called `key_expansion` internally on every single call. Since a real caller typically encrypts many blocks under the same key, this meant the full 11-round-key schedule (involving RotWord, SubWord, and S-box lookups) was being regenerated from scratch for every 16 bytes of data — far more expensive than any single round operation.

**Fix:** Changed `aes128_encrypt_block`/`aes128_decrypt_block` to accept the already-expanded round keys (`std::array<State,11>`) rather than the raw key, mirroring how real cipher libraries separate key setup from per-block encryption (e.g. OpenSSL's `AES_set_encrypt_key` followed by repeated `AES_encrypt` calls).

**Result:** This was the larger architectural fix of the two, removing per-call overhead that scaled with how many blocks were encrypted under one key.

### Finding 3 — not all "obvious" optimizations help

Manual loop unrolling was tried on `shift_row`, replacing the loop-and-modulo version with 16 direct, hardcoded assignments. This produced no measurable improvement (within noise of the original). The likely explanation: GCC at `-O3` already aggressively unrolls small, fixed-bound loops like this one, so the hand-written version gave the compiler no new information. This was a useful negative result — it showed that optimization effort is best spent on operations with genuinely different algorithmic cost (like replacing an 8-iteration branchy loop with a table lookup), not on fighting a compiler that's already doing its job.

### Net result

| Stage | Throughput (single block, chained) |
|---|---|
| Original implementation | ~31 MB/s |
| After MixColumns tables + key expansion fix | ~43 MB/s |

For reference, OpenSSL's hardware-accelerated AES-NI implementation on the same class of CPU reaches ~1200+ MB/s for the same block size — a reminder that the real performance gap between software AES and hardware AES instructions is roughly 30x, and closing that gap further would require moving to AES-NI compiler intrinsics rather than further software-level tuning.