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