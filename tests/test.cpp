#include <cassert>
#include <array>
#include <iostream>
#include <string>
#include "aes.hpp"

void run_test(const std::string& name, void (*test)()) {
    test();
    std::cout << "[PASS] " << name << '\n';
}

void test_xtime() {
    assert(xtime(0x57) == 0xae);
    assert(xtime(0xae) == 0x47);
}

void test_gmul() {
    assert(gmul(0x01, 0x57) == 0x57);
    assert(gmul(0x02, 0x57) == xtime(0x57));
    assert(gmul(0x03, 0x57) == (xtime(0x57) ^ 0x57));

    // Official AES example
    assert(gmul(0x57, 0x13) == 0xfe);
}

void test_mix_col_word() {
    Word in = pack_word(0xdb,0x13,0x53,0x45);
    Word expected = pack_word(0x8e,0x4d,0xa1,0xbc);

    assert(mix_col_word(in) == expected);
}

void test_shift_row() {
    State in = {
        pack_word(0x00,0x11,0x22,0x33),
        pack_word(0x44,0x55,0x66,0x77),
        pack_word(0x88,0x99,0xaa,0xbb),
        pack_word(0xcc,0xdd,0xee,0xff)
    };

    State expected = {
        pack_word(0x00,0x55,0xaa,0xff),
        pack_word(0x44,0x99,0xee,0x33),
        pack_word(0x88,0xdd,0x22,0x77),
        pack_word(0xcc,0x11,0x66,0xbb)
    };

    assert(shift_row(in) == expected);
}

void test_inv_shift_row() {
    State original = {
        pack_word(0x00,0x11,0x22,0x33),
        pack_word(0x44,0x55,0x66,0x77),
        pack_word(0x88,0x99,0xaa,0xbb),
        pack_word(0xcc,0xdd,0xee,0xff)
    };

    State shifted = shift_row(original);
    State unshifted = inv_shift_row(shifted);

    assert(unshifted == original);
}

void test_sub_bytes() {
    assert(sub_bytes(0x00) == 0x63);  // first entry
    assert(sub_bytes(0xff) == 0x16);  // last entry
    assert(sub_bytes(0x53) == 0xed);  // middle value
    assert(inv_sub_bytes(sub_bytes(0x42)) == 0x42);  // round trip
}

void test_add_round_key() {
    State state = {
        pack_word(0x32,0x88,0x31,0xe0),
        pack_word(0x43,0x5a,0x31,0x37),
        pack_word(0xf6,0x30,0x98,0x07),
        pack_word(0xa8,0x8d,0xa2,0x34)
    };

    State round_key = {
        pack_word(0x2b,0x28,0xab,0x09),
        pack_word(0x7e,0xae,0xf7,0xcf),
        pack_word(0x15,0xd2,0x15,0x4f),
        pack_word(0x16,0xa6,0x88,0x3c)
    };

    State expected = {
        pack_word(0x19,0xa0,0x9a,0xe9),
        pack_word(0x3d,0xf4,0xc6,0xf8),
        pack_word(0xe3,0xe2,0x8d,0x48),
        pack_word(0xbe,0x2b,0x2a,0x08)
    };

    assert(add_round_key(state, round_key) == expected);
}

void test_rot_word() {
    Word in = pack_word(0x09,0xcf,0x4f,0x3c);
    Word expected = pack_word(0xcf,0x4f,0x3c,0x09);

    assert(rot_word(in) == expected);
}

void test_sub_word() {
    Word in = pack_word(0x00,0x53,0xff,0x01);
    Word expected = pack_word(0x63,0xed,0x16,0x7c);

    assert(sub_word(in) == expected);
}

void test_key_expansion() {
    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c
    };

    auto round_keys = key_expansion(key);

    State expected_rk0 = {
        pack_word(0x2b,0x7e,0x15,0x16),
        pack_word(0x28,0xae,0xd2,0xa6),
        pack_word(0xab,0xf7,0x15,0x88),
        pack_word(0x09,0xcf,0x4f,0x3c)
    };

    assert(round_keys[0] == expected_rk0);
}

void test_state_conversion() {
    std::array<uint8_t,16> in = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

    State s = bytes_to_state(in);
    auto out = state_to_bytes(s);

    assert(in == out);

    assert(byte0(s[0]) == 0x00);
    assert(byte1(s[0]) == 0x01);
    assert(byte2(s[0]) == 0x02);
    assert(byte3(s[0]) == 0x03);

    assert(byte0(s[1]) == 0x04);
}

void test_mix_col_state() {
    State in = {
        pack_word(0xdb,0x13,0x53,0x45),
        0,
        0,
        0
    };

    State expected = {
        pack_word(0x8e,0x4d,0xa1,0xbc),
        0,
        0,
        0
    };

    assert(mix_col_state(in) == expected);
}

void test_inv_mix_col_state() {
    State original = {
        pack_word(0xdb,0x13,0x53,0x45),
        pack_word(0xf2,0x0a,0x22,0x5c),
        pack_word(0x01,0x01,0x01,0x01),
        pack_word(0xc6,0xc6,0xc6,0xc6)
    };

    State mixed = mix_col_state(original);
    State unmixed = inv_mix_col_state(mixed);

    assert(unmixed == original);
}

void test_aes128_encrypt_block() {
    std::array<uint8_t,16> plaintext = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };

    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    std::array<uint8_t,16> expected = {
        0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
    };

    std::array<State,11> round_key = key_expansion(key);

    assert(aes128_encrypt_block(plaintext, round_key) == expected);
}

void test_aes128_decrypt_block() {
    std::array<uint8_t,16> ciphertext = {
        0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
    };

    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    std::array<uint8_t,16> expected_plaintext = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };


    std::array<State,11> round_key = key_expansion(key);

    assert(aes128_decrypt_block(ciphertext, round_key) == expected_plaintext);
}

void test_encrypt_decrypt_block_roundtrip() {
    std::array<uint8_t,16> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::array<State,11> round_key = key_expansion(key);
    auto ciphertext = aes128_encrypt_block(plaintext, round_key);
    auto decrypted = aes128_decrypt_block(ciphertext, round_key);

    assert(decrypted == plaintext);
}

void test_ctr_mode_roundtrip() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::string message = "The quick brown fox jumps over the lazy dog, this is a longer message spanning multiple blocks!";

    auto ciphertext = aes128_encrypt_ctr_mode(message, key);
    std::string decrypted = aes128_decrypt_ctr_mode(ciphertext, key);

    assert(decrypted == message);
}

void test_ctr_mode_short_message() {
    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    std::string message = "hi";  // shorter than one block

    auto ciphertext = aes128_encrypt_ctr_mode(message, key);
    std::string decrypted = aes128_decrypt_ctr_mode(ciphertext, key);

    assert(decrypted == message);
}

void test_ctr_mode_empty_message() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::string message = "";

    auto ciphertext = aes128_encrypt_ctr_mode(message, key);
    std::string decrypted = aes128_decrypt_ctr_mode(ciphertext, key);

    assert(decrypted == message);
}

void test_ctr_mode_boundary_lengths() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::vector<size_t> lengths = {15, 16, 17, 31, 32, 33};

    for (size_t len : lengths) {
        std::string message(len, 'x');  // string of 'x' repeated len times

        auto ciphertext = aes128_encrypt_ctr_mode(message, key);
        std::string decrypted = aes128_decrypt_ctr_mode(ciphertext, key);

        assert(decrypted == message);
        assert(decrypted.size() == len);
    }
}

void test_ctr_mode_binary_data() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::string s;
    for(int i = 0; i < 256; i++)
        s.push_back(static_cast<char>(i));

    auto ciphertext = aes128_encrypt_ctr_mode(s, key);
    std::string decrypted = aes128_decrypt_ctr_mode(ciphertext, key);

    assert(decrypted.size() == s.size());
    assert(decrypted == s);
}

void test_pkcs7_pad_empty() {
    std::vector<uint8_t> bytes;
    pkcs7_pad(bytes);
    assert(bytes.size() == 16);
    for(auto b : bytes) assert(b == 0x10);
}

void test_pkcs7_pad_exact_block() {
    std::vector<uint8_t> bytes(16, 0xAA);
    pkcs7_pad(bytes);
    assert(bytes.size() == 32);
    for(size_t i = 16; i < 32; i++) assert(bytes[i] == 0x10);
}

void test_pkcs7_pad_15_bytes() {
    std::vector<uint8_t> bytes(15, 0xAA);
    pkcs7_pad(bytes);
    assert(bytes.size() == 16);
    assert(bytes[15] == 0x01);
}

void test_pkcs7_pad_17_bytes() {
    std::vector<uint8_t> bytes(17, 0xAA);
    pkcs7_pad(bytes);
    assert(bytes.size() == 32);
    for(size_t i = 17; i < 32; i++) assert(bytes[i] == 0x0F);
}

void test_pkcs7_roundtrip() {
    std::vector<size_t> lengths = {0, 1, 15, 16, 17, 31, 32, 33};
    for(size_t len : lengths) {
        std::vector<uint8_t> original(len, 0x42);
        std::vector<uint8_t> bytes = original;

        pkcs7_pad(bytes);
        pkcs7_unpad(bytes);

        assert(bytes == original);
    }
}

void test_cbc_mode_roundtrip() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::string message =
        "The quick brown fox jumps over the lazy dog, "
        "this is a longer message spanning multiple blocks!";

    auto ciphertext = aes128_encrypt_cbc_mode(message, key);
    std::string decrypted = aes128_decrypt_cbc_mode(ciphertext, key);

    assert(decrypted == message);
}

void test_cbc_mode_short_message() {
    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    std::string message = "hi";

    auto ciphertext = aes128_encrypt_cbc_mode(message, key);
    std::string decrypted = aes128_decrypt_cbc_mode(ciphertext, key);

    assert(decrypted == message);
}

void test_cbc_mode_empty_message() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::string message = "";

    auto ciphertext = aes128_encrypt_cbc_mode(message, key);
    std::string decrypted = aes128_decrypt_cbc_mode(ciphertext, key);

    assert(decrypted == message);
}

void test_cbc_mode_boundary_lengths() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::vector<size_t> lengths = {
        15,16,17,
        31,32,33
    };

    for(size_t len : lengths) {
        std::string message(len, 'x');

        auto ciphertext = aes128_encrypt_cbc_mode(message, key);
        auto decrypted = aes128_decrypt_cbc_mode(ciphertext, key);

        assert(decrypted == message);
        assert(decrypted.size() == len);
    }
}

void test_cbc_padding_sizes() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    {
        std::string msg = "";
        auto ct = aes128_encrypt_cbc_mode(msg,key);
        assert(ct.size() == 32);
    }

    {
        std::string msg(16,'a');
        auto ct = aes128_encrypt_cbc_mode(msg,key);
        assert(ct.size() == 48);
    }

    {
        std::string msg(17,'a');
        auto ct = aes128_encrypt_cbc_mode(msg,key);
        assert(ct.size() == 48);
    }
}

void test_cbc_random_iv() {
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::string message = "same plaintext";

    auto ct1 = aes128_encrypt_cbc_mode(message,key);
    auto ct2 = aes128_encrypt_cbc_mode(message,key);

    assert(ct1 != ct2);
}

int main() {
    // Tests for aes128 block implementation
    run_test("xtime", test_xtime);
    run_test("gmul", test_gmul);
    run_test("mix_col_word", test_mix_col_word);
    run_test("mix_col_state",test_mix_col_state);
    run_test("inv_mix_col_state",test_inv_mix_col_state);
    run_test("shift_row", test_shift_row);
    run_test("sub_bytes", test_sub_bytes);
    run_test("add_round_key", test_add_round_key);
    run_test("rot_word",test_rot_word);
    run_test("sub_word",test_sub_word);
    run_test("key_expansion",test_key_expansion);
    run_test("state_conversion",test_state_conversion);
    run_test("aes128_encrypt_block",test_aes128_encrypt_block);
    run_test("aes128_decrpyt_block",test_aes128_encrypt_block);
    run_test("encrypt_decrypt_block_roundtrip",test_encrypt_decrypt_block_roundtrip);

    // Test for CTR mode 
    run_test("ctr_mode_roundtrip",test_ctr_mode_roundtrip); 
    run_test("ctr_mode_short_message",test_ctr_mode_short_message);
    run_test("ctr_mode_empty_message",test_ctr_mode_empty_message);
    run_test("ctr_mode_boundary_lengths",test_ctr_mode_boundary_lengths); 
    run_test("ctr_mode_binary_data",test_ctr_mode_binary_data);

    // Test for pkcs7 padding/unpadding
    run_test("pkcs7_pad_15_bytes",test_pkcs7_pad_15_bytes);
    run_test("pkcs7_pad_17_bytes",test_pkcs7_pad_17_bytes);
    run_test("pkcs7_pad_empty",test_pkcs7_pad_empty);
    run_test("pkcs7_pad_exact_block",test_pkcs7_pad_exact_block);
    run_test("pkcs7_pad_roundtrip",test_pkcs7_roundtrip);

    // Test for CBC mode
    run_test("cbc_mode_roundtrip", test_cbc_mode_roundtrip);
    run_test("cbc_mode_short_message", test_cbc_mode_short_message);
    run_test("cbc_mode_empty_message", test_cbc_mode_empty_message);
    run_test("cbc_mode_boundary_lengths", test_cbc_mode_boundary_lengths);
    run_test("cbc_padding_sizes", test_cbc_padding_sizes);
    run_test("cbc_random_iv", test_cbc_random_iv);

    std::cout << "\nAll tests passed!\n";
    return 0;
}