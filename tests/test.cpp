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

void test_mixcol() {
    std::array<uint8_t,4> in = {
        0xdb, 0x13, 0x53, 0x45
    };

    std::array<uint8_t,4> expected = {
        0x8e, 0x4d, 0xa1, 0xbc
    };

    assert(mixcol(in) == expected);
}

void test_shiftrow() {
    State in = {{
        {{0x00,0x44,0x88,0xcc}},
        {{0x11,0x55,0x99,0xdd}},
        {{0x22,0x66,0xaa,0xee}},
        {{0x33,0x77,0xbb,0xff}}
    }};

    State expected = {{
        {{0x00,0x44,0x88,0xcc}},
        {{0x55,0x99,0xdd,0x11}},
        {{0xaa,0xee,0x22,0x66}},
        {{0xff,0x33,0x77,0xbb}}
    }};

    assert(shiftrow(in) == expected);
}

void test_sub_bytes() {
    assert(sub_bytes(0x00) == 0x63);  // first entry
    assert(sub_bytes(0xff) == 0x16);  // last entry
    assert(sub_bytes(0x53) == 0xed);  // middle value
    assert(inv_sub_bytes(sub_bytes(0x42)) == 0x42);  // round trip
}

void test_add_round_key() {
    State state = {{
        {{0x32,0x88,0x31,0xe0}},
        {{0x43,0x5a,0x31,0x37}},
        {{0xf6,0x30,0x98,0x07}},
        {{0xa8,0x8d,0xa2,0x34}}
    }};

    State round_key = {{
        {{0x2b,0x28,0xab,0x09}},
        {{0x7e,0xae,0xf7,0xcf}},
        {{0x15,0xd2,0x15,0x4f}},
        {{0x16,0xa6,0x88,0x3c}}
    }};

    State expected = {{
        {{0x19,0xa0,0x9a,0xe9}},
        {{0x3d,0xf4,0xc6,0xf8}},
        {{0xe3,0xe2,0x8d,0x48}},
        {{0xbe,0x2b,0x2a,0x08}}
    }};

    assert(add_round_key(state, round_key) == expected);
}

void test_rot_word() {
    std::array<uint8_t,4> in = {0x09,0xcf,0x4f,0x3c};
    std::array<uint8_t,4> expected = {0xcf,0x4f,0x3c,0x09};
    assert(rot_word(in) == expected);
}

void test_sub_word() {
    std::array<uint8_t,4> in = {0x00,0x53,0xff,0x01};
    std::array<uint8_t,4> expected = {0x63,0xed,0x16,0x7c};
    assert(sub_word(in) == expected);
}

void test_key_expansion() {
    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    auto round_keys = key_expansion(key);

    // round_keys[0] should equal the original key, column-wise
    State expected_rk0 = {{
        {{0x2b,0x28,0xab,0x09}},
        {{0x7e,0xae,0xf7,0xcf}},
        {{0x15,0xd2,0x15,0x4f}},
        {{0x16,0xa6,0x88,0x3c}}
    }};
    assert(round_keys[0] == expected_rk0);

    // round_keys[1] from FIPS 197 example
    State expected_rk1 = {{
        {{0xa0,0x88,0x23,0x2a}},
        {{0xfa,0x54,0xa3,0x6c}},
        {{0xfe,0x2c,0x39,0x76}},
        {{0x17,0xb1,0x39,0x05}}
    }};
    assert(round_keys[1] == expected_rk1);
}

int main() {
    run_test("xtime", test_xtime);
    run_test("gmul", test_gmul);
    run_test("mixcol", test_mixcol);
    run_test("shiftrow", test_shiftrow);
    run_test("sub_bytes", test_sub_bytes);
    run_test("add_round_key", test_add_round_key);
    run_test("rot_word",test_rot_word);
    run_test("sub_word",test_sub_word);
    run_test("key_expansion",test_key_expansion);


    std::cout << "\nAll tests passed!\n";
    return 0;
}