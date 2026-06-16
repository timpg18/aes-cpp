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

int main() {
    run_test("xtime", test_xtime);
    run_test("gmul", test_gmul);
    run_test("mixcol", test_mixcol);
    run_test("shiftrow", test_shiftrow);
    run_test("sub_bytes", test_sub_bytes);

    std::cout << "\nAll tests passed!\n";
    return 0;
}