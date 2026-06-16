#include <cassert>
#include <array>
#include <iostream>
#include "aes.hpp"

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

int main() {
    test_xtime();
    test_gmul();
    test_mixcol();

    std::cout << "All tests passed!\n";
}