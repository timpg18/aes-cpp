#include <chrono>
#include <iostream>
#include "aes.hpp"

template<typename Func, typename Arg>
double time_function(Func f, Arg arg, size_t iterations){
    auto start = std::chrono::high_resolution_clock::now();
    for(size_t i = 0; i < iterations; i++){
        arg = f(arg);
    }
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

int main(){
    const size_t iterations = 10'000'000;

    std::array<uint8_t,16> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    std::array<State,11> round_keys = key_expansion(key);

    State state = {{
        {{0x00,0x44,0x88,0xcc}},
        {{0x11,0x55,0x99,0xdd}},
        {{0x22,0x66,0xaa,0xee}},
        {{0x33,0x77,0xbb,0xff}}
    }};

    std::array<uint8_t,16> block = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };

    double t_sub      = time_function(sub_bytes_state, state, iterations);
    double t_shift     = time_function(shift_row, state, iterations);
    double t_shift_fast = time_function(shift_row_fast, state, iterations);
    double t_mix_fast  = time_function(mix_col_state_fast, state, iterations);

    auto s1 = std::chrono::high_resolution_clock::now();
    std::array<State,11> rk;
    for(size_t i = 0; i < iterations; i++) rk = key_expansion(key);
    auto e1 = std::chrono::high_resolution_clock::now();
    double t_keyexp = std::chrono::duration<double>(e1 - s1).count();

    auto s2 = std::chrono::high_resolution_clock::now();
    auto result = block;
    for(size_t i = 0; i < iterations; i++) result = aes128_encrypt_block(result, round_keys);
    auto e2 = std::chrono::high_resolution_clock::now();
    double t_fullblock = std::chrono::duration<double>(e2 - s2).count();

    std::cout << "sub_bytes_state:        " << t_sub        << " s\n";
    std::cout << "shift_row (original):   " << t_shift      << " s\n";
    std::cout << "shift_row (fast):       " << t_shift_fast << " s\n";
    std::cout << "Speedup:                " << (t_shift / t_shift_fast) << "x\n";
    std::cout << "mix_columns_fast:       " << t_mix_fast   << " s\n";
    std::cout << "key_expansion:          " << t_keyexp     << " s\n";
    std::cout << "full block (no keyexp): " << t_fullblock  << " s\n";

    return 0;
}