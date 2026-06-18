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
    State state = {{
        {{0x00,0x44,0x88,0xcc}},
        {{0x11,0x55,0x99,0xdd}},
        {{0x22,0x66,0xaa,0xee}},
        {{0x33,0x77,0xbb,0xff}}
    }};

    State round_key = {{
        {{0x2b,0x28,0xab,0x09}},
        {{0x7e,0xae,0xf7,0xcf}},
        {{0x15,0xd2,0x15,0x4f}},
        {{0x16,0xa6,0x88,0x3c}}
    }};

    const size_t iterations = 50'000'000;

    double t_sub = time_function(sub_bytes_state, state, iterations);
    double t_shift = time_function(shift_row, state, iterations);
    double t_mix = time_function(mix_col_state, state, iterations);
    double t_mix_fast = time_function(mix_col_state_fast, state, iterations);

    // add_round_key needs two args, so timed separately
    auto start = std::chrono::high_resolution_clock::now();
    for(size_t i = 0; i < iterations; i++){
        state = add_round_key(state, round_key);
    }
    auto end = std::chrono::high_resolution_clock::now();
    double t_add = std::chrono::duration<double>(end - start).count();

    std::cout << "sub_bytes_state: " << t_sub  << " s\n";
    std::cout << "shiftrow:        " << t_shift << " s\n";
    std::cout << "mix_columns:     " << t_mix  << " s\n";
    std::cout << "add_round_key:   " << t_add  << " s\n";

    double total = t_sub + t_shift + t_mix + t_add;
    std::cout << "\nApprox breakdown (% of these 4 functions combined):\n";
    std::cout << "sub_bytes_state: " << (t_sub/total)*100  << "%\n";
    std::cout << "shiftrow:        " << (t_shift/total)*100 << "%\n";
    std::cout << "mix_columns:     " << (t_mix/total)*100  << "%\n";
    std::cout << "add_round_key:   " << (t_add/total)*100  << "%\n\n";

    std::cout << "mix_columns (fast):     " << t_mix_fast << " s\n";
    std::cout << "Speedup: " << (t_mix / t_mix_fast) << "x\n";

    return 0;
}