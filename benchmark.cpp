#include <chrono>
#include <iostream>
#include "aes.hpp"

int main(){
    std::array<uint8_t,16> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    std::array<uint8_t,16> block = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };

    // warmup
    auto result = aes128_encrypt_block(block, key);

    const size_t iterations = 10'000'000;

    auto start = std::chrono::high_resolution_clock::now();

    uint8_t checksum = 0;
    for(size_t i = 0; i < iterations; i++){
        result = aes128_encrypt_block(result, key);
        checksum ^= result[0];
    }

    auto end = std::chrono::high_resolution_clock::now();

    double seconds = std::chrono::duration<double>(end - start).count();
    double bytes_processed = static_cast<double>(iterations) * 16;
    double mb_per_sec = (bytes_processed / (1024*1024)) / seconds;

    std::cout << "Checksum (ignore): " << static_cast<int>(checksum) << "\n";
    std::cout << "Iterations: " << iterations << "\n";
    std::cout << "Time: " << seconds << " s\n";
    std::cout << "Throughput: " << mb_per_sec << " MB/s\n";

    return 0;
}