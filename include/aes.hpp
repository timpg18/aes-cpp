#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <string>

using State = std::array<std::array<uint8_t,4>,4>;

uint8_t xtime(uint8_t b);
uint8_t gmul(uint8_t a, uint8_t b);
std::array<uint8_t,4> mixcol(const std::array<uint8_t,4>& col);
State shiftrow(const State& state);
uint8_t sub_bytes(const uint8_t x);
uint8_t inv_sub_bytes(const uint8_t x);

std::vector<uint8_t> aes_encrypt(const std::string& message, const std::array<uint8_t,16>& key);
std::string aes_decrypt(const std::vector<uint8_t>& cipher, const std::array<uint8_t,16>& key);