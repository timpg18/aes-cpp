#pragma once
#include <string>
#include <array>
#include <cstdint>
#include <vector>

uint8_t xtime(const uint8_t b);
uint8_t gmul(const uint8_t a,const uint8_t b);

std::array<uint8_t,4> mixcol(const std::array<uint8_t,4>& col);

std::vector<uint8_t> aes_encrypt(const std::string& message,const std::array<uint8_t,16>& key);

std::string aes_decrypt(const std::vector<uint8_t>& cipher,const std::array<uint8_t,16>& key);
