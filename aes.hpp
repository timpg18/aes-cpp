#pragma once
#include <string>
#include <array>
#include <cstdint>
#include <vector>

std::vector<uint8_t> aes_encrypt(const std::string& message,const std::array<uint8_t,16>& key);

std::string aes_decrypt(const std::vector<uint8_t>& cipher,const std::array<uint8_t,16>& key);
