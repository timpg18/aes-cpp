#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <string>

using Word = std::array<uint8_t,4>;
using State = std::array<Word,4>;

uint8_t xtime(uint8_t b);
uint8_t gmul(uint8_t a, uint8_t b);
Word mix_col(const Word& col);
Word inv_mix_col(const Word& col);
State shift_row(const State& state);
uint8_t sub_bytes(const uint8_t x);
uint8_t inv_sub_bytes(const uint8_t x);
State add_round_key(const State& state, const State& round_key);
Word rot_word(const Word& word);
Word sub_word(const Word& word);
std::array<State,11> key_expansion(const std::array<uint8_t,16>& key);
State bytes_to_state(const std::array<uint8_t,16>& bytes);
std::array<uint8_t,16> state_to_bytes(const State& state);
State mix_columns(const State& state);
State inv_mix_columns(const State& state);
State inv_shift_row(const State& state);

std::array<uint8_t,16> aes_encrypt(const std::array<uint8_t,16>& plaintext,const std::array<uint8_t,16>& key);
std::array<uint8_t,16> aes_decrypt(const std::array<uint8_t,16>& ciphertext,const std::array<uint8_t,16>& key);