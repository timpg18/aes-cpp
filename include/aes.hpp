#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <string>
#include <random>
#include <algorithm>

using Word = std::array<uint8_t,4>;
using State = std::array<Word,4>;

constexpr uint8_t xtime(const uint8_t b){return (b & 0x80) ? ((b << 1) ^ 0x1B ) : (b<<1);}
constexpr uint8_t gmul(const uint8_t a,const uint8_t b){
    uint8_t res = 0;
    uint8_t b_curr = b;
    for(int i = 0;i<8;i++){
        if((a>>i) & 1) res ^=b_curr;
        b_curr = xtime(b_curr);
    }
    return res;
}

Word mix_col_word(const Word& col);
Word inv_mix_col_word(const Word& col);
State mix_col_state(const State& state);
State inv_mix_col_state(const State& state);

State shift_row(const State& state);

// New for implementation
Word mix_col_word_fast(const Word& col);
State mix_col_state_fast(const State& state);
Word inv_mix_col_word_fast(const Word& col);
State inv_mix_col_state_fast(const State& state);

State shift_row_fast(const State& state);

uint8_t sub_bytes(const uint8_t x);
uint8_t inv_sub_bytes(const uint8_t x);
State sub_bytes_state(const State& state);
State inv_sub_bytes_state(const State& state);
State add_round_key(const State& state, const State& round_key);
Word rot_word(const Word& word);
Word sub_word(const Word& word);
std::array<State,11> key_expansion(const std::array<uint8_t,16>& key);
State bytes_to_state(const std::array<uint8_t,16>& bytes);
std::array<uint8_t,16> state_to_bytes(const State& state);
State inv_shift_row(const State& state);

void pkcs7_pad(std::vector<uint8_t>& bytes);
void pkcs7_unpad(std::vector<uint8_t>& bytes);

std::array<uint8_t,16> aes128_encrypt_block(const std::array<uint8_t,16>& plaintext,const std::array<State,11>& round_key);
std::array<uint8_t,16> aes128_decrypt_block(const std::array<uint8_t,16>& ciphertext,const std::array<State,11>& round_key);

// Operation mode - CTR
std::vector<uint8_t> aes128_encrypt_ctr_mode(const std::string& message, const std::array<uint8_t,16>& key);
std::string aes128_decrypt_ctr_mode(const std::vector<uint8_t>& ciphertext, const std::array<uint8_t,16>& key);

// Operation mode - CBC
std::vector<uint8_t> aes128_encrypt_cbc_mode(const std::string& message, const std::array<uint8_t,16>& key);
std::string aes128_decrypt_cbc_mode(const std::vector<uint8_t>& ciphertext, const std::array<uint8_t,16>& key);