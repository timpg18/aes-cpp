#include "aes.hpp"

static constexpr uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static constexpr uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static constexpr uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t sub_bytes(const uint8_t x){return SBOX[x];}
uint8_t inv_sub_bytes(const uint8_t x){return INV_SBOX[x];}

constexpr std::array<uint8_t,256> make_mul_table(uint8_t multiplier){
    std::array<uint8_t,256> table{};
    for(int i = 0; i < 256; i++){
        table[i] = gmul(multiplier, static_cast<uint8_t>(i));
    }
    return table;
}

static constexpr std::array<uint8_t,256> MUL2 = make_mul_table(0x02);
static constexpr std::array<uint8_t,256> MUL3 = make_mul_table(0x03);
static constexpr std::array<uint8_t,256> MUL9  = make_mul_table(0x09);
static constexpr std::array<uint8_t,256> MUL11 = make_mul_table(0x0b);
static constexpr std::array<uint8_t,256> MUL13 = make_mul_table(0x0d);
static constexpr std::array<uint8_t,256> MUL14 = make_mul_table(0x0e);

// new
Word mix_col_word(const Word& col){
    uint8_t s0 = byte0(col);
    uint8_t s1 = byte1(col);
    uint8_t s2 = byte2(col);
    uint8_t s3 = byte3(col);

    return pack_word(
        MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3,
        s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3,
        s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3],
        MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]
    );
}

Word inv_mix_col_word(const Word& col){
    uint8_t s0 = byte0(col);
    uint8_t s1 = byte1(col);
    uint8_t s2 = byte2(col);
    uint8_t s3 = byte3(col);

    return pack_word(
        MUL14[s0] ^ MUL11[s1] ^ MUL13[s2] ^ MUL9[s3],
        MUL9[s0]  ^ MUL14[s1] ^ MUL11[s2] ^ MUL13[s3],
        MUL13[s0] ^ MUL9[s1]  ^ MUL14[s2] ^ MUL11[s3],
        MUL11[s0] ^ MUL13[s1] ^ MUL9[s2]  ^ MUL14[s3]
    );
}

State mix_col_state(const State& state){
    return {mix_col_word(state[0]),
            mix_col_word(state[1]),
            mix_col_word(state[2]),
            mix_col_word(state[3])};
}

State inv_mix_col_state(const State& state){
    return {inv_mix_col_word(state[0]),
            inv_mix_col_word(state[1]),
            inv_mix_col_word(state[2]),
            inv_mix_col_word(state[3])};
}

State shift_row(const State& state){
    return {
        pack_word(
            byte0(state[0]),
            byte1(state[1]),
            byte2(state[2]),
            byte3(state[3])
        ),
        pack_word(
            byte0(state[1]),
            byte1(state[2]),
            byte2(state[3]),
            byte3(state[0])
        ),
        pack_word(
            byte0(state[2]),
            byte1(state[3]),
            byte2(state[0]),
            byte3(state[1])
        ),
        pack_word(
            byte0(state[3]),
            byte1(state[0]),
            byte2(state[1]),
            byte3(state[2])
        )
    };
}

State inv_shift_row(const State& state){
    return {
        pack_word(
            byte0(state[0]),
            byte1(state[3]),
            byte2(state[2]),
            byte3(state[1])
        ),
        pack_word(
            byte0(state[1]),
            byte1(state[0]),
            byte2(state[3]),
            byte3(state[2])
        ),
        pack_word(
            byte0(state[2]),
            byte1(state[1]),
            byte2(state[0]),
            byte3(state[3])
        ),
        pack_word(
            byte0(state[3]),
            byte1(state[2]),
            byte2(state[1]),
            byte3(state[0])
        )
    };
}

Word sub_word(const Word& word){
    return (static_cast<uint32_t>(SBOX[(word >> 24) & 0xFF]) << 24) |
           (static_cast<uint32_t>(SBOX[(word >> 16) & 0xFF]) << 16) |
           (static_cast<uint32_t>(SBOX[(word >>  8) & 0xFF]) <<  8) |
           (static_cast<uint32_t>(SBOX[(word      ) & 0xFF]));
}

Word inv_sub_word(const Word& word){
    return (static_cast<uint32_t>(INV_SBOX[(word >> 24) & 0xFF]) << 24) |
           (static_cast<uint32_t>(INV_SBOX[(word >> 16) & 0xFF]) << 16) |
           (static_cast<uint32_t>(INV_SBOX[(word >>  8) & 0xFF]) <<  8) |
           (static_cast<uint32_t>(INV_SBOX[(word      ) & 0xFF]));
}

State sub_bytes_state(const State& state){
    return {
        sub_word(state[0]),
        sub_word(state[1]),
        sub_word(state[2]),
        sub_word(state[3])
    };
}

State inv_sub_bytes_state(const State& state){
    return {
        inv_sub_word(state[0]),
        inv_sub_word(state[1]),
        inv_sub_word(state[2]),
        inv_sub_word(state[3])
    };
}

State add_round_key(const State& state, const State& round_key){
    State new_state;
    for(size_t row = 0; row < 4; row++){
        new_state[row] = state[row] ^ round_key[row];    
    }
    return new_state;
}

Word rot_word(const Word& word){
    return (word << 8) | (word >> 24);
}

std::array<State,11> key_expansion(const std::array<uint8_t,16>& key){
    std::array<Word,44> words;
    words[0] = pack_word(key[0],key[1],key[2],key[3]);
    words[1] = pack_word(key[4],key[5],key[6],key[7]);
    words[2] = pack_word(key[8],key[9],key[10],key[11]);
    words[3] = pack_word(key[12],key[13],key[14],key[15]);

    // main loop
    for(size_t i = 4; i < 44; i++){
        Word temp = words[i - 1];
        if(i % 4 == 0){
            temp = rot_word(temp);
            temp = sub_word(temp);
            temp ^= (static_cast<uint32_t>(RCON[i/4 - 1]) << 24);
        }
        words[i] = words[i - 4] ^ temp;
        
    }

    // conversion to State
    std::array<State,11> expanded_key;
    for( size_t key_no = 0; key_no < 11; key_no++ ){
        for(size_t row = 0; row < 4; row++){
            expanded_key[key_no][row] = words[key_no*4 + row];
        }
    }

    return expanded_key;
}

State bytes_to_state(const std::array<uint8_t,16>& bytes){
    State state;

    for(size_t col = 0; col < 4; col++){
        state[col] =
            (static_cast<uint32_t>(bytes[4*col + 0]) << 24) |
            (static_cast<uint32_t>(bytes[4*col + 1]) << 16) |
            (static_cast<uint32_t>(bytes[4*col + 2]) << 8 ) |
            (static_cast<uint32_t>(bytes[4*col + 3]));
    }

    return state;
}

std::array<uint8_t,16> state_to_bytes(const State& state){
    std::array<uint8_t,16> bytes;

    for(size_t col = 0; col < 4; col++){
        bytes[4*col + 0] = static_cast<uint8_t>((state[col] >> 24) & 0xFF);
        bytes[4*col + 1] = static_cast<uint8_t>((state[col] >> 16) & 0xFF);
        bytes[4*col + 2] = static_cast<uint8_t>((state[col] >> 8 ) & 0xFF);
        bytes[4*col + 3] = static_cast<uint8_t>( state[col]        & 0xFF);
    }

    return bytes;
}

std::array<uint8_t,16> aes128_encrypt_block(const std::array<uint8_t,16>& plaintext,const std::array<State,11>& round_key){
    State state = bytes_to_state(plaintext);

    state = add_round_key(state, round_key[0]);
    for(size_t round = 1; round < 10; round ++ ){
        state = sub_bytes_state(state);
        state = shift_row(state);
        state = mix_col_state(state);
        state = add_round_key(state, round_key[round]);
    }
    
    // final round - no mix columns
    state = sub_bytes_state(state);
    state = shift_row(state);
    state = add_round_key(state, round_key[10]);

    std::array<uint8_t,16> ciphertext = state_to_bytes(state);
    return ciphertext;
}

std::array<uint8_t,16> aes128_decrypt_block(const std::array<uint8_t,16>& ciphertext,const std::array<State,11>& round_key){
    State state = bytes_to_state(ciphertext);

    state = add_round_key(state,round_key[10]);
    for(size_t round = 9; round != 0; round--){
        state = inv_shift_row(state);
        state = inv_sub_bytes_state(state);
        state = add_round_key(state,round_key[round]);
        state = inv_mix_col_state(state);
    }

    // final round — no inv_mix_columns
    state = inv_shift_row(state);
    state = inv_sub_bytes_state(state);
    state = add_round_key(state,round_key[0]);

    std::array<uint8_t,16> plaintext = state_to_bytes(state);
    return plaintext;
}

template<uint8_t N>
std::array<uint8_t,N> generate_nonce(){
    std::array<uint8_t,N> nonce;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for(auto& b : nonce) b = static_cast<uint8_t>(dist(gen));
    return nonce;
}

std::array<uint8_t,16> make_counter_block(const std::array<uint8_t,8>& nonce, uint64_t counter){
    std::array<uint8_t,16> block;
    for(int i = 0; i < 8; i++) block[i] = nonce[i];
    for(int i = 0; i < 8; i++) block[8+i] = static_cast<uint8_t>((counter >> (8*(7-i))) & 0xFF);
    return block;
}

void pkcs7_pad(std::vector<uint8_t>& bytes){
    size_t original_size = bytes.size(); 
    uint8_t pad_needed = static_cast<uint8_t>(16 - (original_size & 15));
    bytes.resize(original_size + pad_needed);
    for(size_t i = 0; i < pad_needed; i++){
        bytes[original_size + i] = pad_needed;
    }
}

void pkcs7_unpad(std::vector<uint8_t>& bytes){
    uint8_t original_pad = bytes[bytes.size() - 1];
    bytes.resize(bytes.size() - original_pad);
}

std::vector<uint8_t> aes128_encrypt_ctr_mode(const std::string& message, const std::array<uint8_t,16>& key){
    std::vector<uint8_t> bytes(message.begin(),message.end());
    unsigned long long message_size = bytes.size();

    std::array<State,11> round_key = key_expansion(key);

    std::array<uint8_t,8> nonce = generate_nonce<8>();
    uint64_t counter = 0;
    std::vector<uint8_t> ciphertext;
    ciphertext.resize(message_size + 8);
    for(size_t i = 0; i < 8; i++) ciphertext[i] = nonce[i];

    size_t index = 8;
    for(size_t block = 0; block < message_size; block+=16){
        std::array<uint8_t,16> ctr = make_counter_block(nonce, counter);
        counter++;
        std::array<uint8_t,16> encrypted_ctr = aes128_encrypt_block(ctr,round_key);
        size_t size = std::min<size_t>(16, message_size - block);
        for(size_t i = 0; i < size ; i++ ){
            ciphertext[index++] = encrypted_ctr[i] ^ bytes[block + i];
        }
    }

    return ciphertext;
}

std::string aes128_decrypt_ctr_mode(const std::vector<uint8_t>& ciphertext, const std::array<uint8_t,16>& key){
    std::array<uint8_t,8> nonce;
    for(size_t i = 0; i < 8; i++)nonce[i] = ciphertext[i];
    unsigned long long cipher_size = ciphertext.size() - 8;

    std::array<State,11> round_key = key_expansion(key);

    std::vector<uint8_t> bytes;
    bytes.resize(cipher_size);
    uint64_t counter = 0;

    for(size_t block = 0; block < cipher_size; block+=16){
        std::array<uint8_t,16> ctr = make_counter_block(nonce, counter);
        counter++;
        std::array<uint8_t,16> encrypted_ctr = aes128_encrypt_block(ctr,round_key);
        size_t size = std::min<size_t>(16, cipher_size - block);
        for(size_t i = 0; i < size ; i++ ){
            bytes[block + i] = encrypted_ctr[i] ^ ciphertext[block + i + 8];
        }
    }
    
    return std::string(bytes.begin(),bytes.end());
}

std::vector<uint8_t> aes128_encrypt_cbc_mode(const std::string& message, const std::array<uint8_t,16>& key){
    std::vector<uint8_t> bytes(message.begin(),message.end());
    std::array<State,11> round_key = key_expansion(key);
    std::array<uint8_t,16> IV = generate_nonce<16>();
    pkcs7_pad(bytes);
    size_t padded_length = bytes.size();

    std::vector<uint8_t> ciphertext;
    ciphertext.resize(16 + padded_length);
    for(size_t i = 0; i < 16; i++)ciphertext[i] = IV[i];

    std::array<uint8_t,16> prev = IV ;
    std::array<uint8_t,16> curr;
    for(size_t block = 0; block < padded_length; block+=16){
        for(size_t i = 0; i < 16; i++)curr[i] = bytes[block + i] ^ prev[i];
        curr = aes128_encrypt_block(curr,round_key);
        for(size_t i = 0; i < 16; i++)ciphertext[16 + block + i] = curr[i];
        prev = curr;
    }

    return ciphertext;
}

std::string aes128_decrypt_cbc_mode(const std::vector<uint8_t>& ciphertext, const std::array<uint8_t,16>& key){
    size_t original_size = ciphertext.size() - 16;
    std::array<uint8_t,16> IV;
    for(size_t i = 0; i < 16; i++)IV[i] = ciphertext[i];
    std::vector<uint8_t> plaintext;
    plaintext.resize(original_size);

    std::array<State,11> round_key = key_expansion(key);

    std::array<uint8_t,16> prev = IV;
    std::array<uint8_t,16> curr;
    std::array<uint8_t,16> ciphertext_block;

    for(size_t block = 0; block < original_size; block+=16){
        for(size_t i = 0; i < 16; i++)ciphertext_block[i] = ciphertext[block + 16 + i];
        curr = aes128_decrypt_block(ciphertext_block,round_key);

        for(size_t i = 0; i < 16; i++)plaintext[block + i] = curr[i] ^ prev[i];
        prev = ciphertext_block;
    }

    pkcs7_unpad(plaintext);
    return std::string(plaintext.begin(),plaintext.end());
}