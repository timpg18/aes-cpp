#include "aes.hpp"

uint8_t xtime(const uint8_t b){
    return (b & 0x80) ? ((b << 1) ^ 0x1B ) : (b<<1);
}

uint8_t gmul(const uint8_t a,const uint8_t b){
    uint8_t res = 0;
    uint8_t b_curr = b;
    for(int i = 0;i<8;i++){
        if((a>>i) & 1) res ^=b_curr;
        b_curr = xtime(b_curr);
    }
    return res;
}

std::array<uint8_t,4> mixcol(const std::array<uint8_t,4>& col){
    uint8_t s0 = col[0];
    uint8_t s1 = col[1];
    uint8_t s2 = col[2];
    uint8_t s3 = col[3];

    std::array<uint8_t,4> newcol;
    newcol[0] = gmul(0x02,s0) ^ gmul(0x03,s1) ^ s2 ^ s3;
    newcol[1] = s0 ^ gmul(0x02,s1) ^ gmul(0x03,s2) ^ s3;
    newcol[2] = s0 ^ s1 ^ gmul(0x02,s2) ^ gmul(0x03,s3);
    newcol[3] = gmul(0x03,s0) ^ s1 ^ s2 ^ gmul(0x02,s3);

    return newcol;
}

std::vector<uint8_t> aes_encrypt(const std::string& message,const std::array<uint8_t,16>& key){
    
}

std::string aes_decrypt(const std::vector<uint8_t>& cipher,const std::array<uint8_t,16>& key){

}
