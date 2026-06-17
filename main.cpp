#include <iostream>
#include <iomanip>
#include <sstream>
#include "aes.hpp"

std::string bytes_to_hex(const std::vector<uint8_t>& bytes){
    std::stringstream ss;
    for(auto b : bytes){
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

std::array<uint8_t,16> parse_key(const std::string& key_str){
    std::array<uint8_t,16> key{};
    for(size_t i = 0; i < 16 && i < key_str.size(); i++){
        key[i] = static_cast<uint8_t>(key_str[i]);
    }
    return key;
}

int main(int argc, char* argv[]){
    if(argc < 3){
        std::cerr << "Usage: ./aes <message> <key (up to 16 chars)>\n";
        return 1;
    }

    std::string message = argv[1];
    std::array<uint8_t,16> key = parse_key(argv[2]);

    std::cout << "Message:   " << message << "\n";

    auto ciphertext = aes128_encrypt_ctr_mode(message, key);
    std::cout << "Encrypted: " << bytes_to_hex(ciphertext) << "\n";

    std::string decrypted = aes128_decrypt_ctr_mode(ciphertext, key);
    std::cout << "Decrypted: " << decrypted << "\n";

    if(decrypted == message){
        std::cout << "Round trip successful\n";
    } else {
        std::cout << "Round trip FAILED\n";
    }

    return 0;
}