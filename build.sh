#!/bin/bash

INPUT="Hello, AES!"
KEY="mysecretkey12345"

g++ -std=c++20 main.cpp src/aes.cpp -Iinclude -o aes

if [ $? -eq 0 ]; then
    echo "Build successful"
    ./aes "$INPUT" "$KEY"
else
    echo "Build failed"
fi