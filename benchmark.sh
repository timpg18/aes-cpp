#!/bin/bash

g++ -std=c++20 -O3 benchmark.cpp src/aes.cpp -Iinclude -o benchmark

if [ $? -eq 0 ]; then
    echo "Build successful"
    ./benchmark
else
    echo "Build failed"
fi