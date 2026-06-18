#!/bin/bash

set -e

g++ -std=c++20 src/aes.cpp tests/test.cpp -Iinclude -o test

./test