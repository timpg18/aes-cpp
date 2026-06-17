# minimum cmake version required
cmake_minimum_required(VERSION 3.20)

# project name and language
project(aes CXX)

# set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# headers live in include/
include_directories(include)

# main executable
add_executable(aes main.cpp src/aes.cpp)

# test executable
add_executable(test_aes tests/test.cpp src/aes.cpp)