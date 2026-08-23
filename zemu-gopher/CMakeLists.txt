cmake_minimum_required(VERSION 3.28)
project(zemu-gopher CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(zemu-gopher src/main.cpp)
set_target_properties(zemu-gopher PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
