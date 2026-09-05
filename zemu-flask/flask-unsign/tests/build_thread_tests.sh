#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
export PATH="/c/msys64/ucrt64/bin:$PATH"
g++ -O2 -std=c++26 -Wall -municode -static -static-libgcc -static-libstdc++ \
  -DZK_THREAD_TESTING src/main.cpp src/flask.cpp src/crack_cpu.cpp \
  src/gpu/ocl.cpp src/gpu/nvrtc.cpp -o bin/test_thread_cleanup.exe -lz
echo "built: bin/test_thread_cleanup.exe (test-only fault injection)"
g++ -O2 -std=c++26 -Wall -static -static-libgcc -static-libstdc++ \
  tests/thread_group_test.cpp src/crack_cpu.cpp -o bin/thread_group_test.exe
