#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
# Windows/MSYS2 test build. Honor CXX/PATH first; otherwise use this
# MSYS2 installation's UCRT64 compiler, independent of its drive/directory.
if [[ "$OSTYPE" != msys* && "$OSTYPE" != cygwin* ]]; then
  echo "This test build requires Windows with MSYS2 MinGW." >&2
  exit 1
fi
CXX="${CXX:-g++}"
if ! command -v "$CXX" >/dev/null 2>&1; then
  if [[ "$CXX" == g++ && -x /ucrt64/bin/g++.exe ]]; then
    export PATH="/ucrt64/bin:$PATH"
  else
    echo "Compiler not found: $CXX. Set CXX or add MinGW bin to PATH." >&2
    exit 1
  fi
fi
mkdir -p bin
"$CXX" -O2 -std=c++26 -Wall -municode -static -static-libgcc -static-libstdc++ \
  -DZK_THREAD_TESTING src/main.cpp src/flask.cpp src/crack_cpu.cpp \
  src/gpu/ocl.cpp src/gpu/nvrtc.cpp -o bin/test_thread_cleanup.exe -lz
echo "built: bin/test_thread_cleanup.exe (test-only fault injection)"
"$CXX" -O2 -std=c++26 -Wall -static -static-libgcc -static-libstdc++ \
  tests/thread_group_test.cpp src/crack_cpu.cpp -o bin/thread_group_test.exe
