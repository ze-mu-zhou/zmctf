#!/usr/bin/env bash
# 编译 zemu-autodan(MSYS2 UCRT64 MinGW g++,静态链接,仅依赖 OpenSSL)。
set -e
cd "$(dirname "$0")"
export PATH="/c/msys64/ucrt64/bin:$PATH"
# WSL 兼容:bash 不会自动补 .exe 后缀,需显式指向 Windows 版 g++
GXX=g++
if ! g++ --version 2>/dev/null | grep -qi mingw; then
  [ -x /mnt/c/msys64/ucrt64/bin/g++.exe ] && GXX=/mnt/c/msys64/ucrt64/bin/g++.exe
fi
mkdir -p bin
"$GXX" -O2 -std=c++26 -Wall \
  src/main.cpp src/http.cpp src/target.cpp src/judge.cpp src/attacks/template.cpp src/attacks/adaptive.cpp src/attacks/autodan.cpp \
  -static -static-libgcc -static-libstdc++ -o bin/zemu-autodan.exe -lssl -lcrypto -lz -lws2_32 -lcrypt32
echo "built: bin/zemu-autodan.exe"
