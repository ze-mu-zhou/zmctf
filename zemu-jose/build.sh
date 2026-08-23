#!/usr/bin/env bash
# 编译 zemu-jose(仅支持 MSYS2 UCRT64 的 MinGW g++,静态链接 libcrypto 静态库)。
# 依赖:MSYS2 ucrt64 的 mingw-w64-ucrt-x86_64-openssl 包(提供 libcrypto.a / 头文件)。
# 注意:cc1plus 依赖的 libisl/libmpc/libmpfr 等 DLL 在 ucrt64/bin,须先加入 PATH。
# 自研部分(sha2/hmac/bigint/rsa)不依赖 OpenSSL;OpenSSL 仅用于 ES*/EdDSA/JWE。
set -e
cd "$(dirname "$0")"
export PATH="/c/msys64/ucrt64/bin:$PATH"
mkdir -p bin
g++ -O3 -std=c++26 -Wall -static -static-libgcc -static-libstdc++ \
  src/main.cpp src/jose.cpp src/ossl.cpp src/gpu/ocl.cpp \
  -o bin/zemu-jose.exe -lcrypto -lz -lws2_32 -lcrypt32
echo "built: bin/zemu-jose.exe"
