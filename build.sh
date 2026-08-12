#!/usr/bin/env bash
# 编译 zemu-crypto(MSYS2 UCRT64 g++,静态链接免 DLL 依赖)
# 注意:cc1plus 依赖的 libisl/libmpc/libmpfr 等 DLL 在 ucrt64/bin,
# 需先把该目录加入 PATH,否则编译子进程静默失败(exit 1 无诊断)。
# OpenCL 走运行时 LoadLibrary 动态加载(src/gpu/ocl.cpp),无需链接期依赖。
set -e
cd "$(dirname "$0")"
export PATH="/c/msys64/ucrt64/bin:$PATH"
mkdir -p bin
g++ -O3 -std=c++26 -Wall -static -static-libgcc -static-libstdc++ \
  src/main.cpp src/flask.cpp src/crack_cpu.cpp src/gpu/ocl.cpp src/gpu/nvrtc.cpp \
  -o bin/zemu-crypto.exe -lz
echo "built: bin/zemu-crypto.exe"
