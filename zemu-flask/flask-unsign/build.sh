#!/usr/bin/env bash
# 编译 zemu-flask。Windows 使用 MSYS2 UCRT64 MinGW，Linux 使用 GCC + CUDA/NVRTC 运行时。
# 不支持 MSVC 等其他工具链:源码用了 GNU 扩展 __attribute__((target("sha,..."))) 与内联汇编级 intrinsics。
# 注意:cc1plus 依赖的 libisl/libmpc/libmpfr 等 DLL 在 ucrt64/bin,
# 需先把该目录加入 PATH,否则编译子进程静默失败(exit 1 无诊断)。
# -municode:入口用 wmain 接收宽字符 argv,转 UTF-8 后进 runMain——
# 否则窄字符 main 拿到 ANSI 码页(中文系统=GBK)字节,非 ASCII 参数失配。
# OpenCL 走运行时 LoadLibrary 动态加载(src/gpu/ocl.cpp),无需链接期依赖。
set -e
cd "$(dirname "$0")"
mkdir -p bin
if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* ]]; then
  export PATH="/c/msys64/ucrt64/bin:$PATH"
  g++ -O3 -std=c++26 -Wall -municode -static -static-libgcc -static-libstdc++ \
    src/main.cpp src/flask.cpp src/crack_cpu.cpp src/gpu/ocl.cpp src/gpu/nvrtc.cpp \
    -o bin/zemu-flask.exe -lz
  echo "built: bin/zemu-flask.exe"
else
  CXX="${CXX:-g++}"
  "$CXX" -O3 -std=c++23 -Wall \
    src/main.cpp src/flask.cpp src/crack_cpu.cpp src/gpu/ocl_stub.cpp src/gpu/nvrtc.cpp \
    -o bin/zemu-flask -ldl -lz
  echo "built: bin/zemu-flask"
fi
