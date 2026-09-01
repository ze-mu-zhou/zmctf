# zm-hash

高性能、纯标准库的 C++26 命令行 MD5 约束搜索工具。支持大写/小写字母、数字、字母数字、十六进制或自定义输入字符集；全局白名单/黑名单、按位置字符集合；完整摘要或 `?` 通配模式；弱碰撞与完整 MD5 真碰撞；多线程枚举和候选数上限。

## 构建（MSVC）

在 *Developer PowerShell for VS* 中执行：

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

也可以直接编译 `src/main.cpp`，要求启用 C++26。

## 构建（Linux）

以 Debian/Ubuntu 为例：

```bash
sudo apt install build-essential cmake ninja-build
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/zm-hash --mode hash --text hello
```

MSYS2 推荐使用 **UCRT64** 终端：

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## 基线 benchmark

benchmark 使用固定候选数、预热轮次、重复测量和中位数统计；计时从所有线程统一起跑开始，不包含线程创建和预热。校验值用于防止编译器消除 MD5 计算：

```bash
./build/zm-hash --mode benchmark --length 8 --charset lower \
  --threads 4 --bench-candidates 5000000 \
  --bench-warmup 1 --bench-repeats 5 --no-color
```

后续比较 SIMD 版本时必须保持候选长度、字符集、候选数、线程数和编译优化级别一致；建议另外测试 `--threads 1`、物理核心数和逻辑线程数，避免把线程扩展收益误认为 SIMD 收益。

可用 `ZM_HASH_EXTRA_CXX_FLAGS` 追加优化参数，例如测量 GCC 的 `-Ofast`：

```bash
cmake -S . -B build-ofast -G Ninja \
  -DZM_HASH_EXTRA_CXX_FLAGS=-Ofast \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-ofast -j
```

`-Ofast` 对这个以整数运算为主的 MD5 内核不保证有收益，必须用相同 benchmark 参数比较中位数；同时确认两种构建的校验值一致。

混合进制解码默认使用 vendored 的官方 `libdivide` v5.3.0 单头文件，不需要配置时联网；使用 `-DZM_HASH_USE_LIBDIVIDE=OFF` 可关闭并回退原生除法。

在支持 AVX-512F 的 x86-64 CPU 上，benchmark 会自动使用 16 路 AVX-512 单块 MD5；不支持时自动回退标量实现。使用 `--no-simd` 可强制测量标量基线。当前 AVX-512 路径用于 benchmark 对照，搜索模式仍使用标量路径。

MSVC 使用独立的 `md5_avx512.cpp` 编译单元；CMake 会探测 `/arch:AVX512`，只有支持该选项时才启用 AVX-512 代码，主程序本身不强制使用 AVX-512。建议使用支持 `/arch:AVX512` 的新版本 Visual Studio；旧版可通过 `-DZM_HASH_ENABLE_AVX512=OFF` 构建标量版本。

## 示例

```powershell
# 直接计算字符串的 MD5，输出大写十六进制
./build/Release/zm-hash.exe --mode hash --text hello --output-case upper

# 只枚举大写字母，找摘要前 8 位为 00000000 的候选
./build/Release/zm-hash.exe --mode match --length 6 --charset upper `
  --digest-pattern 00000000???????????????????????? --threads 8

# 白名单/黑名单和位置约束可以叠加；位置从 0 开始
./build/Release/zm-hash.exe --mode match --length 5 --charset alnum `
  --allow ABC123 --deny B --position 0=AC,1=12,4=3

# PHP 弱碰撞（magic hash）：两条 MD5 都是 0e 后跟纯数字
./build/Release/zm-hash.exe --mode weak-collision --length 8 --charset alnum --threads 16

# 普通前缀碰撞：前 6 个十六进制字符相同
./build/Release/zm-hash.exe --mode prefix-collision --length 7 --charset digits --weak-hex 6

# 真碰撞：两个不同输入产生相同完整 MD5（穷举空间需足够大）
./build/Release/zm-hash.exe --mode collision --length 8 --charset lower --threads 16
```

候选顺序是按位置字符集合的笛卡尔积进行的。碰撞模式会保留已见摘要对应的输入，内存消耗随候选数增长；对完整 128 位碰撞进行普通穷举在计算上通常不可行，工具不会把弱碰撞误报为真碰撞。
