/**
 * divmagic.h:libdivide 式 u64÷u32 魔数预计算(主机端,OpenCL/CUDA 两后端共用)。
 * q = mul_hi(x, M) >> s(add 档先并回隐含高位);2 的幂(含 1)退化为纯移位。
 * flag: bit0-5 shift,bit6 add,bit7 pow2。
 */
#pragma once

#include <cstdint>

struct DivMagic { uint64_t m; uint32_t flag; };

inline DivMagic divMagicFor(uint32_t d) {
  if ((d & (d - 1)) == 0) { // 2 的幂:纯移位
    uint32_t s = 0;
    while ((1U << s) < d) s++;
    return {0, s | 128};
  }
  int fl = 31 - __builtin_clz(d); // floor(log2 d),d ≥ 3
  // proposed_m = floor(2^(64+fl) / d) < 2^64
  unsigned __int128 num = (unsigned __int128)1 << (64 + fl);
  uint64_t proposed_m = (uint64_t)(num / d);
  uint64_t rem = (uint64_t)(num % d);
  uint64_t e = d - rem;
  uint32_t flag = (uint32_t)fl;
  if (e >= (1ULL << fl)) { // 需要 add 修正档
    proposed_m *= 2;
    uint64_t twice = rem * 2;
    if (twice >= d || twice < rem) proposed_m += 1;
    flag |= 64;
  }
  return {proposed_m + 1, flag};
}
