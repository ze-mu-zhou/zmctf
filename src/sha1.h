/**
 * sha1.h:SHA1(便携实现 + SHA-NI 硬件路径,运行时 cpuid 调度)+ HMAC-SHA1。
 * 头文件内联全部实现,保证各 TU 内热路径可内联。
 * SHA-NI 块函数单独以 target("sha,sse4.1") 编译,调用前 hasShaNi() 检测;
 * 不支持的 CPU 自动回退便携实现。
 * HMAC 三种形态:
 * - hmacSha1      一次性;
 * - HmacSha1      增量式:key 固定,init 预存 ipad/opad 压缩态,多消息复用;
 * - HmacFixedMsg  预计算:msg 固定、key 逐个变(爆破热路径),尾部块事先拼好,
 *                 每 key 仅做 2+N 次块压缩,无流式缓冲/逐字节 padding。
 */
#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <vector>

/** CPU 是否支持 SHA-NI(cpuid,只查一次) */
inline bool hasShaNi() {
  static const bool v = __builtin_cpu_supports("sha");
  return v;
}

/** 实现强制切换:0=自动,1=便携,2=SHA-NI(selftest 对拍用) */
inline int g_forceImpl = 0;

/**
 * SHA-NI 块压缩:一次处理 blocks 个 64 字节块,原地更新 state(5 个 u32)。
 * 轮次数据流逐行对齐 Crypto++ SHA1_SSE_SHA_Transform。
 */
__attribute__((target("sha,sse4.1")))
inline void sha1niBlocks(uint32_t state[5], const uint8_t* data, size_t blocks) {
  const __m128i MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);
  __m128i ABCD = _mm_loadu_si128((const __m128i*)state);
  __m128i E0 = _mm_set_epi32((int)state[4], 0, 0, 0);
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
  while (blocks--) {
    const __m128i ABCD_SAVE = ABCD;
    const __m128i E0_SAVE = E0;
    __m128i E1, MSG0, MSG1, MSG2, MSG3;

    // 轮 0-3(k=0)
    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 0)), MASK);
    E0 = _mm_add_epi32(E0, MSG0);
    E1 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    // 轮 4-7
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 16)), MASK);
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    // 轮 8-11
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 32)), MASK);
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 12-15
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 48)), MASK);
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 16-19
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 20-23(k=1)
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 24-27
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 28-31
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 32-35
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 36-39
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 40-43(k=2)
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 44-47
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 48-51
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 52-55
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 56-59
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 60-63(k=3)
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 64-67
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 68-71
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 72-75
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    // 轮 76-79
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    // 回加上一状态
    E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);
    data += 64;
  }
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
  _mm_storeu_si128((__m128i*)state, ABCD);
  state[4] = (uint32_t)_mm_extract_epi32(E0, 3);
}

/** SHA1 初始向量 */
inline void sha1Iv(uint32_t h[5]) {
  h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE; h[3] = 0x10325476; h[4] = 0xC3D2E1F0;
}

/**
 * SHA-NI 块压缩(字域版):输入已是主机序持有的大端字(免逐块 bswap shuffle)。
 * 爆破热路径专用——尾块/填充块预转字域后,逐候选只剩纯压缩。
 * 与 sha1niBlocks 轮次一致,仅消息装载不同。
 */
__attribute__((target("sha,sse4.1")))
inline void sha1niBlocksW(uint32_t state[5], const uint32_t* w, size_t blocks) {
  // sha1niBlocks 的 MASK(16 字节全反转)把 BE 字节流变成"反字序的本机字";
  // 字数组本来就是本机字,故这里只需反字序(shuffle_epi32 0x1B),免 bswap
  __m128i ABCD = _mm_loadu_si128((const __m128i*)state);
  __m128i E0 = _mm_set_epi32((int)state[4], 0, 0, 0);
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
  while (blocks--) {
    const __m128i ABCD_SAVE = ABCD;
    const __m128i E0_SAVE = E0;
    __m128i E1, MSG0, MSG1, MSG2, MSG3;

    // 轮 0-3(k=0)
    MSG0 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)(w + 0)), 0x1B);
    E0 = _mm_add_epi32(E0, MSG0);
    E1 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    // 轮 4-7
    MSG1 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)(w + 4)), 0x1B);
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    // 轮 8-11
    MSG2 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)(w + 8)), 0x1B);
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 12-15
    MSG3 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)(w + 12)), 0x1B);
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 16-19
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 20-23(k=1)
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 24-27
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 28-31
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 32-35
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 36-39
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 40-43(k=2)
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 44-47
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 48-51
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 52-55
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 56-59
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);
    // 轮 60-63(k=3)
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);
    // 轮 64-67
    E0 = _mm_sha1nexte_epu32(E0, MSG0);
    E1 = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);
    // 轮 68-71
    E1 = _mm_sha1nexte_epu32(E1, MSG1);
    E0 = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);
    // 轮 72-75
    E0 = _mm_sha1nexte_epu32(E0, MSG2);
    E1 = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    // 轮 76-79
    E1 = _mm_sha1nexte_epu32(E1, MSG3);
    E0 = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    // 回加上一状态
    E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);
    w += 16;
  }
  ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
  _mm_storeu_si128((__m128i*)state, ABCD);
  state[4] = (uint32_t)_mm_extract_epi32(E0, 3);
}

/** 状态 → 20 字节大端摘要 */
inline void sha1StoreBe20(const uint32_t h[5], uint8_t out[20]) {
  for (int i = 0; i < 5; i++) {
    out[i * 4] = (uint8_t)(h[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
    out[i * 4 + 3] = (uint8_t)h[i];
  }
}

inline constexpr uint32_t sha1Rol(uint32_t v, int n) { return std::rotl(v, n); }

/** 单块压缩(自动调度 SHA-NI / 便携),state 原地更新 */
inline void sha1Compress(uint32_t h[5], const uint8_t* p) {
  int impl = g_forceImpl ? g_forceImpl : (hasShaNi() ? 2 : 1);
  if (impl == 2) {
    sha1niBlocks(h, p, 1);
    return;
  }
  uint32_t w[80];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
           (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
  for (int i = 16; i < 80; i++)
    w[i] = sha1Rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
    else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
    else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
    else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
    uint32_t t = sha1Rol(a, 5) + f + e + k + w[i];
    e = d; d = c; c = sha1Rol(b, 30); b = a; a = t;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

/** SHA1 流式哈希(块内自动调度 SHA-NI / 便携) */
class Sha1 {
  uint32_t h_[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  uint64_t len_ = 0;
  uint8_t buf_[64] = {0};
  size_t bufLen_ = 0;

  void block(const uint8_t* p) { sha1Compress(h_, p); }

public:
  /** 从中间状态恢复(已消化 consumed 字节且块对齐,缓冲为空) */
  void reset(const uint32_t state[5], uint64_t consumed) {
    memcpy(h_, state, 20);
    len_ = consumed;
    bufLen_ = 0;
  }

  void update(const void* data, size_t n) {
    const uint8_t* p = (const uint8_t*)data;
    len_ += n;
    if (bufLen_) {
      size_t need = 64 - bufLen_;
      size_t take = n < need ? n : need;
      memcpy(buf_ + bufLen_, p, take);
      bufLen_ += take; p += take; n -= take;
      if (bufLen_ == 64) { block(buf_); bufLen_ = 0; }
    }
    while (n >= 64) { block(p); p += 64; n -= 64; }
    if (n) { memcpy(buf_, p, n); bufLen_ = n; }
  }

  void final(uint8_t out[20]) {
    uint64_t bits = len_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (bufLen_ != 56) update(&zero, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(bits >> (56 - i * 8));
    update(lenbe, 8);
    for (int i = 0; i < 5; i++) {
      out[i * 4] = (uint8_t)(h_[i] >> 24);
      out[i * 4 + 1] = (uint8_t)(h_[i] >> 16);
      out[i * 4 + 2] = (uint8_t)(h_[i] >> 8);
      out[i * 4 + 3] = (uint8_t)h_[i];
    }
  }
};

/** key 规范化为 64 字节块(>64 先哈希,不足零填充) */
inline void hmacKeyBlock(const uint8_t* key, size_t keyLen, uint8_t k[64]) {
  memset(k, 0, 64);
  if (keyLen > 64) {
    Sha1 h;
    h.update(key, keyLen);
    h.final(k);
  } else {
    memcpy(k, key, keyLen);
  }
}

/**
 * HMAC-SHA1 增量式:key 固定,init 时压缩 ipad/opad 并预存中间状态,
 * 之后每条消息 compute 一次即可(多消息复用同一 key 时省 2 次块压缩/条)。
 */
class HmacSha1 {
  uint32_t inner_[5], outer_[5]; // 压缩过 ipad / opad 后的中间状态

public:
  void init(const uint8_t* key, size_t keyLen) {
    uint8_t k[64], pad[64];
    hmacKeyBlock(key, keyLen, k);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha1Iv(inner_);
    sha1Compress(inner_, pad);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5C;
    sha1Iv(outer_);
    sha1Compress(outer_, pad);
  }

  void compute(const uint8_t* msg, size_t msgLen, uint8_t out[20]) const {
    uint8_t inner[20];
    Sha1 h;
    h.reset(inner_, 64);
    h.update(msg, msgLen);
    h.final(inner);
    h.reset(outer_, 64);
    h.update(inner, 20);
    h.final(out);
  }
};

/** HMAC-SHA1 一次性 */
inline void hmacSha1(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen,
                     uint8_t out[20]) {
  HmacSha1 h;
  h.init(key, keyLen);
  h.compute(msg, msgLen, out);
}

/** 20 字节摘要 → 5 个大端字(GPU kernel 按值传参用) */
inline void beWords20(const uint8_t in[20], uint32_t out[5]) {
  for (int i = 0; i < 5; i++)
    out[i] = ((uint32_t)in[i * 4] << 24) | ((uint32_t)in[i * 4 + 1] << 16) |
             ((uint32_t)in[i * 4 + 2] << 8) | (uint32_t)in[i * 4 + 3];
}

/**
 * HMAC-SHA1 预计算:msg 固定、key 逐个变化(爆破热路径)。
 * init 把 msg||padding 拼成整块序列 tail(衔接在 ipad 块之后,64 的倍数);
 * compute 每个 key 仅做 2+tailBlocks 次块压缩,无流式缓冲与逐字节 padding。
 */
struct HmacFixedMsg {
  std::vector<uint8_t> tail;  // msg||0x80||0…||bitlen(64+msgLen),衔接 ipad 块后
  std::vector<uint32_t> tailw; // tail 的大端字视图(GPU kernel 直接按 16 字块压缩,免逐字节 LDG)

  void init(const uint8_t* msg, size_t msgLen) {
    uint64_t total = 64 + (uint64_t)msgLen;          // ipad 块 + msg
    uint64_t padded = (total + 9 + 63) / 64 * 64;    // +0x80 与 8 字节长度后对齐
    tail.assign((size_t)(padded - 64), 0);
    memcpy(tail.data(), msg, msgLen);
    tail[msgLen] = 0x80;
    uint64_t bits = total * 8;
    for (int i = 0; i < 8; i++)
      tail[tail.size() - 8 + i] = (uint8_t)(bits >> (56 - i * 8));
    tailw.resize(tail.size() / 4);
    for (size_t i = 0; i < tailw.size(); i++)
      tailw[i] = ((uint32_t)tail[i * 4] << 24) | ((uint32_t)tail[i * 4 + 1] << 16) |
                 ((uint32_t)tail[i * 4 + 2] << 8) | (uint32_t)tail[i * 4 + 3];
  }

  size_t tailBlocks() const { return tail.size() / 64; }

  void compute(const uint8_t* key, size_t keyLen, uint8_t out[20]) const {
    uint8_t k[64], pad[64];
    hmacKeyBlock(key, keyLen, k);
    uint32_t h[5];
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha1Iv(h);
    sha1Compress(h, pad);
    for (size_t off = 0; off < tail.size(); off += 64) sha1Compress(h, tail.data() + off);
    // 外层定长尾块:digest(20)||0x80||0…||bitlen(64+20)=672=0x2A0
    uint8_t ob[64] = {0};
    sha1StoreBe20(h, ob);
    ob[20] = 0x80;
    ob[62] = 0x02;
    ob[63] = 0xA0;
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5C;
    sha1Iv(h);
    sha1Compress(h, pad);
    sha1Compress(h, ob);
    sha1StoreBe20(h, out);
  }
};
