/** sha2.h — SHA-256/384/512 自研实现(便携 C++26 + SHA-256 的 SHA-NI 硬件路径)。
 * 与标准实现(Python hashlib / OpenSSL EVP / FIPS 180-4 测试向量)输出完全对拍,
 * 见 tests/vectest.cpp + tests/ref.py 差分测试。
 *
 * 结构镜像 zemu-flask/src/sha1.h:
 * - hasShaNi()/g_forceImpl 运行时 cpuid 调度,SHA-NI 块函数以 target("sha,sse4.1") 编译;
 * - HMAC 三种形态:一次性 / 增量式(固定 key 预存 ipad/opad 压缩态)/ 爆破热路径。
 */
#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <span>
#include <string_view>
#include <vector>

namespace jose::sha2 {

/** CPU 是否支持 SHA-NI(cpuid,只查一次) */
inline bool hasShaNi() {
  static const bool v = __builtin_cpu_supports("sha");
  return v;
}

/** 实现强制切换:0=自动,1=便携,2=SHA-NI(selftest 对拍用) */
inline int g_forceImpl = 0;

inline std::uint32_t rotr32(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline std::uint64_t rotR64(std::uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

/* ==================== SHA-256 ==================== */

inline constexpr std::uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/** 便携 SHA-256 单块压缩 */
inline void sha256BlockPortable(std::uint32_t s[8], const std::uint8_t* p) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (std::uint32_t)p[i * 4] << 24 | (std::uint32_t)p[i * 4 + 1] << 16 |
           (std::uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
  for (int i = 16; i < 64; i++) {
    std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
  for (int i = 0; i < 64; i++) {
    std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    std::uint32_t ch = (e & f) ^ (~e & g);
    std::uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
    std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    std::uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

/** SHA-NI SHA-256 块压缩:一次处理 blocks 个 64 字节块。
 * 移植自 Crypto++ sha_simd.cpp SHA256_HashMultipleBlocks_SHANI
 * (Walton & Gulley,Intel SHA Extensions 论文代码,Boost Software License),
 * 逐指令保持一致:初始状态 shuffle 0xB1/0x1B + alignr/blend 布局、
 * 4 字节组内大端反转 mask、msg1/alignr/msg2 滚动消息调度、0x0E 半交换复用 K。 */
__attribute__((target("sha,sse4.1")))
inline void sha256niBlocks(std::uint32_t s[8], const std::uint8_t* data, std::size_t blocks) {
  __m128i STATE0, STATE1;
  __m128i MSG, TMP, MASK;
  __m128i TMSG0, TMSG1, TMSG2, TMSG3;
  __m128i ABEF_SAVE, CDGH_SAVE;

  TMP = _mm_loadu_si128((const __m128i*)(s + 0));
  STATE1 = _mm_loadu_si128((const __m128i*)(s + 4));
  MASK = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

  TMP = _mm_shuffle_epi32(TMP, 0xB1);           // CDAB
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);     // EFGH
  STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);     // ABEF
  STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);  // CDGH

  while (blocks--) {
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // 轮 0-3
    MSG = _mm_loadu_si128((const __m128i*)(data + 0));
    TMSG0 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    // 轮 4-7
    MSG = _mm_loadu_si128((const __m128i*)(data + 16));
    TMSG1 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);
    // 轮 8-11
    MSG = _mm_loadu_si128((const __m128i*)(data + 32));
    TMSG2 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);
    // 轮 12-15
    MSG = _mm_loadu_si128((const __m128i*)(data + 48));
    TMSG3 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);
    // 轮 16-19
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);
    // 轮 20-23
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);
    // 轮 24-27
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);
    // 轮 28-31
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);
    // 轮 32-35
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);
    // 轮 36-39
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);
    // 轮 40-43
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);
    // 轮 44-47
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);
    // 轮 48-51
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);
    // 轮 52-55
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    // 轮 56-59
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    // 轮 60-63
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // 加回初始状态
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
    data += 64;
  }

  TMP = _mm_shuffle_epi32(STATE0, 0x1B);        // FEBA
  STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);     // DCHG
  STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);  // DCBA
  STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);     // ABEF
  _mm_storeu_si128((__m128i*)(s + 0), STATE0);
  _mm_storeu_si128((__m128i*)(s + 4), STATE1);
}

/** 分派:SHA-256 块压缩(自动 SHA-NI / 便携) */
inline void sha256Blocks(std::uint32_t s[8], const std::uint8_t* data, std::size_t blocks) {
  if (hasShaNi() && g_forceImpl != 1)
    sha256niBlocks(s, data, blocks);
  else
    while (blocks--) sha256BlockPortable(s, data), data += 64;
}

/** 流式 SHA-256 */
struct Sha256 {
  std::uint32_t s[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::uint64_t total = 0;
  std::uint8_t buf[64];
  std::size_t buflen = 0;

  void update(const std::uint8_t* p, std::size_t n) {
    total += n;
    if (buflen) {
      std::size_t need = 64 - buflen;
      std::size_t take = n < need ? n : need;
      std::memcpy(buf + buflen, p, take);
      buflen += take;
      p += take;
      n -= take;
      if (buflen == 64) { sha256Blocks(s, buf, 1); buflen = 0; }
    }
    std::size_t blocks = n >> 6;
    if (blocks) { sha256Blocks(s, p, blocks); p += blocks << 6; n &= 63; }
    if (n) { std::memcpy(buf, p, n); buflen = n; }
  }
  void update(std::string_view v) { update((const std::uint8_t*)v.data(), v.size()); }

  void final(std::uint8_t out[32]) {
    std::uint8_t pad[128];
    std::size_t rem = (std::size_t)total & 63;
    std::size_t padlen = rem < 56 ? 56 - rem : 120 - rem;
    pad[0] = 0x80;
    std::memset(pad + 1, 0, padlen - 1);
    std::uint64_t bits = total << 3;
    for (int i = 0; i < 8; i++) pad[padlen + i] = (std::uint8_t)(bits >> (56 - i * 8));
    std::uint32_t st[8];
    std::memcpy(st, s, 32);
    std::uint8_t tmp[128];
    std::memcpy(tmp, buf, rem);
    std::memcpy(tmp + rem, pad, padlen + 8);
    std::size_t nblocks = (rem + padlen + 8) / 64;
    sha256Blocks(st, tmp, nblocks);
    for (int i = 0; i < 8; i++) {
      out[i * 4] = (std::uint8_t)(st[i] >> 24);
      out[i * 4 + 1] = (std::uint8_t)(st[i] >> 16);
      out[i * 4 + 2] = (std::uint8_t)(st[i] >> 8);
      out[i * 4 + 3] = (std::uint8_t)st[i];
    }
  }
};

inline std::vector<std::uint8_t> sha256(std::span<const std::uint8_t> data) {
  Sha256 h;
  h.update(data.data(), data.size());
  std::vector<std::uint8_t> out(32);
  h.final(out.data());
  return out;
}

/* ==================== SHA-384 / SHA-512(便携) ==================== */

inline constexpr std::uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

inline void sha512Block(std::uint64_t s[8], const std::uint8_t* p) {
  std::uint64_t w[80];
  for (int i = 0; i < 16; i++)
    w[i] = (std::uint64_t)p[i * 8] << 56 | (std::uint64_t)p[i * 8 + 1] << 48 |
           (std::uint64_t)p[i * 8 + 2] << 40 | (std::uint64_t)p[i * 8 + 3] << 32 |
           (std::uint64_t)p[i * 8 + 4] << 24 | (std::uint64_t)p[i * 8 + 5] << 16 |
           (std::uint64_t)p[i * 8 + 6] << 8 | p[i * 8 + 7];
  for (int i = 16; i < 80; i++) {
    std::uint64_t s0 = rotR64(w[i - 15], 1) ^ rotR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
    std::uint64_t s1 = rotR64(w[i - 2], 19) ^ rotR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint64_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
  for (int i = 0; i < 80; i++) {
    std::uint64_t S1 = rotR64(e, 14) ^ rotR64(e, 18) ^ rotR64(e, 41);
    std::uint64_t ch = (e & f) ^ (~e & g);
    std::uint64_t t1 = h + S1 + ch + SHA512_K[i] + w[i];
    std::uint64_t S0 = rotR64(a, 28) ^ rotR64(a, 34) ^ rotR64(a, 39);
    std::uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    std::uint64_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

/** 流式 SHA-512(SHA-384 复用,IV/截断不同) */
struct Sha512 {
  std::uint64_t s[8];
  std::uint64_t total = 0;
  std::uint8_t buf[128];
  std::size_t buflen = 0;
  std::size_t outlen;

  Sha512(bool sha384) : outlen(sha384 ? 48 : 64) {
    static const std::uint64_t IV384[8] = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
                                           0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
                                           0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
                                           0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
    static const std::uint64_t IV512[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
                                           0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                                           0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                                           0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    std::memcpy(s, sha384 ? IV384 : IV512, 64);
  }

  void update(const std::uint8_t* p, std::size_t n) {
    total += n;
    if (buflen) {
      std::size_t need = 128 - buflen;
      std::size_t take = n < need ? n : need;
      std::memcpy(buf + buflen, p, take);
      buflen += take;
      p += take;
      n -= take;
      if (buflen == 128) { sha512Block(s, buf); buflen = 0; }
    }
    std::size_t blocks = n >> 7;
    for (std::size_t i = 0; i < blocks; i++) { sha512Block(s, p); p += 128; }
    n &= 127;
    if (n) { std::memcpy(buf, p, n); buflen = n; }
  }
  void update(std::string_view v) { update((const std::uint8_t*)v.data(), v.size()); }

  void final(std::uint8_t* out) {
    std::uint8_t pad[256];
    std::size_t rem = (std::size_t)total & 127;
    std::size_t padlen = rem < 112 ? 112 - rem : 240 - rem;
    pad[0] = 0x80;
    std::memset(pad + 1, 0, padlen - 1);
    // 128 位长度字段:高 8 字节必须显式置 0(pad 未初始化)
    std::memset(pad + padlen, 0, 8);
    std::uint64_t bits = total << 3;
    for (int i = 0; i < 8; i++) pad[padlen + 8 + i] = (std::uint8_t)(bits >> (56 - i * 8));
    std::uint64_t st[8];
    std::memcpy(st, s, 64);
    std::uint8_t tmp[256];
    std::memcpy(tmp, buf, rem);
    std::memcpy(tmp + rem, pad, padlen + 16);
    std::size_t nblocks = (rem + padlen + 16) / 128;
    for (std::size_t i = 0; i < nblocks; i++) sha512Block(st, tmp + i * 128);
    for (int i = 0; i < (int)(outlen / 8); i++) {
      std::uint64_t v = st[i];
      for (int j = 0; j < 8; j++) out[i * 8 + j] = (std::uint8_t)(v >> (56 - j * 8));
    }
  }
};

/* ==================== HMAC-SHA2 ==================== */

template <int HASH>  // 256 / 384 / 512
struct HmacSha {
  static constexpr std::size_t BLOCK = HASH == 256 ? 64 : 128;
  static constexpr std::size_t DLEN = HASH == 256 ? 32 : (HASH == 384 ? 48 : 64);
  std::uint8_t ipadKey[BLOCK], opadKey[BLOCK];
  bool keyed = false;

  void init(std::span<const std::uint8_t> key) {
    std::uint8_t k[BLOCK] = {};
    if (key.size() > BLOCK) {
      if constexpr (HASH == 256) {
        auto d = sha256(key);
        std::memcpy(k, d.data(), d.size());
      } else {
        Sha512 h(HASH == 384);
        h.update(key.data(), key.size());
        h.final(k);
      }
    } else {
      std::memcpy(k, key.data(), key.size());
    }
    for (std::size_t i = 0; i < BLOCK; i++) {
      ipadKey[i] = k[i] ^ 0x36;
      opadKey[i] = k[i] ^ 0x5c;
    }
    keyed = true;
  }
  void init(std::string_view key) { init(std::span<const std::uint8_t>((const std::uint8_t*)key.data(), key.size())); }

  void digest(std::span<const std::uint8_t> msg, std::uint8_t out[DLEN]) {
    if constexpr (HASH == 256) {
      Sha256 inner;
      inner.update(ipadKey, BLOCK);
      inner.update(msg.data(), msg.size());
      std::uint8_t ih[32];
      inner.final(ih);
      Sha256 outer;
      outer.update(opadKey, BLOCK);
      outer.update(ih, 32);
      outer.final(out);
    } else {
      Sha512 inner(HASH == 384);
      inner.update(ipadKey, BLOCK);
      inner.update(msg.data(), msg.size());
      std::uint8_t ih[64];
      inner.final(ih);
      Sha512 outer(HASH == 384);
      outer.update(opadKey, BLOCK);
      outer.update(ih, HASH == 384 ? 48 : 64);
      outer.final(out);
    }
  }
};

/** 一次性 HMAC-SHA2 */
inline void hmacSha(std::string_view key, std::span<const std::uint8_t> msg, int bits, std::uint8_t* out) {
  if (bits == 256) {
    HmacSha<256> h; h.init(key); h.digest(msg, out);
  } else if (bits == 384) {
    HmacSha<384> h; h.init(key); h.digest(msg, out);
  } else {
    HmacSha<512> h; h.init(key); h.digest(msg, out);
  }
}

/** HMAC-SHA256 爆破热路径:msg 固定、key 逐个变。
 * 预先为 msg 补齐填充块,每个候选 key 只需:
 *   inner = (ipad块) + msg 块 + 内填充块
 *   outer = (opad块) + inner摘要块 + 外填充块
 */
struct HmacSha256FixedMsg {
  std::vector<std::array<std::uint8_t, 64>> msgBlocks;  // 完整填充后的消息块
  std::uint8_t innerFinalBlock[64];  // inner摘要 || 0x80 || 0... || 长度512bit

  HmacSha256FixedMsg(std::span<const std::uint8_t> msg) {
    // 内层流 = ipad块(64B) + msg,长度字段必须包含 ipad 块
    std::uint64_t bits = ((std::uint64_t)msg.size() + 64) * 8;
    std::size_t rem = msg.size() % 64;
    std::size_t padlen = rem < 56 ? 56 - rem : 120 - rem;
    std::size_t totalBytes = msg.size() + padlen + 8;
    std::size_t totalBlocks = totalBytes / 64;
    msgBlocks.resize(totalBlocks);
    std::size_t off = 0;
    while (off < msg.size()) {
      std::size_t n = msg.size() - off < 64 ? msg.size() - off : 64;
      std::memcpy(msgBlocks[off / 64].data(), msg.data() + off, n);
      off += n;
    }
    std::size_t tailOff = msg.size();
    std::size_t blockIdx = tailOff / 64, inBlock = tailOff % 64;
    msgBlocks[blockIdx][inBlock] = 0x80;
    // 长度字段(大端 8 字节)写在最后一个块的末尾
    for (int i = 0; i < 8; i++)
      msgBlocks.back()[63 - i] = (std::uint8_t)(bits >> (i * 8));
    // 外层填充块:opad块(64B) + inner摘要(32B) = 96B,长度 768bit(=0x300)
    std::uint8_t ifb[64] = {};
    ifb[32] = 0x80;
    ifb[62] = 0x03;  // 0x300 的次低字节
    std::memcpy(innerFinalBlock, ifb, 64);
  }

  /** 候选 key → 32 字节 HMAC-SHA256。 */
  void mac(const std::uint8_t* key, std::size_t keylen, std::uint8_t out[32]) const {
    std::uint8_t k[64] = {};
    if (keylen > 64) {
      auto d = sha256(std::span<const std::uint8_t>(key, keylen));
      std::memcpy(k, d.data(), 32);
    } else {
      std::memcpy(k, key, keylen);
    }
    // 合并为连续缓冲,一次调用处理全部内层块
    // msg 块数 ≤3 走栈上定长缓冲(热路径零分配),更长消息用堆缓冲
    std::uint8_t stackBuf[64 + 3 * 64];
    std::vector<std::uint8_t> dynBuf;
    std::uint8_t* innerBuf = stackBuf;
    if (msgBlocks.size() > 3) {
      dynBuf.resize(64 * (1 + msgBlocks.size()));
      innerBuf = dynBuf.data();
    }
    std::uint8_t* p = innerBuf;
    for (int i = 0; i < 64; i++) *p++ = k[i] ^ 0x36;
    for (auto& b : msgBlocks) { std::memcpy(p, b.data(), 64); p += 64; }
    std::uint32_t is[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::size_t innerBlocks = 1 + msgBlocks.size();
    sha256Blocks(is, innerBuf, innerBlocks);
    std::uint8_t inner[32];
    for (int i = 0; i < 8; i++) {
      inner[i * 4] = (std::uint8_t)(is[i] >> 24);
      inner[i * 4 + 1] = (std::uint8_t)(is[i] >> 16);
      inner[i * 4 + 2] = (std::uint8_t)(is[i] >> 8);
      inner[i * 4 + 3] = (std::uint8_t)is[i];
    }
    std::uint8_t ifb[64];
    std::memcpy(ifb, innerFinalBlock, 64);
    std::memcpy(ifb, inner, 32);
    std::uint8_t outerBuf[128];
    for (int i = 0; i < 64; i++) outerBuf[i] = k[i] ^ 0x5c;
    std::memcpy(outerBuf + 64, ifb, 64);
    std::uint32_t os[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    sha256Blocks(os, outerBuf, 2);
    for (int i = 0; i < 8; i++) {
      out[i * 4] = (std::uint8_t)(os[i] >> 24);
      out[i * 4 + 1] = (std::uint8_t)(os[i] >> 16);
      out[i * 4 + 2] = (std::uint8_t)(os[i] >> 8);
      out[i * 4 + 3] = (std::uint8_t)os[i];
    }
  }
};

}  // namespace jose::sha2
