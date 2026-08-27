#include "sha1.h"
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <random>

#define XROL(x, n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - (n)))
#define XF0(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d))
#define XF1(b, c, d) _mm256_xor_si256(_mm256_xor_si256(b, c), d)
#define XF2(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), \
                                     _mm256_and_si256(d, _mm256_or_si256(b, c)))

__attribute__((target("avx2")))
static void sha1_block_x8(__m256i h[5], const __m256i wIn[16]) {
  const __m256i K0 = _mm256_set1_epi32((int)0x5A827999U);
  const __m256i K1 = _mm256_set1_epi32((int)0x6ED9EBA1U);
  const __m256i K2 = _mm256_set1_epi32((int)0x8F1BBCDCU);
  const __m256i K3 = _mm256_set1_epi32((int)0xCA62C1D6U);
  __m256i w[16];
  for (int j = 0; j < 16; j++) w[j] = wIn[j];
  __m256i a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  #define XSTEP(F, aa, bb, cc, dd, ee, KK, ww) { \
    ee = _mm256_add_epi32(ee, XROL(aa, 5)); \
    ee = _mm256_add_epi32(ee, F(bb, cc, dd)); \
    ee = _mm256_add_epi32(ee, KK); \
    ee = _mm256_add_epi32(ee, ww); \
    bb = XROL(bb, 30); }
  XSTEP(XF0, a, b, c, d, e, K0, w[0]);
  XSTEP(XF0, e, a, b, c, d, K0, w[1]);
  XSTEP(XF0, d, e, a, b, c, K0, w[2]);
  XSTEP(XF0, c, d, e, a, b, K0, w[3]);
  XSTEP(XF0, b, c, d, e, a, K0, w[4]);
  XSTEP(XF0, a, b, c, d, e, K0, w[5]);
  XSTEP(XF0, e, a, b, c, d, K0, w[6]);
  XSTEP(XF0, d, e, a, b, c, K0, w[7]);
  XSTEP(XF0, c, d, e, a, b, K0, w[8]);
  XSTEP(XF0, b, c, d, e, a, K0, w[9]);
  XSTEP(XF0, a, b, c, d, e, K0, w[10]);
  XSTEP(XF0, e, a, b, c, d, K0, w[11]);
  XSTEP(XF0, d, e, a, b, c, K0, w[12]);
  XSTEP(XF0, c, d, e, a, b, K0, w[13]);
  XSTEP(XF0, b, c, d, e, a, K0, w[14]);
  XSTEP(XF0, a, b, c, d, e, K0, w[15]);
  #define XROUND(idx, F, KK) { \
    __m256i nx_ = _mm256_xor_si256(_mm256_xor_si256(w[(idx + 13) & 15], w[(idx + 8) & 15]), \
                                   _mm256_xor_si256(w[(idx + 2) & 15], w[idx])); \
    w[idx] = XROL(nx_, 1); \
    switch (idx) { \
      case 0: XSTEP(F, a, b, c, d, e, KK, w[0]); break; \
      case 1: XSTEP(F, e, a, b, c, d, KK, w[1]); break; \
      case 2: XSTEP(F, d, e, a, b, c, KK, w[2]); break; \
      case 3: XSTEP(F, c, d, e, a, b, KK, w[3]); break; \
      case 4: XSTEP(F, b, c, d, e, a, KK, w[4]); break; \
      case 5: XSTEP(F, a, b, c, d, e, KK, w[5]); break; \
      case 6: XSTEP(F, e, a, b, c, d, KK, w[6]); break; \
      case 7: XSTEP(F, d, e, a, b, c, KK, w[7]); break; \
      case 8: XSTEP(F, c, d, e, a, b, KK, w[8]); break; \
      case 9: XSTEP(F, b, c, d, e, a, KK, w[9]); break; \
      case 10: XSTEP(F, a, b, c, d, e, KK, w[10]); break; \
      case 11: XSTEP(F, e, a, b, c, d, KK, w[11]); break; \
      case 12: XSTEP(F, d, e, a, b, c, KK, w[12]); break; \
      case 13: XSTEP(F, c, d, e, a, b, KK, w[13]); break; \
      case 14: XSTEP(F, b, c, d, e, a, KK, w[14]); break; \
      default: XSTEP(F, a, b, c, d, e, KK, w[15]); break; } }
  for (int t = 16; t < 20; t++) XROUND(t & 15, XF0, K0);
  for (int t = 20; t < 40; t++) XROUND(t & 15, XF1, K1);
  for (int t = 40; t < 60; t++) XROUND(t & 15, XF2, K2);
  for (int t = 60; t < 80; t++) XROUND(t & 15, XF1, K3);
  #undef XROUND
  #undef XSTEP
  h[0] = _mm256_add_epi32(h[0], a);
  h[1] = _mm256_add_epi32(h[1], b);
  h[2] = _mm256_add_epi32(h[2], c);
  h[3] = _mm256_add_epi32(h[3], d);
  h[4] = _mm256_add_epi32(h[4], e);
}

alignas(32) static const uint32_t IVW[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

int main() {
  std::mt19937 rng(777);
  alignas(32) uint32_t msg[8][16];
  for (int lane = 0; lane < 8; lane++)
    for (int j = 0; j < 16; j++) msg[lane][j] = rng();
  alignas(32) uint32_t be[8][16];
  for (int lane = 0; lane < 8; lane++)
    for (int j = 0; j < 16; j++) {
      uint32_t v = msg[lane][j];
      be[lane][j] = ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24);
    }
  __m256i h[5];
  for (int j = 0; j < 5; j++) h[j] = _mm256_set1_epi32((int)IVW[j]);
  alignas(32) uint32_t tmp[8];
  __m256i win[16];
  for (int j = 0; j < 16; j++) {
    for (int i = 0; i < 8; i++) tmp[i] = be[i][j];
    win[j] = _mm256_load_si256((const __m256i*)tmp);
  }
  sha1_block_x8(h, win);
  alignas(32) uint32_t dig[5][8];
  for (int j = 0; j < 5; j++) _mm256_store_si256((__m256i*)dig[j], h[j]);
  int bad = 0;
  for (int lane = 0; lane < 8; lane++) {
    uint32_t st[5] = {IVW[0], IVW[1], IVW[2], IVW[3], IVW[4]};
    uint8_t buf[64]; // 正确 BE 序列化
    for (int j = 0; j < 16; j++) {
      uint32_t v = be[lane][j]; // 参考消息 = 向量域实际接收的(已交换)字
      buf[j*4]   = (uint8_t)(v >> 24); buf[j*4+1] = (uint8_t)(v >> 16);
      buf[j*4+2] = (uint8_t)(v >> 8);  buf[j*4+3] = (uint8_t)v;
    }
    g_forceImpl = 1;
    sha1Compress(st, buf);
    if (st[0]!=dig[0][lane]||st[1]!=dig[1][lane]||st[2]!=dig[2][lane]||
        st[3]!=dig[3][lane]||st[4]!=dig[4][lane]) bad++;
  }
  printf("single-block mismatch lanes: %d/8\n", bad);
  return bad ? 1 : 0;
}
