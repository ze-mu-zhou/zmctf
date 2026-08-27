#include "sha1.h"
#include <cstdio>
#include <cstring>
#include <random>
#include <bit>
alignas(32) static const uint32_t IVW[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

#define XROL(x, n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - (n)))
#define XF0(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d))
#define XF1(b, c, d) _mm256_xor_si256(_mm256_xor_si256(b, c), d)
#define XF2(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), \
                                     _mm256_and_si256(d, _mm256_or_si256(b, c)))

/** 单块压缩:8 lane 并行。h 为 5 个状态向量,wIn 为 16 字消息(已大端字域)。 */
__attribute__((target("avx2")))
static void sha1_block_x8(__m256i h[5], const __m256i wIn[16]) {
  const __m256i K0 = _mm256_set1_epi32((int)0x5A827999U);
  const __m256i K1 = _mm256_set1_epi32((int)0x6ED9EBA1U);
  const __m256i K2 = _mm256_set1_epi32((int)0x8F1BBCDCU);
  const __m256i K3 = _mm256_set1_epi32((int)0xCA62C1D6U);
  __m256i w[16];
  for (int j = 0; j < 16; j++) w[j] = wIn[j];
  __m256i a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

  // 轮 0-15:直接用消息字
  {
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
  }
  // 轮 16-79:滚动展开。w[t] = rol1(w[t-3]^w[t-8]^w[t-14]^w[t-16]),
  // 槽位下标随 t 取模 16 变化;但 STEP 五元组角色必须按「轮号 t%5」循环
  // (与前 16 轮手工展开的参数轮换序列对齐;槽位周期 16 与角色周期 5 不同!)。
  #define XROUND(tt, F, KK) { \
    const int idx = (tt) & 15; \
    __m256i nx_ = _mm256_xor_si256(_mm256_xor_si256(w[(idx + 13) & 15], w[(idx + 8) & 15]), \
                                   _mm256_xor_si256(w[(idx + 2) & 15], w[idx])); \
    w[idx] = XROL(nx_, 1); \
    switch ((tt) % 5) { \
      case 0: XSTEP(F, a, b, c, d, e, KK, w[idx]); break; \
      case 1: XSTEP(F, e, a, b, c, d, KK, w[idx]); break; \
      case 2: XSTEP(F, d, e, a, b, c, KK, w[idx]); break; \
      case 3: XSTEP(F, c, d, e, a, b, KK, w[idx]); break; \
      default: XSTEP(F, b, c, d, e, a, KK, w[idx]); break; } }
  for (int t = 16; t < 20; t++) XROUND(t, XF0, K0);
  for (int t = 20; t < 40; t++) XROUND(t, XF1, K1);
  for (int t = 40; t < 60; t++) XROUND(t, XF2, K2);
  for (int t = 60; t < 80; t++) XROUND(t, XF1, K3);
  #undef XROUND
  #undef XSTEP

  h[0] = _mm256_add_epi32(h[0], a);
  h[1] = _mm256_add_epi32(h[1], b);
  h[2] = _mm256_add_epi32(h[2], c);
  h[3] = _mm256_add_epi32(h[3], d);
  h[4] = _mm256_add_epi32(h[4], e);
}

/** AVX2 批量验证:8 lane 纵向双层 HMAC-SHA1。
 * 每候选 ~9 次块压缩全部在向量域完成;盐尾/value 尾各候选相同,广播即可。
 * 返回首个命中 lane 下标或 -1。 */
__attribute__((target("avx2")))


int main() {
  std::mt19937 rng(9);
  alignas(32) uint32_t msg[8][16], be[8][16];
  for (int l = 0; l < 8; l++) for (int j = 0; j < 16; j++) { msg[l][j]=rng(); be[l][j]=std::byteswap(msg[l][j]); }
  alignas(32) uint32_t tmp[8]; __m256i win[16];
  for (int j = 0; j < 16; j++) { for (int i = 0; i < 8; i++) tmp[i]=be[i][j]; win[j]=_mm256_load_si256((__m256i*)tmp); }
  __m256i hv[5]; for (int j = 0; j < 5; j++) hv[j]=_mm256_set1_epi32((int)IVW[j]);
  sha1_block_x8(hv, win);
  alignas(32) uint32_t got[5][8];
  for (int j = 0; j < 5; j++) _mm256_store_si256((__m256i*)got[j], hv[j]);
  int bad = 0;
  for (int lane = 0; lane < 8; lane++) {
    uint32_t h[5] = {IVW[0],IVW[1],IVW[2],IVW[3],IVW[4]};
    uint32_t w[80]; for (int j = 0; j < 16; j++) w[j] = be[lane][j];
    for (int t = 16; t < 80; t++) w[t] = std::rotl(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1);
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
    auto rol=[](uint32_t v,int n){ return (v<<n)|(v>>(32-n)); };
    for (int t = 0; t < 80; t++) {
      uint32_t f = t<20 ? (b&c)|(~b&d) : t<40||t>=60 ? b^c^d : (b&c)|(b&d)|(c&d);
      uint32_t k = t<20?0x5A827999u:t<40?0x6ED9EBA1u:t<60?0x8F1BBCDCu:0xCA62C1D6u;
      uint32_t tt = rol(a,5)+f+e+k+w[t];
      e=d; d=c; c=rol(b,30); b=a; a=tt;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
    if (memcmp(h,&got[0][lane],4)||memcmp(&h[1],&got[1][lane],4)||memcmp(&h[2],&got[2][lane],4)||
        memcmp(&h[3],&got[3][lane],4)||memcmp(&h[4],&got[4][lane],4)) bad++;
  }
  printf("full-80 mismatch lanes: %d/8\n", bad);
  return bad?1:0;
}
