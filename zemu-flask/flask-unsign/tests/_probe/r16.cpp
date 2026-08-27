#include "sha1.h"
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <random>
#include <utility>
#define XROL(x, n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - (n)))
#define XF0(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d))
alignas(32) static const uint32_t IVW[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

// 仅前 16 轮的 AVX2 版本(与被测代码相同的 STEP 宏)
__attribute__((target("avx2")))
static void r16_avx(__m256i st[5], const __m256i wIn[16]) {
  __m256i a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
  #define S(F, aa, bb, cc, dd, ee, KK, ww) { \
    ee = _mm256_add_epi32(ee, XROL(aa, 5)); \
    ee = _mm256_add_epi32(ee, F(bb, cc, dd)); \
    ee = _mm256_add_epi32(ee, KK); \
    ee = _mm256_add_epi32(ee, ww); \
    bb = XROL(bb, 30); }
  S(XF0,a,b,c,d,e,_mm256_set1_epi32((int)0x5A827999U),wIn[0]);
  S(XF0,e,a,b,c,d,_mm256_set1_epi32((int)0x5A827999U),wIn[1]);
  S(XF0,d,e,a,b,c,_mm256_set1_epi32((int)0x5A827999U),wIn[2]);
  S(XF0,c,d,e,a,b,_mm256_set1_epi32((int)0x5A827999U),wIn[3]);
  S(XF0,b,c,d,e,a,_mm256_set1_epi32((int)0x5A827999U),wIn[4]);
  S(XF0,a,b,c,d,e,_mm256_set1_epi32((int)0x5A827999U),wIn[5]);
  S(XF0,e,a,b,c,d,_mm256_set1_epi32((int)0x5A827999U),wIn[6]);
  S(XF0,d,e,a,b,c,_mm256_set1_epi32((int)0x5A827999U),wIn[7]);
  S(XF0,c,d,e,a,b,_mm256_set1_epi32((int)0x5A827999U),wIn[8]);
  S(XF0,b,c,d,e,a,_mm256_set1_epi32((int)0x5A827999U),wIn[9]);
  S(XF0,a,b,c,d,e,_mm256_set1_epi32((int)0x5A827999U),wIn[10]);
  S(XF0,e,a,b,c,d,_mm256_set1_epi32((int)0x5A827999U),wIn[11]);
  S(XF0,d,e,a,b,c,_mm256_set1_epi32((int)0x5A827999U),wIn[12]);
  S(XF0,c,d,e,a,b,_mm256_set1_epi32((int)0x5A827999U),wIn[13]);
  S(XF0,b,c,d,e,a,_mm256_set1_epi32((int)0x5A827999U),wIn[14]);
  S(XF0,a,b,c,d,e,_mm256_set1_epi32((int)0x5A827999U),wIn[15]);
  st[0]=a; st[1]=b; st[2]=c; st[3]=d; st[4]=e;
}

// 标量参考:同样只做 16 步(不回加,输出轮末状态)
static void r16_ref(uint32_t h[5], const uint8_t* p) {
  uint32_t w[16];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
  auto rol=[](uint32_t v,int n){ return (v<<n)|(v>>(32-n)); };
  for (int i = 0; i < 16; i++) {
    uint32_t f = (b&c)|(~b&d);
    uint32_t t = rol(a,5)+f+e+0x5A827999u+w[i];
    e=d; d=c; c=rol(b,30); b=a; a=t;
  }
  h[0]=a; h[1]=b; h[2]=c; h[3]=d; h[4]=e;
}

int main() {
  std::mt19937 rng(42);
  alignas(32) uint32_t msg[8][16];
  for (int lane = 0; lane < 8; lane++) for (int j = 0; j < 16; j++) msg[lane][j] = rng();
  // 统一用 BE 字域:标量参考直接按 BE 解析 buf
  alignas(32) uint8_t buf[8][64];
  for (int lane = 0; lane < 8; lane++)
    for (int j = 0; j < 16; j++) {
      uint32_t v = msg[lane][j];
      buf[lane][j*4]=(uint8_t)(v>>24); buf[lane][j*4+1]=(uint8_t)(v>>16);
      buf[lane][j*4+2]=(uint8_t)(v>>8); buf[lane][j*4+3]=(uint8_t)v;
    }
  alignas(32) uint32_t tmp[8];
  __m256i win[16];
  for (int j = 0; j < 16; j++) {
    for (int i = 0; i < 8; i++) tmp[i] = msg[i][j]; // 向量域直接用原始字(BE 字节流的解析结果一致)
    win[j] = _mm256_load_si256((const __m256i*)tmp);
  }
  __m256i st[5];
  for (int j = 0; j < 5; j++) st[j] = _mm256_set1_epi32((int)IVW[j]);
  r16_avx(st, win);
  alignas(32) uint32_t got[5][8];
  for (int j = 0; j < 5; j++) _mm256_store_si256((__m256i*)got[j], st[j]);
  int bad = 0;
  for (int lane = 0; lane < 8; lane++) {
    uint32_t h[5] = {IVW[0],IVW[1],IVW[2],IVW[3],IVW[4]};
    r16_ref(h, buf[lane]);
    bool ok = !memcmp(h, &got[0][lane], 4) && !memcmp(&h[1], &got[1][lane], 4) &&
              !memcmp(&h[2], &got[2][lane], 4) && !memcmp(&h[3], &got[3][lane], 4) &&
              !memcmp(&h[4], &got[4][lane], 4);
    printf("lane %d: %08x %08x %08x %08x %08x  %s\n", lane, got[0][lane], got[1][lane], got[2][lane], got[3][lane], got[4][lane], ok?"OK":"MISMATCH");
    if (!ok) bad++;
  }
  return bad?1:0;
}
