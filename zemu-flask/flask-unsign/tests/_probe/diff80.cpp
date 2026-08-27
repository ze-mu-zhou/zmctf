#include "sha1.h"
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <random>
#include <utility>
#define XROL(x, n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - (n)))
#define XF0(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d))
#define XF1(b, c, d) _mm256_xor_si256(_mm256_xor_si256(b, c), d)
#define XF2(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), \
                                     _mm256_and_si256(d, _mm256_or_si256(b, c)))
alignas(32) static const uint32_t IVW[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

__attribute__((target("avx2")))
static void blk_x8(__m256i h[5], __m256i w[16]) {
  const __m256i K0 = _mm256_set1_epi32((int)0x5A827999U);
  const __m256i K1 = _mm256_set1_epi32((int)0x6ED9EBA1U);
  const __m256i K2 = _mm256_set1_epi32((int)0x8F1BBCDCU);
  const __m256i K3 = _mm256_set1_epi32((int)0xCA62C1D6U);
  __m256i a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
  #define S(F, aa,bb,cc,dd,ee, KK, ww) { \
    ee=_mm256_add_epi32(ee,XROL(aa,5)); ee=_mm256_add_epi32(ee,F(bb,cc,dd)); \
    ee=_mm256_add_epi32(ee,KK); ee=_mm256_add_epi32(ee,ww); bb=XROL(bb,30); }
  S(XF0,a,b,c,d,e,K0,w[0]);  S(XF0,e,a,b,c,d,K0,w[1]);
  S(XF0,d,e,a,b,c,K0,w[2]);  S(XF0,c,d,e,a,b,K0,w[3]);
  S(XF0,b,c,d,e,a,K0,w[4]);  S(XF0,a,b,c,d,e,K0,w[5]);
  S(XF0,e,a,b,c,d,K0,w[6]);  S(XF0,d,e,a,b,c,K0,w[7]);
  S(XF0,c,d,e,a,b,K0,w[8]);  S(XF0,b,c,d,e,a,K0,w[9]);
  S(XF0,a,b,c,d,e,K0,w[10]); S(XF0,e,a,b,c,d,K0,w[11]);
  S(XF0,d,e,a,b,c,K0,w[12]); S(XF0,c,d,e,a,b,K0,w[13]);
  S(XF0,b,c,d,e,a,K0,w[14]); S(XF0,a,b,c,d,e,K0,w[15]);
  int idx = 0;

    switch(idx){
      case 0: S(XF0,a,b,c,d,e,K,w[idx]); break; case 1: S(XF0,e,a,b,c,d,K,w[idx]); break;
      case 2: S(XF0,d,e,a,b,c,K,w[idx]); break; case 3: S(XF0,c,d,e,a,b,K,w[idx]); break;
      case 4: S(XF0,b,c,d,e,a,K,w[idx]); break; case 5: S(XF0,a,b,c,d,e,K,w[idx]); break;
      case 6: S(XF0,e,a,b,c,d,K,w[idx]); break; case 7: S(XF0,d,e,a,b,c,K,w[idx]); break;
      case 8: S(XF0,c,d,e,a,b,K,w[idx]); break; case 9: S(XF0,b,c,d,e,a,K,w[idx]); break;
      case 10:S(XF0,a,b,c,d,e,K,w[idx]); break; case 11:S(XF0,e,a,b,c,d,K,w[idx]); break;
      case 12:S(XF0,d,e,a,b,c,K,w[idx]); break; case 13:S(XF0,c,d,e,a,b,K,w[idx]); break;
      case 14:S(XF0,b,c,d,e,a,K,w[idx]); break; default:S(XF0,a,b,c,d,e,K,w[idx]); break; } };
  for (int t = 16; t < ROUNDS; t++) {
    w[t&15]=XROL(_mm256_xor_si256(_mm256_xor_si256(w[(idx+13)&15],w[(idx+8)&15]),
                                  _mm256_xor_si256(w[(idx+2)&15],w[idx])),1);
    int Fsel = t<20?0:t<40?1:t<60?2:1; __m256i KK = t<20?K0:t<40?K1:t<60?K2:K3;
    rnd(Fsel,KK); idx=(idx+1)&15;
  }
  h[0]=_mm256_add_epi32(h[0],a); h[1]=_mm256_add_epi32(h[1],b); h[2]=_mm256_add_epi32(h[2],c);
  h[3]=_mm256_add_epi32(h[3],d); h[4]=_mm256_add_epi32(h[4],e);
}

// 标量旋转版:与向量版完全同构(同样的参数名轮换、同样的滚动缓冲下标)
static void blk_ref(uint32_t h[5], uint32_t w[80]) {
  // 先按标准公式展开到 w[16..79](与向量版滚动缓冲语义一致)
  constexpr int ROUNDS = 20;
  for (int t = 16; t < ROUNDS; t++)
    w[t] = std::rotl(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1);
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
  auto rol=[](uint32_t v,int n){ return (v<<n)|(v>>(32-n)); };
  for (int t = 0; t < ROUNDS; t++) {
    uint32_t f = t<20 ? (b&c)|(~b&d) : t<40||t>=60 ? b^c^d : (b&c)|(b&d)|(c&d);
    uint32_t k = t<20?0x5A827999u:t<40?0x6ED9EBA1u:t<60?0x8F1BBCDCu:0xCA62C1D6u;
    uint32_t tmp = rol(a,5)+f+e+k+w[t];
    e=d; d=c; c=rol(b,30); b=a; a=tmp;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
}
#include <bit>

int main() {
  std::mt19937 rng(9);
  alignas(32) uint32_t msg[8][16], be[8][16];
  for (int l = 0; l < 8; l++) for (int j = 0; j < 16; j++) { msg[l][j]=rng(); be[l][j]=std::byteswap(msg[l][j]); }
  alignas(32) uint32_t tmp[8]; __m256i win[16];
  for (int j = 0; j < 16; j++) { for (int i = 0; i < 8; i++) tmp[i]=be[i][j]; win[j]=_mm256_load_si256((__m256i*)tmp); }
  __m256i hv[5]; for (int j = 0; j < 5; j++) hv[j]=_mm256_set1_epi32((int)IVW[j]);
  blk_x8(hv, win);
  alignas(32) uint32_t got[5][8];
  for (int j = 0; j < 5; j++) _mm256_store_si256((__m256i*)got[j], hv[j]);
  int bad = 0;
  for (int lane = 0; lane < 8; lane++) {
    uint32_t h[5] = {IVW[0],IVW[1],IVW[2],IVW[3],IVW[4]};
    uint32_t w[80]; for (int j = 0; j < 16; j++) w[j] = be[lane][j];
    blk_ref(h, w);
    if (memcmp(h,&got[0][lane],4)||memcmp(&h[1],&got[1][lane],4)||memcmp(&h[2],&got[2][lane],4)||
        memcmp(&h[3],&got[3][lane],4)||memcmp(&h[4],&got[4][lane],4)) {
      printf("lane %d ref=%08x %08x %08x %08x %08x | vec=%08x %08x %08x %08x %08x\n",
             lane,h[0],h[1],h[2],h[3],h[4],got[0][lane],got[1][lane],got[2][lane],got[3][lane],got[4][lane]);
      bad++;
    }
  }
  printf("full-80 mismatch lanes: %d/8\n", bad);
  return bad?1:0;
}
