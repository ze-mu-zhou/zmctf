#include "sha1.h"
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <random>
alignas(32) static const uint32_t IVW[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
#include <bit>
#define XROL(x, n) _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - (n)))
#define XF0(b, c, d) _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d))
#define XF1(b, c, d) _mm256_xor_si256(_mm256_xor_si256(b, c), d)

// 20 轮 AVX2 版(轮 0-19,F=ch,K=0x5A827999)
__attribute__((target("avx2")))
static void blk20_x8(__m256i h[5], const __m256i wIn[16]) {
  const __m256i K0 = _mm256_set1_epi32((int)0x5A827999U);
  __m256i w[16];
  for (int j = 0; j < 16; j++) w[j] = wIn[j];
  __m256i a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
  #define S(aa,bb,cc,dd,ee,KK,ww) { \
    ee=_mm256_add_epi32(ee,XROL(aa,5)); ee=_mm256_add_epi32(ee,XF0(bb,cc,dd)); \
    ee=_mm256_add_epi32(ee,KK); ee=_mm256_add_epi32(ee,ww); bb=XROL(bb,30); }
  S(a,b,c,d,e,K0,w[0]);  S(e,a,b,c,d,K0,w[1]);  S(d,e,a,b,c,K0,w[2]);
  S(c,d,e,a,b,K0,w[3]);  S(b,c,d,e,a,K0,w[4]);  S(a,b,c,d,e,K0,w[5]);
  S(e,a,b,c,d,K0,w[6]);  S(d,e,a,b,c,K0,w[7]);  S(c,d,e,a,b,K0,w[8]);
  S(b,c,d,e,a,K0,w[9]);  S(a,b,c,d,e,K0,w[10]); S(e,a,b,c,d,K0,w[11]);
  S(d,e,a,b,c,K0,w[12]); S(c,d,e,a,b,K0,w[13]); S(b,c,d,e,a,K0,w[14]);
  S(a,b,c,d,e,K0,w[15]);
  for (int t = 16; t < 20; t++) {
    int idx = t & 15;
    w[idx] = XROL(_mm256_xor_si256(_mm256_xor_si256(w[(idx+13)&15], w[(idx+8)&15]),
                                   _mm256_xor_si256(w[(idx+2)&15], w[idx])), 1);
    switch (idx) {
      case 0: S(a,b,c,d,e,K0,w[0]); break;  case 1: S(e,a,b,c,d,K0,w[1]); break;
      case 2: S(d,e,a,b,c,K0,w[2]); break;  case 3: S(c,d,e,a,b,K0,w[3]); break;
      case 4: S(b,c,d,e,a,K0,w[4]); break;  case 5: S(a,b,c,d,e,K0,w[5]); break;
      case 6: S(e,a,b,c,d,K0,w[6]); break;  case 7: S(d,e,a,b,c,K0,w[7]); break;
      case 8: S(c,d,e,a,b,K0,w[8]); break;  case 9: S(b,c,d,e,a,K0,w[9]); break;
      case 10:S(a,b,c,d,e,K0,w[10]); break; case 11:S(e,a,b,c,d,K0,w[11]); break;
      case 12:S(d,e,a,b,c,K0,w[12]); break; case 13:S(c,d,e,a,b,K0,w[13]); break;
      case 14:S(b,c,d,e,a,K0,w[14]); break; default:S(a,b,c,d,e,K0,w[15]); break;
    }
  }
  #undef S
  h[0]=_mm256_add_epi32(h[0],a); h[1]=_mm256_add_epi32(h[1],b); h[2]=_mm256_add_epi32(h[2],c);
  h[3]=_mm256_add_epi32(h[3],d); h[4]=_mm256_add_epi32(h[4],e);
}

static void blk20_ref(uint32_t h[5], const uint8_t* p) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
  auto rol=[](uint32_t v,int n){ return (v<<n)|(v>>(32-n)); };
  for (int t = 0; t < 20; t++) {
    uint32_t f = (b&c)|(~b&d), k = 0x5A827999u;
    uint32_t tmp = rol(a,5)+f+e+k+w[t];
    e=d; d=c; c=rol(b,30); b=a; a=tmp;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
}

int main() {
  std::mt19937 rng(555);
  alignas(32) uint32_t be[8][16]; alignas(32) uint8_t bytes[8][64];
  for (int l = 0; l < 8; l++) for (int j = 0; j < 16; j++) {
    be[l][j] = rng();
    uint32_t v = be[l][j];
    bytes[l][j*4]=(uint8_t)(v>>24); bytes[l][j*4+1]=(uint8_t)(v>>16);
    bytes[l][j*4+2]=(uint8_t)(v>>8); bytes[l][j*4+3]=(uint8_t)v;
  }
  alignas(32) uint32_t tmp[8]; __m256i win[16];
  for (int j = 0; j < 16; j++) { for (int i = 0; i < 8; i++) tmp[i]=be[i][j];
    win[j]=_mm256_load_si256((const __m256i*)tmp); }
  __m256i hv[5]; for (int j = 0; j < 5; j++) hv[j]=_mm256_set1_epi32((int)IVW[j]);
  blk20_x8(hv, win);
  alignas(32) uint32_t got[5][8];
  for (int j = 0; j < 5; j++) _mm256_store_si256((__m256i*)got[j], hv[j]);
  int bad = 0;
  for (int lane = 0; lane < 8; lane++) {
    uint32_t h[5] = {(uint32_t)IVW[0],(uint32_t)IVW[1],(uint32_t)IVW[2],(uint32_t)IVW[3],(uint32_t)IVW[4]};
    blk20_ref(h, bytes[lane]);
    if (memcmp(h,&got[0][lane],4)||memcmp(&h[1],&got[1][lane],4)||memcmp(&h[2],&got[2][lane],4)||
        memcmp(&h[3],&got[3][lane],4)||memcmp(&h[4],&got[4][lane],4)) {
      printf("lane %d ref=%08x %08x %08x %08x %08x | vec=%08x %08x %08x %08x %08x\n",
             lane,h[0],h[1],h[2],h[3],h[4],got[0][lane],got[1][lane],got[2][lane],got[3][lane],got[4][lane]);
      bad++;
    }
  }
  printf("20-round mismatch lanes: %d/8\n", bad);
  return bad?1:0;
}
