/**
 * kernel_cl.h:Flask session 爆破 OpenCL kernel(内嵌为字符串,单 exe 分发)。
 * 要点:
 * - SHA1 压缩核心改编自 hashcat OpenCL/inc_hash_sha1.cl(MIT License,
 *   https://github.com/hashcat/hashcat):80 个具名标量(寄存器分配全自由)
 *   + 跨步长消息调度(rol 1/2/4,缩短关键路径)+ bitselect(NV 单条 LOP3)
 *   + 三输入加法(诱导 NV IADD3);
 * - HMAC 预计算:msg 固定,主机端先把 msg||padding 拼成整块 tail(衔接 ipad
 *   块后)并预转大端字放 __constant;每候选仅 2+tailBlocks 次块压缩,tail 压缩
 *   读 16 字(广播)而非 64 次逐字节 LDG;期望摘要按值传 5 字,比较零内存访问;
 * - key 块 / ipad / opad / 外层尾块全部按 16 字在寄存器构造(key < 64B 由调用方
 *   保证),无 k[64]/pad[64]/ob[64] 逐字节循环,不触发 local memory;
 * - 每个 work item 处理 1 个候选,拉满占用率;命中写 found(候选序号)。
 * 实测备注(勿重复尝试):SHA1 16 轮一组部分展开(~356M/s)与
 * reqd_work_group_size 限块(驱动忽略)均更差/无效,已回退。
 */
#pragma once

inline const char* FLASK_CRACK_CL = R"CL(

// —— 双后端 shim:同一份源码,OpenCL JIT 与 NVRTC(CUDA)都能编 ——
// OpenCL 的 __constant 小缓冲走常量银行;CUDA 侧退化为 const __restrict__
// 全局指针(sm_35+ 走 LDG 只读路径,广播读性能等价),word 大缓冲两侧都是全局内存。
#ifdef __CUDACC__
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long long ulong;
typedef long long i64;
#define ZK_KERNEL         extern "C" __global__
#define ZK_CPTR(T)        const T* __restrict__
#define ZK_GCPTR(T)       const T* __restrict__
#define ZK_GPTR(T)        T* __restrict__
#define ZK_GID()          (blockIdx.x * blockDim.x + threadIdx.x)
#define ZK_MULHI64(a,b)   __umul64hi(a,b)
#define ZK_BITSEL(a,b,c)  (((a) & ~(c)) | ((b) & (c)))
#else
typedef long i64;
#define ZK_KERNEL         __kernel
#define ZK_CPTR(T)        __constant const T*
#define ZK_GCPTR(T)       __global const T*
#define ZK_GPTR(T)        __global T*
#define ZK_GID()          get_global_id(0)
#define ZK_MULHI64(a,b)   mul_hi(a,b)
#define ZK_BITSEL(a,b,c)  bitselect(a,b,c)
#endif

inline uint rol32(uint v, int n) { return (v << n) | (v >> (32 - n)); }

// —— SHA1 压缩核心:改编自 hashcat 7.1.2 inc_hash_sha1.cl GPU 分支(MIT)——
// bitselect(a,b,c) = (a & ~c)|(b & c):Ch/Maj 均可折成单条 LOP3
#define SHA1_F0o(x,y,z) ZK_BITSEL((z),(y),(x))
#define SHA1_F1(x,y,z)  ((x)^(y)^(z))
#define SHA1_F2o(x,y,z) ZK_BITSEL((x),(y),((x)^(z)))
#define HC_ADD3(x,y,z)  ((x)+(y)+(z))
#define SHA1_STEP_S(f,a,b,c,d,e,x) \
  { e += K; e = HC_ADD3(e, x, f(b,c,d)); e += rol32(a,5); b = rol32(b,30); }

/** 全展开 SHA1 块压缩(16 字大端消息;改编自 hashcat,见头注) */
inline void sha1_block_w(uint* h, const uint w[16]) {
  uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

  uint w00_t = w[0];
  uint w01_t = w[1];
  uint w02_t = w[2];
  uint w03_t = w[3];
  uint w04_t = w[4];
  uint w05_t = w[5];
  uint w06_t = w[6];
  uint w07_t = w[7];
  uint w08_t = w[8];
  uint w09_t = w[9];
  uint w0a_t = w[10];
  uint w0b_t = w[11];
  uint w0c_t = w[12];
  uint w0d_t = w[13];
  uint w0e_t = w[14];
  uint w0f_t = w[15];
  uint w10_t;
  uint w11_t;
  uint w12_t;
  uint w13_t;
  uint w14_t;
  uint w15_t;
  uint w16_t;
  uint w17_t;
  uint w18_t;
  uint w19_t;
  uint w1a_t;
  uint w1b_t;
  uint w1c_t;
  uint w1d_t;
  uint w1e_t;
  uint w1f_t;
  uint w20_t;
  uint w21_t;
  uint w22_t;
  uint w23_t;
  uint w24_t;
  uint w25_t;
  uint w26_t;
  uint w27_t;
  uint w28_t;
  uint w29_t;
  uint w2a_t;
  uint w2b_t;
  uint w2c_t;
  uint w2d_t;
  uint w2e_t;
  uint w2f_t;
  uint w30_t;
  uint w31_t;
  uint w32_t;
  uint w33_t;
  uint w34_t;
  uint w35_t;
  uint w36_t;
  uint w37_t;
  uint w38_t;
  uint w39_t;
  uint w3a_t;
  uint w3b_t;
  uint w3c_t;
  uint w3d_t;
  uint w3e_t;
  uint w3f_t;
  uint w40_t;
  uint w41_t;
  uint w42_t;
  uint w43_t;
  uint w44_t;
  uint w45_t;
  uint w46_t;
  uint w47_t;
  uint w48_t;
  uint w49_t;
  uint w4a_t;
  uint w4b_t;
  uint w4c_t;
  uint w4d_t;
  uint w4e_t;
  uint w4f_t;

  #define K 0x5A827999U

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w00_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w01_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w02_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w03_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w04_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w05_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w06_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w07_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w08_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w09_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0a_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0b_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w0c_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w0d_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w0e_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0f_t);
  w10_t = rol32 ((w0d_t ^ w08_t ^ w02_t ^ w00_t), 1u); SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w10_t);
  w11_t = rol32 ((w0e_t ^ w09_t ^ w03_t ^ w01_t), 1u); SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w11_t);
  w12_t = rol32 ((w0f_t ^ w0a_t ^ w04_t ^ w02_t), 1u); SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w12_t);
  w13_t = rol32 ((w10_t ^ w0b_t ^ w05_t ^ w03_t), 1u); SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w13_t);

  #undef K
  #define K 0x6ED9EBA1U

  w14_t = rol32 ((w11_t ^ w0c_t ^ w06_t ^ w04_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w14_t);
  w15_t = rol32 ((w12_t ^ w0d_t ^ w07_t ^ w05_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w15_t);
  w16_t = rol32 ((w13_t ^ w0e_t ^ w08_t ^ w06_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w16_t);
  w17_t = rol32 ((w14_t ^ w0f_t ^ w09_t ^ w07_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w17_t);
  w18_t = rol32 ((w15_t ^ w10_t ^ w0a_t ^ w08_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w18_t);
  w19_t = rol32 ((w16_t ^ w11_t ^ w0b_t ^ w09_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w19_t);
  w1a_t = rol32 ((w17_t ^ w12_t ^ w0c_t ^ w0a_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w1a_t);
  w1b_t = rol32 ((w18_t ^ w13_t ^ w0d_t ^ w0b_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w1b_t);
  w1c_t = rol32 ((w19_t ^ w14_t ^ w0e_t ^ w0c_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1c_t);
  w1d_t = rol32 ((w1a_t ^ w15_t ^ w0f_t ^ w0d_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w1d_t);
  w1e_t = rol32 ((w1b_t ^ w16_t ^ w10_t ^ w0e_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1e_t);
  w1f_t = rol32 ((w1c_t ^ w17_t ^ w11_t ^ w0f_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w1f_t);
  w20_t = rol32 ((w1a_t ^ w10_t ^ w04_t ^ w00_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w20_t);
  w21_t = rol32 ((w1b_t ^ w11_t ^ w05_t ^ w01_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w21_t);
  w22_t = rol32 ((w1c_t ^ w12_t ^ w06_t ^ w02_t), 2u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w22_t);
  w23_t = rol32 ((w1d_t ^ w13_t ^ w07_t ^ w03_t), 2u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w23_t);
  w24_t = rol32 ((w1e_t ^ w14_t ^ w08_t ^ w04_t), 2u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w24_t);
  w25_t = rol32 ((w1f_t ^ w15_t ^ w09_t ^ w05_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w25_t);
  w26_t = rol32 ((w20_t ^ w16_t ^ w0a_t ^ w06_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w26_t);
  w27_t = rol32 ((w21_t ^ w17_t ^ w0b_t ^ w07_t), 2u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w27_t);

  #undef K
  #define K 0x8F1BBCDCU

  w28_t = rol32 ((w22_t ^ w18_t ^ w0c_t ^ w08_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w28_t);
  w29_t = rol32 ((w23_t ^ w19_t ^ w0d_t ^ w09_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w29_t);
  w2a_t = rol32 ((w24_t ^ w1a_t ^ w0e_t ^ w0a_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w2a_t);
  w2b_t = rol32 ((w25_t ^ w1b_t ^ w0f_t ^ w0b_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w2b_t);
  w2c_t = rol32 ((w26_t ^ w1c_t ^ w10_t ^ w0c_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w2c_t);
  w2d_t = rol32 ((w27_t ^ w1d_t ^ w11_t ^ w0d_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2d_t);
  w2e_t = rol32 ((w28_t ^ w1e_t ^ w12_t ^ w0e_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w2e_t);
  w2f_t = rol32 ((w29_t ^ w1f_t ^ w13_t ^ w0f_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w2f_t);
  w30_t = rol32 ((w2a_t ^ w20_t ^ w14_t ^ w10_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w30_t);
  w31_t = rol32 ((w2b_t ^ w21_t ^ w15_t ^ w11_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w31_t);
  w32_t = rol32 ((w2c_t ^ w22_t ^ w16_t ^ w12_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w32_t);
  w33_t = rol32 ((w2d_t ^ w23_t ^ w17_t ^ w13_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w33_t);
  w34_t = rol32 ((w2e_t ^ w24_t ^ w18_t ^ w14_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w34_t);
  w35_t = rol32 ((w2f_t ^ w25_t ^ w19_t ^ w15_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w35_t);
  w36_t = rol32 ((w30_t ^ w26_t ^ w1a_t ^ w16_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w36_t);
  w37_t = rol32 ((w31_t ^ w27_t ^ w1b_t ^ w17_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w37_t);
  w38_t = rol32 ((w32_t ^ w28_t ^ w1c_t ^ w18_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w38_t);
  w39_t = rol32 ((w33_t ^ w29_t ^ w1d_t ^ w19_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w39_t);
  w3a_t = rol32 ((w34_t ^ w2a_t ^ w1e_t ^ w1a_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w3a_t);
  w3b_t = rol32 ((w35_t ^ w2b_t ^ w1f_t ^ w1b_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w3b_t);

  #undef K
  #define K 0xCA62C1D6U

  w3c_t = rol32 ((w36_t ^ w2c_t ^ w20_t ^ w1c_t), 2u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3c_t);
  w3d_t = rol32 ((w37_t ^ w2d_t ^ w21_t ^ w1d_t), 2u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w3d_t);
  w3e_t = rol32 ((w38_t ^ w2e_t ^ w22_t ^ w1e_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3e_t);
  w3f_t = rol32 ((w39_t ^ w2f_t ^ w23_t ^ w1f_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w3f_t);
  w40_t = rol32 ((w34_t ^ w20_t ^ w08_t ^ w00_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w40_t);
  w41_t = rol32 ((w35_t ^ w21_t ^ w09_t ^ w01_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w41_t);
  w42_t = rol32 ((w36_t ^ w22_t ^ w0a_t ^ w02_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w42_t);
  w43_t = rol32 ((w37_t ^ w23_t ^ w0b_t ^ w03_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w43_t);
  w44_t = rol32 ((w38_t ^ w24_t ^ w0c_t ^ w04_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w44_t);
  w45_t = rol32 ((w39_t ^ w25_t ^ w0d_t ^ w05_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w45_t);
  w46_t = rol32 ((w3a_t ^ w26_t ^ w0e_t ^ w06_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w46_t);
  w47_t = rol32 ((w3b_t ^ w27_t ^ w0f_t ^ w07_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w47_t);
  w48_t = rol32 ((w3c_t ^ w28_t ^ w10_t ^ w08_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w48_t);
  w49_t = rol32 ((w3d_t ^ w29_t ^ w11_t ^ w09_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w49_t);
  w4a_t = rol32 ((w3e_t ^ w2a_t ^ w12_t ^ w0a_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w4a_t);
  w4b_t = rol32 ((w3f_t ^ w2b_t ^ w13_t ^ w0b_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4b_t);
  w4c_t = rol32 ((w40_t ^ w2c_t ^ w14_t ^ w0c_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4c_t);
  w4d_t = rol32 ((w41_t ^ w2d_t ^ w15_t ^ w0d_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w4d_t);
  w4e_t = rol32 ((w42_t ^ w2e_t ^ w16_t ^ w0e_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4e_t);
  w4f_t = rol32 ((w43_t ^ w2f_t ^ w17_t ^ w0f_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w4f_t);

  #undef K
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

/** 全展开 SHA1 块压缩(主机端预转大端字的 __constant 字源,先取 16 字进寄存器) */
inline void sha1_block_c(uint* h, ZK_CPTR(uint) p) {
  uint w[16];
  for (int i = 0; i < 16; i++) w[i] = p[i];
  sha1_block_w(h, w);
}

inline void sha1_iv(uint* h) {
  h[0] = 0x67452301U; h[1] = 0xEFCDAB89U; h[2] = 0x98BADCFEU;
  h[3] = 0x10325476U; h[4] = 0xC3D2E1F0U;
}

/**
 * HMAC-SHA1 预计算路径(字节 key,klen < 64 由调用方保证)。
 * ipad/opad 错峰构造:复用同一 w[16],靠 WAR 依赖强制排序,压低寄存器峰值——
 * 此前 iw/ow 双拼版 wgs=256(占用率过低),实测比逐字节版更慢,故改为顺序构造。
 */
inline void hmac_pre_b(const uchar* key, uint klen,
                       ZK_CPTR(uint) tail, uint tailBlocks, uint out[5]) {
  uint w[16];
  for (int i = 0; i < 16; i++) {
    uint kb = 0, bi = (uint)i * 4;
    if (bi < klen) {
      kb = (uint)key[bi] << 24;
      if (bi + 1 < klen) kb |= (uint)key[bi + 1] << 16;
      if (bi + 2 < klen) kb |= (uint)key[bi + 2] << 8;
      if (bi + 3 < klen) kb |= (uint)key[bi + 3];
    }
    w[i] = kb ^ 0x36363636U;
  }
  uint h[5];
  sha1_iv(h);
  sha1_block_w(h, w);
  for (uint b = 0; b < tailBlocks; b++) sha1_block_c(h, tail + b * 16);
  uint hi0 = h[0], hi1 = h[1], hi2 = h[2], hi3 = h[3], hi4 = h[4];
  for (int i = 0; i < 16; i++) {
    uint kb = 0, bi = (uint)i * 4;
    if (bi < klen) {
      kb = (uint)key[bi] << 24;
      if (bi + 1 < klen) kb |= (uint)key[bi + 1] << 16;
      if (bi + 2 < klen) kb |= (uint)key[bi + 2] << 8;
      if (bi + 3 < klen) kb |= (uint)key[bi + 3];
    }
    w[i] = kb ^ 0x5C5C5C5CU;
  }
  sha1_iv(h);
  sha1_block_w(h, w);
  uint ew[16];
  ew[0] = hi0; ew[1] = hi1; ew[2] = hi2; ew[3] = hi3; ew[4] = hi4;
  ew[5] = 0x80000000U;
  for (int i = 6; i < 15; i++) ew[i] = 0;
  ew[15] = 0x000002A0U;
  sha1_block_w(h, ew);
  out[0] = h[0]; out[1] = h[1]; out[2] = h[2]; out[3] = h[3]; out[4] = h[4];
}

/** HMAC-SHA1 预计算路径(20 字节字 key,即上一级派生出的 dk),同样错峰构造 */
inline void hmac_pre_w(const uint dk[5],
                       ZK_CPTR(uint) tail, uint tailBlocks, uint out[5]) {
  uint w[16];
  for (int i = 0; i < 16; i++) w[i] = (i < 5 ? dk[i] : 0U) ^ 0x36363636U;
  uint h[5];
  sha1_iv(h);
  sha1_block_w(h, w);
  for (uint b = 0; b < tailBlocks; b++) sha1_block_c(h, tail + b * 16);
  uint hi0 = h[0], hi1 = h[1], hi2 = h[2], hi3 = h[3], hi4 = h[4];
  for (int i = 0; i < 16; i++) w[i] = (i < 5 ? dk[i] : 0U) ^ 0x5C5C5C5CU;
  sha1_iv(h);
  sha1_block_w(h, w);
  uint ew[16];
  ew[0] = hi0; ew[1] = hi1; ew[2] = hi2; ew[3] = hi3; ew[4] = hi4;
  ew[5] = 0x80000000U;
  for (int i = 6; i < 15; i++) ew[i] = 0;
  ew[15] = 0x000002A0U;
  sha1_block_w(h, ew);
  out[0] = h[0]; out[1] = h[1]; out[2] = h[2]; out[3] = h[3]; out[4] = h[4];
}

/** 5 字摘要 vs 期望(主机端预转大端字,按值传参,零内存访问) */
inline bool eq20w(const uint* h, uint e0, uint e1, uint e2, uint e3, uint e4) {
  return ((h[0] ^ e0) | (h[1] ^ e1) | (h[2] ^ e2) | (h[3] ^ e3) | (h[4] ^ e4)) == 0;
}

ZK_KERNEL void crack_mask(
    ZK_CPTR(uint) salt_tail, const uint salt_blocks,
    ZK_CPTR(uint) value_tail, const uint value_blocks,
    const uint e0, const uint e1, const uint e2, const uint e3, const uint e4,
    ZK_CPTR(uchar) csbuf,
    ZK_CPTR(uint) csoff,
    ZK_CPTR(uint) cslen,
    ZK_CPTR(ulong) csmag,
    ZK_CPTR(uint) csflg,
    const uint npos,
    const ulong base,
    const ulong total,
    ZK_GPTR(i64) found)
{
  if (*found >= 0) return;
  ulong idx = base + (ulong)ZK_GID();
  if (idx >= total) return;
  // 注:以下结构实验在本 kernel 上实测均为负收益/无效,勿重复尝试——
  // 末位内层循环(spill,慢 8x)、双候选 ILP(private 64B,~503M/s 略负)、
  // SHA1 16 轮部分展开(~356M/s)、reqd_work_group_size(驱动忽略,wgs 恒 256)。
  // 候选展开:libdivide 式魔数乘(mul_hi ~5 指令)替代 u64 除法链(~30+/位)。
  // csflg:bit0-5 shift,bit6 add 修正,bit7 2 的幂纯移位;魔数主机端预计算。
  uchar cand[32];
  ulong x = idx;
  for (int k = (int)npos - 1; k >= 0; k--) {
    uint f = csflg[k];
    ulong q;
    if (f & 128) {
      q = x >> (f & 63);
    } else {
      q = ZK_MULHI64(x, csmag[k]);
      if (f & 64) q = ((x - q) >> 1) + q;
      q >>= (f & 63);
    }
    cand[k] = csbuf[csoff[k] + (uint)(x - q * cslen[k])];
    x = q;
  }
  uint dkw[5], macw[5];
  hmac_pre_b(cand, npos, salt_tail, salt_blocks, dkw);
  hmac_pre_w(dkw, value_tail, value_blocks, macw);
  if (eq20w(macw, e0, e1, e2, e3, e4)) *found = (i64)idx;
}

ZK_KERNEL void crack_dict(
    ZK_CPTR(uint) salt_tail, const uint salt_blocks,
    ZK_CPTR(uint) value_tail, const uint value_blocks,
    const uint e0, const uint e1, const uint e2, const uint e3, const uint e4,
    ZK_GCPTR(uchar) words, const uint stride,
    const ulong base,
    const ulong total,
    ZK_GPTR(i64) found)
{
  if (*found >= 0) return;
  ulong idx = base + (ulong)ZK_GID();
  if (idx >= total) return;
  ZK_GCPTR(uchar) w = words + idx * (ulong)stride;
  uchar cand[32];
  uint len = 0;
  while (len < stride && w[len]) { cand[len] = w[len]; len++; }
  uint dkw[5], macw[5];
  hmac_pre_b(cand, len, salt_tail, salt_blocks, dkw);
  hmac_pre_w(dkw, value_tail, value_blocks, macw);
  if (eq20w(macw, e0, e1, e2, e3, e4)) *found = (i64)idx;
}

ZK_KERNEL void probe_ok(ZK_GPTR(i64) found) {
  *found = 12345;
}

)CL";
