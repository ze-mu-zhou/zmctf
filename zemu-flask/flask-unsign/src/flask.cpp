#include "flask.h"

#include "b64.h"
#include "crack_cpu.h"
#include "gpu/nvrtc.h"
#include "gpu/ocl.h"
#include "json_mini.h"
#include "sha1.h"

#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <thread>
#include <zlib.h>

static const char* DEFAULT_SALT = "cookie-session";

/** 派生签名密钥:HMAC-SHA1(key=secret, msg=salt) */
static void deriveKey(const std::string& secret, const std::string& salt, uint8_t out[20]) {
  hmacSha1((const uint8_t*)secret.data(), secret.size(),
           (const uint8_t*)salt.data(), salt.size(), out);
}

struct CookieParts {
  std::string payload, ts, sig;
};

/** cookie 结构切分:payload.ts.sig('.' 不在 b64url 字母表内,必为 3 段) */
static std::optional<CookieParts> splitCookie(const std::string& cookie) {
  size_t p1 = cookie.find('.');
  size_t p2 = cookie.rfind('.');
  if (p1 == std::string::npos || p1 == p2) return std::nullopt;
  CookieParts c{ cookie.substr(0, p1), cookie.substr(p1 + 1, p2 - p1 - 1), cookie.substr(p2 + 1) };
  if (c.payload.empty() || c.ts.empty() || c.sig.empty()) return std::nullopt;
  return c;
}

/* ================= decode / verify / sign ================= */

int flaskDecode(const std::string& cookie) {
  std::string payload = cookie;
  bool compressed = false;
  if (!payload.empty() && payload[0] == '.') {
    compressed = true;
    payload = payload.substr(1);
  }
  size_t dot = payload.find('.');
  std::string data = payload.substr(0, dot);
  std::vector<uint8_t> raw;
  if (!b64urlDecode(data, raw)) {
    std::cerr << "[!] base64 解码失败,确定是 Flask session cookie?" << std::endl;
    return 1;
  }
  if (compressed) {
    // 解压后尺寸未知:1MB 起步,Z_BUF_ERROR 则翻倍重试,上限 256MB
    uLongf cap = 1 << 20, outLen = 0;
    std::vector<uint8_t> out;
    int zr = Z_BUF_ERROR;
    while (zr == Z_BUF_ERROR && cap <= (1u << 28)) {
      out.resize(cap);
      outLen = cap;
      zr = uncompress(out.data(), &outLen, raw.data(), (uLong)raw.size());
      cap *= 2;
    }
    if (zr != Z_OK) {
      std::cerr << "[!] zlib 解压失败"
                << (zr == Z_BUF_ERROR ? "(解压后超过 256MB 上限)" : "") << std::endl;
      return 1;
    }
    raw.assign(out.begin(), out.begin() + outLen);
  }
  std::cout.write((const char*)raw.data(), (std::streamsize)raw.size());
  std::cout << std::endl;
  return 0;
}

int flaskVerify(const std::string& cookie, const std::string& secret, const std::string& saltIn) {
  std::string salt = saltIn.empty() ? DEFAULT_SALT : saltIn;
  auto parts = splitCookie(cookie);
  if (!parts) {
    std::cerr << "[!] cookie 结构不合法(应为 payload.ts.sig 三段)" << std::endl;
    return 1;
  }
  auto& [payload, ts, sig] = *parts;
  std::vector<uint8_t> expect;
  if (!b64urlDecode(sig, expect) || expect.size() != 20) {
    std::cerr << "[!] 签名段不是合法的 20 字节 HMAC-SHA1" << std::endl;
    return 1;
  }
  std::string value = payload + "." + ts;
  uint8_t key[20], mac[20];
  deriveKey(secret, salt, key);
  hmacSha1(key, 20, (const uint8_t*)value.data(), value.size(), mac);
  uint8_t diff = 0;
  for (int i = 0; i < 20; i++) diff |= mac[i] ^ expect[i];
  if (diff == 0) {
    std::cout << "valid" << std::endl;
    return 0;
  }
  std::cout << "invalid" << std::endl;
  return 1;
}

int flaskSign(const std::string& secret, const std::string& jsonText, const std::string& saltIn,
              bool legacy) {
  std::string salt = saltIn.empty() ? DEFAULT_SALT : saltIn;
  Json j;
  JsonParser parser(jsonText);
  if (!parser.parse(j)) {
    std::cerr << "[!] JSON 解析失败" << std::endl;
    return 1;
  }
  parser.ws();
  if (*parser.p) {
    std::cerr << "[!] JSON 末尾有多余内容" << std::endl;
    return 1;
  }
  std::string canonical;
  if (!jsonCanonical(j, canonical)) {
    std::cerr << "[!] JSON 含非法 UTF-8 字节序列" << std::endl;
    return 1;
  }
  std::string payload = b64urlEncode((const uint8_t*)canonical.data(), canonical.size());
  // legacy:itsdangerous <1.0 的 EPOCH = 1293840000(2011-01-01 UTC)
  int64_t ts = (int64_t)time(nullptr) - (legacy ? 1293840000 : 0);
  uint8_t tsBytes[8];
  for (int i = 0; i < 8; i++) tsBytes[i] = (uint8_t)((uint64_t)ts >> (56 - i * 8));
  int lead = 0;
  while (lead < 7 && tsBytes[lead] == 0) lead++;
  std::string tsB64 = b64urlEncode(tsBytes + lead, 8 - lead);
  std::string value = payload + "." + tsB64;
  uint8_t key[20], mac[20];
  deriveKey(secret, salt, key);
  hmacSha1(key, 20, (const uint8_t*)value.data(), value.size(), mac);
  std::cout << value + "." + b64urlEncode(mac, 20) << std::endl;
  return 0;
}

/* ================= crack ================= */

/** 验签闭包参数(CPU 回调与 GPU 参数共用) */
struct VerifyCtx {
  std::string value;   // payload.ts
  std::vector<uint8_t> expect;
  uint32_t expectW[5] = {0}; // 期望摘要的大端字视图(字域验证用)
  std::string salt;
  HmacFixedMsg saltPc;  // 派生:HMAC(key=cand, msg=salt) 预计算尾块
  HmacFixedMsg valuePc; // 验签:HMAC(key=dk, msg=value) 预计算尾块
};

static bool verifyCb(const uint8_t* key, size_t klen, void* v) {
  auto* c = (VerifyCtx*)v;
  uint8_t dk[20], mac[20];
  c->saltPc.compute(key, klen, dk);
  c->valuePc.compute(dk, 20, mac);
  uint8_t diff = 0;
  for (int i = 0; i < 20; i++) diff |= mac[i] ^ c->expect[i];
  return diff == 0;
}

/** key 的第 i 个大端字(不足 4 字节的尾部按零填充) */
static uint32_t beWordPart(const uint8_t* p, size_t n) {
  uint32_t w = 0;
  for (size_t i = 0; i < n; i++) w = (w << 8) | p[i];
  return w << (8 * (4 - n));
}

/**
 * 爆破热路径字域验证:除候选 key 外的一切(尾块/填充/期望摘要)都预转成
 * 主机序持有的大端字,逐候选只剩 8 次 SHA-NI 纯压缩,免 verifyCb 里
 * 逐候选的 64B memset/xor 循环/字节域↔字域转换/ob 块重建。
 * 语义与 verifyCb 完全一致(HMAC(secret,salt)→dk → HMAC(dk,value))。
 */
__attribute__((target("sha,sse4.1")))
static bool verifyFast(const uint8_t* key, size_t klen, void* v) {
  auto* c = (VerifyCtx*)v;
  uint32_t kw[16] = {0};
  if (klen > 64) { // HMAC 规范:超长 key 先 SHA1 折叠
    uint8_t kb[20];
    Sha1 h;
    h.update(key, klen);
    h.final(kb);
    for (int i = 0; i < 5; i++) kw[i] = beWordPart(kb + i * 4, 4);
  } else {
    int nw = (int)((klen + 3) >> 2);
    for (int i = 0; i < nw; i++) {
      size_t off = (size_t)i * 4;
      kw[i] = beWordPart(key + off, klen - off < 4 ? klen - off : 4);
    }
  }
  constexpr uint32_t X36 = 0x36363636, X5C = 0x5C5C5C5C;
  uint32_t w[16], st[5];
  // ---- HMAC(key, salt) → dk ----
  for (int i = 0; i < 16; i++) w[i] = kw[i] ^ X36;
  sha1Iv(st);
  sha1niBlocksW(st, w, 1);
  sha1niBlocksW(st, c->saltPc.tailw.data(), c->saltPc.tailw.size() / 16);
  uint32_t inner1[5] = {st[0], st[1], st[2], st[3], st[4]};
  for (int i = 0; i < 16; i++) w[i] = kw[i] ^ X5C;
  sha1Iv(st);
  sha1niBlocksW(st, w, 1);
  // 外层尾块:digest(20B)||0x80||0…||(64+20)*8 = 0x2A0
  for (int i = 0; i < 5; i++) w[i] = inner1[i];
  w[5] = 0x80000000;
  for (int i = 6; i < 15; i++) w[i] = 0;
  w[15] = 0x2A0;
  sha1niBlocksW(st, w, 1);
  uint32_t dk[5] = {st[0], st[1], st[2], st[3], st[4]};
  // ---- HMAC(dk, value) → mac ----
  for (int i = 0; i < 5; i++) w[i] = dk[i] ^ X36;
  for (int i = 5; i < 16; i++) w[i] = X36; // dk 为 20B,零填充区 ^0x36
  sha1Iv(st);
  sha1niBlocksW(st, w, 1);
  sha1niBlocksW(st, c->valuePc.tailw.data(), c->valuePc.tailw.size() / 16);
  uint32_t inner2[5] = {st[0], st[1], st[2], st[3], st[4]};
  for (int i = 0; i < 5; i++) w[i] = dk[i] ^ X5C;
  for (int i = 5; i < 16; i++) w[i] = X5C;
  sha1Iv(st);
  sha1niBlocksW(st, w, 1);
  for (int i = 0; i < 5; i++) w[i] = inner2[i];
  w[5] = 0x80000000;
  for (int i = 6; i < 15; i++) w[i] = 0;
  w[15] = 0x2A0;
  sha1niBlocksW(st, w, 1);
  return st[0] == c->expectW[0] && st[1] == c->expectW[1] && st[2] == c->expectW[2] &&
         st[3] == c->expectW[3] && st[4] == c->expectW[4];
}

/** AVX-512 可用性(Zen 4/服务器 Xeon 等):16 lane 纵向批量 */
static inline bool hasAvx512f() {
  static const bool v = __builtin_cpu_supports("avx512f");
  return v;
}

// —— AVX-512 纵向 16-lane SHA1:结构与 AVX2 版同构,宽度翻倍;
//    VPROLD 单指令完成旋转(AVX2 需 slli|srli 两条)。角色轮换同样按 t%5。 ——

#define ZROL(x, n) _mm512_rol_epi32(x, n)
#define ZF0(b, c, d) _mm512_or_si512(_mm512_and_si512(b, c), _mm512_andnot_si512(b, d))
#define ZF1(b, c, d) _mm512_xor_si512(_mm512_xor_si512(b, c), d)
#define ZF2(b, c, d) _mm512_or_si512(_mm512_and_si512(b, c), \
                                     _mm512_and_si512(d, _mm512_or_si512(b, c)))

__attribute__((target("avx512f")))
static void sha1_block_x16(__m512i h[5], const __m512i wIn[16]) {
  const __m512i K0 = _mm512_set1_epi32((int)0x5A827999U);
  const __m512i K1 = _mm512_set1_epi32((int)0x6ED9EBA1U);
  const __m512i K2 = _mm512_set1_epi32((int)0x8F1BBCDCU);
  const __m512i K3 = _mm512_set1_epi32((int)0xCA62C1D6U);
  __m512i w[16];
  for (int j = 0; j < 16; j++) w[j] = wIn[j];
  __m512i a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  #define ZSTEP(F, aa, bb, cc, dd, ee, KK, ww) { \
    ee = _mm512_add_epi32(ee, ZROL(aa, 5)); \
    ee = _mm512_add_epi32(ee, F(bb, cc, dd)); \
    ee = _mm512_add_epi32(ee, KK); \
    ee = _mm512_add_epi32(ee, ww); \
    bb = ZROL(bb, 30); }
  // 轮 0-15:直接用消息字(不能走 ZROUND——展开会覆盖原始消息)
  ZSTEP(ZF0, a, b, c, d, e, K0, w[0]);
  ZSTEP(ZF0, e, a, b, c, d, K0, w[1]);
  ZSTEP(ZF0, d, e, a, b, c, K0, w[2]);
  ZSTEP(ZF0, c, d, e, a, b, K0, w[3]);
  ZSTEP(ZF0, b, c, d, e, a, K0, w[4]);
  ZSTEP(ZF0, a, b, c, d, e, K0, w[5]);
  ZSTEP(ZF0, e, a, b, c, d, K0, w[6]);
  ZSTEP(ZF0, d, e, a, b, c, K0, w[7]);
  ZSTEP(ZF0, c, d, e, a, b, K0, w[8]);
  ZSTEP(ZF0, b, c, d, e, a, K0, w[9]);
  ZSTEP(ZF0, a, b, c, d, e, K0, w[10]);
  ZSTEP(ZF0, e, a, b, c, d, K0, w[11]);
  ZSTEP(ZF0, d, e, a, b, c, K0, w[12]);
  ZSTEP(ZF0, c, d, e, a, b, K0, w[13]);
  ZSTEP(ZF0, b, c, d, e, a, K0, w[14]);
  ZSTEP(ZF0, a, b, c, d, e, K0, w[15]);
  #define ZROUND(tt, F, KK) { \
    const int idx = (tt) & 15; \
    w[idx] = ZROL(_mm512_xor_si512(_mm512_xor_si512(w[(idx + 13) & 15], w[(idx + 8) & 15]), \
                                   _mm512_xor_si512(w[(idx + 2) & 15], w[idx])), 1); \
    switch ((tt) % 5) { \
      case 0: ZSTEP(F, a, b, c, d, e, KK, w[idx]); break; \
      case 1: ZSTEP(F, e, a, b, c, d, KK, w[idx]); break; \
      case 2: ZSTEP(F, d, e, a, b, c, KK, w[idx]); break; \
      case 3: ZSTEP(F, c, d, e, a, b, KK, w[idx]); break; \
      default: ZSTEP(F, b, c, d, e, a, KK, w[idx]); break; } }
  // 轮 16-19:首次展开(F=ch,K=K0)
  for (int t = 16; t < 20; t++) {
    const int idx = t & 15;
    w[idx] = ZROL(_mm512_xor_si512(_mm512_xor_si512(w[(idx + 13) & 15], w[(idx + 8) & 15]), \
                                   _mm512_xor_si512(w[(idx + 2) & 15], w[idx])), 1);
    switch ((t) % 5) { \
      case 0: ZSTEP(ZF0, a, b, c, d, e, K0, w[idx]); break; \
      case 1: ZSTEP(ZF0, e, a, b, c, d, K0, w[idx]); break; \
      case 2: ZSTEP(ZF0, d, e, a, b, c, K0, w[idx]); break; \
      case 3: ZSTEP(ZF0, c, d, e, a, b, K0, w[idx]); break; \
      default: ZSTEP(ZF0, b, c, d, e, a, K0, w[idx]); break; } }
  for (int t = 20; t < 40; t++) ZROUND(t, ZF1, K1);
  for (int t = 40; t < 60; t++) ZROUND(t, ZF2, K2);
  for (int t = 60; t < 80; t++) ZROUND(t, ZF1, K3);
  #undef ZROUND
  #undef ZSTEP
  h[0] = _mm512_add_epi32(h[0], a);
  h[1] = _mm512_add_epi32(h[1], b);
  h[2] = _mm512_add_epi32(h[2], c);
  h[3] = _mm512_add_epi32(h[3], d);
  h[4] = _mm512_add_epi32(h[4], e);
}

/** AVX2 可用性(一次检测) */
static inline bool hasAvx2() {
  static const bool v = __builtin_cpu_supports("avx2");
  return v;
}

/** SHA1 初始向量(字域,供 AVX2 路径 set1 加载) */
alignas(32) static const uint32_t IVW[5] = {
    0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

// —— AVX2 纵向 8-lane SHA1:每个 256 位向量的 8 个 lane 各跑一个候选 ——
// 寄存器压力仅 5 个 ymm 存状态,与 SHA-NI 单流相当;吞吐按 8 倍摊薄。

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
static int verifyAvx2Batch(const uint8_t* const* keys, const size_t* klens, void* v) {
  constexpr int N = 8;
  auto* c = (VerifyCtx*)v;

  // key 规范化(>64B 折叠)+ 构造每 lane 的 ipad/opad 首块消息字
  alignas(32) uint8_t kb[N][64];
  alignas(32) uint32_t iw[N][16], ow[N][16];
  for (int i = 0; i < N; i++) {
    hmacKeyBlock(keys[i], klens[i], kb[i]);
    for (int j = 0; j < 16; j++) {
      uint32_t wd = (uint32_t)kb[i][j * 4] << 24 | (uint32_t)kb[i][j * 4 + 1] << 16 |
                    (uint32_t)kb[i][j * 4 + 2] << 8 | kb[i][j * 4 + 3];
      iw[i][j] = wd ^ 0x36363636U;
      ow[i][j] = wd ^ 0x5C5C5C5CU;
    }
  }
  alignas(32) uint32_t tmp[8];
  __m256i IW[16], OW[16];
  for (int j = 0; j < 16; j++) {
    for (int i = 0; i < N; i++) tmp[i] = iw[i][j];
    IW[j] = _mm256_load_si256((const __m256i*)tmp);
    for (int i = 0; i < N; i++) tmp[i] = ow[i][j];
    OW[j] = _mm256_load_si256((const __m256i*)tmp);
  }
  const int saltBlk = (int)(c->saltPc.tailw.size() / 16);
  const int valBlk  = (int)(c->valuePc.tailw.size() / 16);
  __m256i h[5], g[5];

  // —— HMAC#1 内层:ipad 块 + 盐尾块 ——
  for (int j = 0; j < 5; j++) h[j] = _mm256_set1_epi32((int)IVW[j]);
  {
    __m256i w[16];
    for (int j = 0; j < 16; j++) w[j] = IW[j];
    sha1_block_x8(h, w);
    for (int tb = 0; tb < saltBlk; tb++) {
      for (int j = 0; j < 16; j++) w[j] = _mm256_set1_epi32((int)c->saltPc.tailw[tb * 16 + j]);
      sha1_block_x8(h, w);
    }
  }
  // —— HMAC#1 外层:opad 块 + 定长尾块(inner 摘要 || 0x80…|| 0x2A0)→ dk ——
  __m256i dk[5];
  {
    __m256i w[16];
    for (int j = 0; j < 16; j++) w[j] = OW[j];
    for (int j = 0; j < 5; j++) g[j] = _mm256_set1_epi32((int)IVW[j]);
    sha1_block_x8(g, w);
    w[0] = h[0]; w[1] = h[1]; w[2] = h[2]; w[3] = h[3]; w[4] = h[4];
    w[5] = _mm256_set1_epi32((int)0x80000000U);
    for (int j = 6; j < 15; j++) w[j] = _mm256_setzero_si256();
    w[15] = _mm256_set1_epi32(0x2A0);
    sha1_block_x8(g, w);
    for (int j = 0; j < 5; j++) dk[j] = g[j];
  }
  // —— HMAC#2 内层:ipad'(dk^0x36) + value 尾块 ——
  {
    __m256i w[16];
    const __m256i X36 = _mm256_set1_epi32((int)0x36363636U);
    for (int j = 0; j < 5; j++) w[j] = _mm256_xor_si256(dk[j], X36);
    for (int j = 5; j < 16; j++) w[j] = X36;
    for (int j = 0; j < 5; j++) h[j] = _mm256_set1_epi32((int)IVW[j]);
    sha1_block_x8(h, w);
    for (int tb = 0; tb < valBlk; tb++) {
      for (int j = 0; j < 16; j++) w[j] = _mm256_set1_epi32((int)c->valuePc.tailw[tb * 16 + j]);
      sha1_block_x8(h, w);
    }
  }
  // —— HMAC#2 外层:opad'(dk^0x5c) + 定长尾块 → mac ——
  {
    __m256i w[16];
    const __m256i X5C = _mm256_set1_epi32((int)0x5C5C5C5CU);
    for (int j = 0; j < 5; j++) w[j] = _mm256_xor_si256(dk[j], X5C);
    for (int j = 5; j < 16; j++) w[j] = X5C;
    for (int j = 0; j < 5; j++) g[j] = _mm256_set1_epi32((int)IVW[j]);
    sha1_block_x8(g, w);
    w[0] = h[0]; w[1] = h[1]; w[2] = h[2]; w[3] = h[3]; w[4] = h[4];
    w[5] = _mm256_set1_epi32((int)0x80000000U);
    for (int j = 6; j < 15; j++) w[j] = _mm256_setzero_si256();
    w[15] = _mm256_set1_epi32(0x2A0);
    sha1_block_x8(g, w);
  }
  // —— 提取 8 lane 摘要比对 ——
  alignas(32) uint32_t dig[5][N];
  for (int j = 0; j < 5; j++) _mm256_store_si256((__m256i*)dig[j], g[j]);
  for (int i = 0; i < N; i++)
    if (dig[0][i] == c->expectW[0] && dig[1][i] == c->expectW[1] &&
        dig[2][i] == c->expectW[2] && dig[3][i] == c->expectW[3] &&
        dig[4][i] == c->expectW[4])
      return i;
  return -1;
}

__attribute__((target("avx512f")))
static int verifyAvx512Batch(const uint8_t* const* keys, const size_t* klens, void* v) {
  constexpr int N = 16;
  auto* c = (VerifyCtx*)v;

  // key 规范化(>64B 折叠)+ 构造每 lane 的 ipad/opad 首块消息字
  alignas(64) uint8_t kb[N][64];
  alignas(64) uint32_t iw[N][16], ow[N][16];
  for (int i = 0; i < N; i++) {
    hmacKeyBlock(keys[i], klens[i], kb[i]);
    for (int j = 0; j < 16; j++) {
      uint32_t wd = (uint32_t)kb[i][j * 4] << 24 | (uint32_t)kb[i][j * 4 + 1] << 16 |
                    (uint32_t)kb[i][j * 4 + 2] << 8 | kb[i][j * 4 + 3];
      iw[i][j] = wd ^ 0x36363636U;
      ow[i][j] = wd ^ 0x5C5C5C5CU;
    }
  }
  alignas(64) uint32_t tmp[16];
  __m512i IW[16], OW[16];
  for (int j = 0; j < 16; j++) {
    for (int i = 0; i < N; i++) tmp[i] = iw[i][j];
    IW[j] = _mm512_load_si512((const void*)tmp);
    for (int i = 0; i < N; i++) tmp[i] = ow[i][j];
    OW[j] = _mm512_load_si512((const void*)tmp);
  }
  const int saltBlk = (int)(c->saltPc.tailw.size() / 16);
  const int valBlk  = (int)(c->valuePc.tailw.size() / 16);
  __m512i h[5], g[5], dk[5];
  const __m512i K36 = _mm512_set1_epi32((int)0x36363636U);
  const __m512i K5C = _mm512_set1_epi32((int)0x5C5C5C5CU);

  // —— HMAC#1 内层 ——
  for (int j = 0; j < 5; j++) h[j] = _mm512_set1_epi32((int)IVW[j]);
  {
    __m512i w[16];
    for (int j = 0; j < 16; j++) w[j] = IW[j];
    sha1_block_x16(h, w);
    for (int tb = 0; tb < saltBlk; tb++) {
      for (int j = 0; j < 16; j++) w[j] = _mm512_set1_epi32((int)c->saltPc.tailw[tb * 16 + j]);
      sha1_block_x16(h, w);
    }
  }
  // —— HMAC#1 外层 → dk ——
  {
    __m512i w[16];
    for (int j = 0; j < 16; j++) w[j] = OW[j];
    for (int j = 0; j < 5; j++) g[j] = _mm512_set1_epi32((int)IVW[j]);
    sha1_block_x16(g, w);
    for (int j = 0; j < 5; j++) w[j] = h[j];
    w[5] = _mm512_set1_epi32((int)0x80000000U);
    for (int j = 6; j < 15; j++) w[j] = _mm512_setzero_si512();
    w[15] = _mm512_set1_epi32(0x2A0);
    sha1_block_x16(g, w);
    for (int j = 0; j < 5; j++) dk[j] = g[j];
  }
  // —— HMAC#2 内层 ——
  {
    __m512i w[16];
    for (int j = 0; j < 5; j++) w[j] = _mm512_xor_si512(dk[j], K36);
    for (int j = 5; j < 16; j++) w[j] = K36;
    for (int j = 0; j < 5; j++) h[j] = _mm512_set1_epi32((int)IVW[j]);
    sha1_block_x16(h, w);
    for (int tb = 0; tb < valBlk; tb++) {
      for (int j = 0; j < 16; j++) w[j] = _mm512_set1_epi32((int)c->valuePc.tailw[tb * 16 + j]);
      sha1_block_x16(h, w);
    }
  }
  // —— HMAC#2 外层 → mac ——
  {
    __m512i w[16];
    for (int j = 0; j < 5; j++) w[j] = _mm512_xor_si512(dk[j], K5C);
    for (int j = 5; j < 16; j++) w[j] = K5C;
    for (int j = 0; j < 5; j++) g[j] = _mm512_set1_epi32((int)IVW[j]);
    sha1_block_x16(g, w);
    for (int j = 0; j < 5; j++) w[j] = h[j];
    w[5] = _mm512_set1_epi32((int)0x80000000U);
    for (int j = 6; j < 15; j++) w[j] = _mm512_setzero_si512();
    w[15] = _mm512_set1_epi32(0x2A0);
    sha1_block_x16(g, w);
  }
  alignas(64) uint32_t dig[5][N];
  for (int j = 0; j < 5; j++) _mm512_store_si512((__m512i*)dig[j], g[j]);
  for (int i = 0; i < N; i++)
    if (dig[0][i] == c->expectW[0] && dig[1][i] == c->expectW[1] &&
        dig[2][i] == c->expectW[2] && dig[3][i] == c->expectW[3] &&
        dig[4][i] == c->expectW[4])
      return i;
  return -1;
}

static void report(const CrackResult& r, const char* engineName) {
  double rate = r.seconds > 0 ? r.attempts / r.seconds : 0;
  std::cerr << "[*] 引擎 " << engineName << ",尝试 " << r.attempts << " 个,耗时 "
            << r.seconds << " s," << (uint64_t)rate << "/s" << std::endl;
}

/** ZK_GPUTHRESH 显式覆盖(用户/测试强制小任务也走 GPU);返回 0 = 未设置 */
static uint64_t gpuThreshEnv() {
  if (const char* v = std::getenv("ZK_GPUTHRESH")) {
    uint64_t n = 0;
    std::from_chars(v, v + std::strlen(v), n);
    if (n > 0) return n;
  }
  return 0;
}

/**
 * auto 模式 GPU 介入的最小候选数(掩码):冷进程 OpenCL 初始化 ~0.1s,小任务 CPU 反而快
 * (实测 CPU ~100M/s,GPU ~740M/s;冷进程盈亏平衡约 800 万)。
 * serve 常驻进程上下文已就绪(gpuWarm),降为 150 万;ZK_GPUTHRESH 可强制覆盖。
 */
static uint64_t gpuThreshold() {
  if (uint64_t n = gpuThreshEnv()) return n;
  return gpuWarm() ? 1500000 : 8000000;
}

/**
 * 字典模式的 GPU 阈值:早期实现下 GPU 打包上传开销让中小字典反而更慢
 * (彼时 16M 词 GPU 有效 ~78M/s < CPU ~163M/s),但 pinned buffer + DMA 流水
 * 上传接入后重测(2 词~6400 万词全扫),GPU/hybrid 全程胜出、无交叉点
 * (16M 词:纯 CPU 179M/s,纯 GPU 326M/s,auto 混合 360M/s;
 *  1 词量级下 GPU 仍以固定开销优势领先 CPU 约 4 倍)。阈值随之下调到与
 * 掩码模式同一量级,让 auto 混合调度在中小字典也能触发。
 */
static uint64_t gpuDictThreshold() {
  if (uint64_t n = gpuThreshEnv()) return n;
  return gpuWarm() ? 1500000 : 8000000;
}

int flaskCrack(const std::string& cookie, const std::string& wordlist, const std::string& mask,
               const std::string& saltIn, int threads, const std::string& engine) {
  std::string salt = saltIn.empty() ? DEFAULT_SALT : saltIn;
  auto parts = splitCookie(cookie);
  if (!parts) {
    std::cerr << "[!] cookie 结构不合法(应为 payload.ts.sig 三段)" << std::endl;
    return 1;
  }
  auto& [payload, ts, sig] = *parts;
  VerifyCtx ctx;
  ctx.value = payload + "." + ts;
  ctx.salt = salt;
  ctx.saltPc.init((const uint8_t*)ctx.salt.data(), ctx.salt.size());
  ctx.valuePc.init((const uint8_t*)ctx.value.data(), ctx.value.size());
  if (!b64urlDecode(sig, ctx.expect) || ctx.expect.size() != 20) {
    std::cerr << "[!] 签名段不是合法的 20 字节 HMAC-SHA1" << std::endl;
    return 1;
  }
  beWords20(ctx.expect.data(), ctx.expectW);
  // 热路径验证器:SHA-NI 可用走字域快速路径,否则字节域便携路径
  bool (*verify)(const uint8_t*, size_t, void*) = hasShaNi() ? verifyFast : verifyCb;
  // 批量验证器(SIMD 纵向多候选):AVX-512 16 lane 优先,退 AVX2 8 lane;
  // 掩码/字典/混合各 CPU 路径统一走此调度,无 SIMD 时 vb=nullptr 回退纯标量
  VerifyBatchFn vb = nullptr; int bsz = 0;
  if (hasAvx512f())      { vb = &verifyAvx512Batch; bsz = 16; }
  else if (hasAvx2())    { vb = &verifyAvx2Batch;   bsz = 8;  }

  const bool useGpu = engine != "cpu";
  const uint64_t gpuTh = gpuThreshold();
#ifdef _WIN32
  const bool cudaAuto = false; // Windows auto 保持 OpenCL 优先
#else
  const bool cudaAuto = engine == "auto"; // Linux 构建仅提供 CUDA 后端
#endif
  GpuCrackParams gp{ (const uint8_t*)ctx.value.data(), ctx.value.size(), {}, 
                     (const uint8_t*)ctx.salt.data(), ctx.salt.size() };
  memcpy(gp.expect, ctx.expect.data(), 20);

  /* ---------- 掩码模式 ---------- */
  if (!mask.empty()) {
    std::vector<std::string> pos;
    if (!parseMask(mask, pos)) {
      std::cerr << "[!] 掩码不合法(支持 ?l ?u ?d ?s ?a 与字面字符,?? 转义)" << std::endl;
      return 1;
    }
    uint64_t total = 1;
    for (const auto& cs : pos) {
      if (total > UINT64_MAX / cs.size()) {
        std::cerr << "[!] 组合数过大(超过 2^64)" << std::endl;
        return 1;
      }
      total *= (uint64_t)cs.size();
    }
    std::cerr << "[*] 掩码共 " << pos.size() << " 位,组合 " << total << " 个" << std::endl;

    // GPU 优先(auto 模式小任务直接 CPU);显式 --engine gpu/cuda 但参数超上限则报错
    const bool gpuParamsOk = pos.size() <= 24 && ctx.value.size() <= 512 && ctx.salt.size() <= 32;
    const bool gpuish = engine == "gpu" || engine == "cuda";
    if (gpuish && !gpuParamsOk) {
      std::cerr << "[!] GPU 参数超限(value ≤ 512B,salt ≤ 32B,掩码 ≤ 24 位)" << std::endl;
      return 1;
    }
    const bool gpuMask = useGpu && gpuParamsOk && (gpuish || total >= gpuTh);
    if (gpuMask && engine == "auto" && !cudaAuto) {
      // 混合引擎:GPU 从头升序吃块,CPU 池从尾降序吃块,对向推进互不等待;
      // 边界重叠块可能被双侧重复验(幂等,仅统计重复),不会漏
      HybridCtl ctl;
      ctl.tail.store(total);
      CrackResult cpuRes;
      std::thread cpuT([&] { cpuRes = crackCpuMaskRange(pos, threads, verify, &ctx, ctl, vb, bsz); });
      uint64_t idx = 0, gpuAtt = 0;
      std::string err;
      auto t0 = std::chrono::steady_clock::now();
      int rc = gpuCrackMask(gp, pos, total, idx, err, &ctl, &gpuAtt);
      cpuT.join();
      auto t1 = std::chrono::steady_clock::now();
      double secs = std::chrono::duration<double>(t1 - t0).count();
      if (g_crackAbort.load(std::memory_order_relaxed)) {
        std::cerr << "[*] 已取消" << std::endl;
        return 1;
      }
      uint64_t attempts = gpuAtt + cpuRes.attempts;
      double rate = secs > 0 ? attempts / secs : 0;
      if (cpuRes.found) {
        std::cerr << "[*] 引擎 GPU+CPU(" << gpuProbe().deviceName << "),CPU 侧命中,耗时 "
                  << secs << " s,约 " << (uint64_t)rate << "/s" << std::endl;
        std::cout << cpuRes.secret << std::endl;
        return 0;
      }
      if (rc == 0) {
        std::string secret = maskCandidate(idx, pos);
        std::cerr << "[*] 引擎 GPU+CPU(" << gpuProbe().deviceName << "),GPU 侧命中于第 "
                  << idx + 1 << " 个,耗时 " << secs << " s,约 " << (uint64_t)rate << "/s" << std::endl;
        std::cout << secret << std::endl;
        return 0;
      }
      if (rc == -1) {
        if (ctl.head.load() == 0) {
          // GPU 未认领任何块(初始化即败),CPU 侧已覆盖全空间
          report(cpuRes, "CPU");
          std::cerr << "[!] 掩码空间跑完未命中" << std::endl;
          return 1;
        }
        std::cerr << "[*] GPU 中途失败(" << err << "),回退 CPU 全空间补跑" << std::endl;
        // 落到下方 CPU 路径(重复验无害)
      } else {
        std::cerr << "[*] 引擎 GPU+CPU,跑完未命中,耗时 " << secs << " s,约 "
                  << (uint64_t)rate << "/s" << std::endl;
        return 1;
      }
    } else if (gpuMask) {
      const bool cudaBe = engine == "cuda" || cudaAuto; // NVRTC/CUDA 后端(探测档)
      auto t0 = std::chrono::steady_clock::now();
      uint64_t idx = 0;
      std::string err;
      int rc = cudaBe ? cudaCrackMask(gp, pos, total, idx, err)
                      : gpuCrackMask(gp, pos, total, idx, err);
      auto t1 = std::chrono::steady_clock::now();
      double secs = std::chrono::duration<double>(t1 - t0).count();
      if (g_crackAbort.load(std::memory_order_relaxed)) {
        std::cerr << "[*] 已取消" << std::endl;
        return 1;
      }
      if (rc == 0) {
        std::string secret = maskCandidate(idx, pos);
        double rate = secs > 0 ? (idx + 1) / secs : 0;
        std::cerr << "[*] 引擎 " << (cudaBe ? "GPU-CUDA(" : "GPU(")
                  << (cudaBe ? cudaProbe().deviceName : gpuProbe().deviceName) << "),命中于第 "
                  << idx + 1 << " 个,耗时 " << secs << " s,约 " << (uint64_t)rate << "/s" << std::endl;
        std::cout << secret << std::endl;
        return 0;
      }
      if (rc == 1) {
        std::cerr << "[*] 引擎 " << (cudaBe ? "GPU-CUDA" : "GPU") << ",跑完未命中,耗时 " << secs
                  << " s,约 " << (uint64_t)(secs > 0 ? total / secs : 0) << "/s" << std::endl;
        return 1;
      }
      if (gpuish) {
        std::cerr << "[!] GPU 路径失败: " << err << std::endl;
        return 1;
      }
      std::cerr << "[*] GPU 不可用(" << err << "),回退 CPU" << std::endl;
    }

    CrackResult r = crackCpuMask(pos, threads, verify, &ctx, vb, bsz);
    if (g_crackAbort.load(std::memory_order_relaxed)) {
      std::cerr << "[*] 已取消" << std::endl;
      return 1;
    }
    if (!r.error.empty()) {
      std::cerr << "[!] " << r.error << std::endl;
      return 1;
    }
    report(r, "CPU");
    if (r.found) {
      std::cout << r.secret << std::endl;
      return 0;
    }
    std::cerr << "[!] 掩码空间跑完未命中" << std::endl;
    return 1;
  }

  /* ---------- 字典模式 ---------- */
  if (wordlist.empty()) {
    std::cerr << "[!] 缺少 --wordlist 或 --mask" << std::endl;
    return 1;
  }
  if (engine == "cpu") { // 纯 CPU:流式单次加载,免 GPU 打包的全量驻留
    CrackResult r = crackCpuWordlist(wordlist, threads, verify, &ctx, vb, bsz);
    if (g_crackAbort.load(std::memory_order_relaxed)) {
      std::cerr << "[*] 已取消" << std::endl;
      return 1;
    }
    if (!r.error.empty()) {
      std::cerr << "[!] " << r.error << std::endl;
      return 1;
    }
    report(r, "CPU");
    if (r.found) {
      std::cout << r.secret << std::endl;
      return 0;
    }
    std::cerr << "[!] 字典跑完未命中" << std::endl;
    return 1;
  }
  // GPU 可能介入:单次加载进内存,GPU 打包与 CPU 收尾(回退/补跑)共用,不再二读文件
  size_t maxLen = 0; // 加载时跟踪最长词(免 GPU 打包阶段二次 O(n) 扫)
  std::vector<std::string> words;
  {
    std::ifstream f(wordlist, std::ios::binary);
    if (!f) {
      std::cerr << "[!] 打不开字典: " << wordlist << std::endl;
      return 1;
    }
    std::string line;
    while (std::getline(f, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
      if (!line.empty()) {
        if (line.size() > maxLen) maxLen = line.size();
        words.push_back(line);
      }
    }
  }
  if (words.empty()) {
    std::cerr << "[!] 字典为空" << std::endl;
    return 1;
  }

  // GPU:打包成定长 stride=32(超长词跳过;auto 模式小字典直接 CPU)
  const bool gpuish = engine == "gpu" || engine == "cuda";
  const bool cudaBe = engine == "cuda";
  const bool gpuParamsOk = ctx.value.size() <= 512 && ctx.salt.size() <= 32;
  if (gpuish && !gpuParamsOk) {
    std::cerr << "[!] GPU 参数超限(value ≤ 512B,salt ≤ 32B)" << std::endl;
    return 1;
  }
  const bool gpuDict = useGpu && gpuParamsOk && (gpuish || words.size() >= gpuDictThreshold());
  if (gpuDict) {
    using PClk = std::chrono::steady_clock;
    auto tp0 = PClk::now();
    // 自适应 stride(加载已跟踪 maxLen):按最长词向上取 8 的倍数(上限 32)。
    // kernel 以 stride 为读长上限,词长恰好等于 stride 时结果仍正确,故仅跳 > stride 的词
    size_t STRIDE = (maxLen + 7) / 8 * 8;
    if (STRIDE > 32) STRIDE = 32;
    const size_t nw = words.size();
    int nt = threads > 0 ? threads : (int)std::thread::hardware_concurrency();
    if (nt < 1) nt = 1;
    if (nt > (int)nw) nt = (int)nw; // 词数不足时不空转线程

    std::vector<size_t> idxMap;     // packed 序号 → words 序号
    std::vector<size_t> skippedIdx; // 超长词(stride 装不下,GPU 跑不了)

    // 两遍并行打包:Pass 1 各线程计数可打包/超长;Pass 2 按前缀偏移并行写 idxMap/skippedIdx 与字节。
    std::vector<size_t> pCnt((size_t)nt, 0), sCnt((size_t)nt, 0);
    {
      std::vector<std::thread> th;
      th.reserve((size_t)nt);
      for (int t = 0; t < nt; t++) {
        size_t lo = nw * (size_t)t / (size_t)nt, hi = nw * (size_t)(t + 1) / (size_t)nt;
        th.emplace_back([&, t, lo, hi] {
          size_t pc = 0;
          for (size_t i = lo; i < hi; i++)
            if (words[i].size() <= STRIDE && words[i].find('\0') == std::string::npos) pc++;
          pCnt[(size_t)t] = pc;
          sCnt[(size_t)t] = hi - lo - pc;
        });
      }
      for (auto& x : th) x.join();
    }
    std::vector<size_t> pBase((size_t)nt, 0), sBase((size_t)nt, 0);
    size_t packedCount = 0, skippedCount = 0;
    for (int t = 0; t < nt; t++) {
      pBase[(size_t)t] = packedCount;
      packedCount += pCnt[(size_t)t];
      sBase[(size_t)t] = skippedCount;
      skippedCount += sCnt[(size_t)t];
    }
    idxMap.assign(packedCount, (size_t)0);
    skippedIdx.assign(skippedCount, (size_t)0);

    // 缓冲分配:CUDA 走 page-locked,OpenCL 走 pinned,分配失败回退普通 vector
    const size_t totalBytes = packedCount * STRIDE;
    OclHostBuf oclPin;
    CudaHostBuf cudaPin;
    std::vector<uint8_t> fallback;
    uint8_t* buf = nullptr;
    bool cudaBuf = false, oclBuf = false;
    if (cudaBe) {
      cudaPin = cudaHostAlloc(totalBytes);
      buf = (uint8_t*)cudaPin.ptr;
      cudaBuf = buf != nullptr;
    } else {
      oclPin = oclHostAlloc(totalBytes);
      buf = (uint8_t*)oclPin.ptr;
      oclBuf = buf != nullptr;
    }
    if (!buf) {
      fallback.assign(totalBytes, 0);
      buf = fallback.data();
    }

    // Pass 2:并行写(idxMap/skippedIdx 与 packed 字节;末尾短于 stride 的部分显式零填充)
    if (totalBytes > 0) {
      std::vector<std::thread> th;
      th.reserve((size_t)nt);
      for (int t = 0; t < nt; t++) {
        size_t lo = nw * (size_t)t / (size_t)nt, hi = nw * (size_t)(t + 1) / (size_t)nt;
        th.emplace_back([&, t, lo, hi] {
          size_t pi = pBase[(size_t)t];
          size_t si = sBase[(size_t)t];
          for (size_t i = lo; i < hi; i++) {
            size_t n = words[i].size();
            if (n > STRIDE || words[i].find('\0') != std::string::npos) {
              skippedIdx[si++] = i;
              continue;
            }
            idxMap[pi] = i;
            uint8_t* dst = buf + pi * STRIDE;
            memcpy(dst, words[i].data(), n);
            if (n < STRIDE) memset(dst + n, 0, STRIDE - n);
            pi++;
          }
        });
      }
      for (auto& x : th) x.join();
    }
    if (std::getenv("ZK_PROF")) {
      double ms = std::chrono::duration<double, std::milli>(PClk::now() - tp0).count();
      fprintf(stderr, "[prof] dict 打包: %.1f ms(%zu 词 → %zu 条,stride=%zu)\n",
              ms, nw, idxMap.size(), STRIDE);
    }
    if (!skippedIdx.empty() && engine != "auto")
      std::cerr << "[*] GPU 路径跳过 " << skippedIdx.size() << " 个超长词(>" << STRIDE
                << "B,GPU 跑完后 CPU 补验)" << std::endl;
    if (!idxMap.empty()) {
      if (engine == "auto" && !cudaAuto) {
        // 混合引擎:序号空间 = 原字典下标(超长词含在内,CPU 侧天然覆盖,免补验)
        HybridCtl ctl;
        ctl.tail.store(words.size());
        CrackResult cpuRes;
        std::thread cpuT([&] { cpuRes = crackCpuWordsRange(words, threads, verify, &ctx, ctl, vb, bsz); });
        uint64_t idx = 0, gpuAtt = 0;
        std::string err;
        auto t0 = std::chrono::steady_clock::now();
        int rc = gpuCrackDict(gp, buf, STRIDE, idxMap.size(), idx, err, &ctl, &idxMap, &gpuAtt,
                              oclBuf ? &oclPin : nullptr);
        cpuT.join();
        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();
        if (g_crackAbort.load(std::memory_order_relaxed)) {
          std::cerr << "[*] 已取消" << std::endl;
          return 1;
        }
        uint64_t attempts = gpuAtt + cpuRes.attempts;
        double rate = secs > 0 ? attempts / secs : 0;
        if (cpuRes.found) {
          std::cerr << "[*] 引擎 GPU+CPU(" << gpuProbe().deviceName << "),CPU 侧命中,耗时 "
                    << secs << " s,约 " << (uint64_t)rate << "/s" << std::endl;
          std::cout << cpuRes.secret << std::endl;
          return 0;
        }
        if (rc == 0) {
          std::cerr << "[*] 引擎 GPU+CPU(" << gpuProbe().deviceName << "),GPU 侧命中于第 "
                    << idx + 1 << " 个,耗时 " << secs << " s,约 " << (uint64_t)rate << "/s" << std::endl;
          // hybrid 模式下 foundIdx 已被 runChunks 映回原字典序号,直接用,勿再过 idxMap
          std::cout << words[idx] << std::endl;
          return 0;
        }
        if (rc == -1) {
          if (ctl.head.load() == 0) {
            // GPU 未认领任何块(初始化即败),CPU 侧已覆盖全部词(含超长词)
            report(cpuRes, "CPU");
            std::cerr << "[!] 字典跑完未命中" << std::endl;
            return 1;
          }
          std::cerr << "[*] GPU 中途失败(" << err << "),回退 CPU 全字典补跑" << std::endl;
          // 落到下方 CPU 路径(重复验无害)
        } else {
          std::cerr << "[*] 引擎 GPU+CPU,跑完未命中,耗时 " << secs << " s,约 "
                    << (uint64_t)rate << "/s" << std::endl;
          return 1;
        }
      } else {
      const bool cudaBe = engine == "cuda" || cudaAuto;
      auto t0 = std::chrono::steady_clock::now();
      uint64_t idx = 0;
      std::string err;
      int rc = cudaBe ? cudaCrackDict(gp, buf, STRIDE, idxMap.size(), idx, err,
                                      cudaBuf ? &cudaPin : nullptr)
                      : gpuCrackDict(gp, buf, STRIDE, idxMap.size(), idx, err, nullptr, nullptr,
                                     nullptr, oclBuf ? &oclPin : nullptr);
      auto t1 = std::chrono::steady_clock::now();
      double secs = std::chrono::duration<double>(t1 - t0).count();
      if (g_crackAbort.load(std::memory_order_relaxed)) {
        std::cerr << "[*] 已取消" << std::endl;
        return 1;
      }
      if (rc == 0) {
        double rate = secs > 0 ? (idx + 1) / secs : 0;
        std::cerr << "[*] 引擎 " << (cudaBe ? "GPU-CUDA(" : "GPU(")
                  << (cudaBe ? cudaProbe().deviceName : gpuProbe().deviceName) << "),命中于第 "
                  << idx + 1 << " 个,耗时 " << secs << " s,约 " << (uint64_t)rate << "/s" << std::endl;
        std::cout << words[idxMap[idx]] << std::endl;
        return 0;
      }
      if (rc == 1) {
        // GPU 未命中:补验被跳过的超长词,避免漏报
        for (size_t i : skippedIdx) {
          if (verify((const uint8_t*)words[i].data(), words[i].size(), &ctx)) {
            std::cerr << "[*] 引擎 GPU+CPU 补验,命中超长词,耗时 " << secs << " s" << std::endl;
            std::cout << words[i] << std::endl;
            return 0;
          }
        }
        std::cerr << "[*] 引擎 " << (cudaBe ? "GPU-CUDA" : "GPU") << ",跑完未命中,耗时 " << secs << " s,约 "
                  << (uint64_t)(secs > 0 ? idxMap.size() / secs : 0) << "/s" << std::endl;
        return 1;
      }
      // 显式 gpu/cuda 引擎失败直接报错;Linux auto 的 CUDA 不可用时回退 CPU。
      if (gpuish) {
        std::cerr << "[!] GPU 路径失败: " << err << std::endl;
        return 1;
      }
      std::cerr << "[*] GPU 不可用(" << err << "),回退 CPU" << std::endl;
      }
    }
  }

  CrackResult r = crackCpuWords(words, threads, verify, &ctx, vb, bsz);
  if (g_crackAbort.load(std::memory_order_relaxed)) {
    std::cerr << "[*] 已取消" << std::endl;
    return 1;
  }
  if (!r.error.empty()) {
    std::cerr << "[!] " << r.error << std::endl;
    return 1;
  }
  report(r, "CPU");
  if (r.found) {
    std::cout << r.secret << std::endl;
    return 0;
  }
  std::cerr << "[!] 字典跑完未命中" << std::endl;
  return 1;
}
