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

static void report(const CrackResult& r, const char* engineName) {
  double rate = r.seconds > 0 ? r.attempts / r.seconds : 0;
  std::cerr << "[*] 引擎 " << engineName << ",尝试 " << r.attempts << " 个,耗时 "
            << r.seconds << " s," << (uint64_t)rate << "/s" << std::endl;
}

/**
 * auto 模式 GPU 介入的最小候选数:冷进程 OpenCL 初始化 ~0.1s,小任务 CPU 反而快
 * (实测 CPU ~100M/s,GPU ~740M/s;冷进程盈亏平衡约 800 万)。
 * serve 常驻进程上下文已就绪(gpuWarm),降为 150 万;ZK_GPUTHRESH 可强制覆盖。
 */
static uint64_t gpuThreshold() {
  if (const char* v = std::getenv("ZK_GPUTHRESH")) {
    uint64_t n = 0;
    std::from_chars(v, v + std::strlen(v), n);
    if (n > 0) return n;
  }
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

  const bool useGpu = engine != "cpu";
  const uint64_t gpuTh = gpuThreshold();
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
    if (gpuMask && engine == "auto") {
      // 混合引擎:GPU 从头升序吃块,CPU 池从尾降序吃块,对向推进互不等待;
      // 边界重叠块可能被双侧重复验(幂等,仅统计重复),不会漏
      HybridCtl ctl;
      ctl.tail.store(total);
      CrackResult cpuRes;
      std::thread cpuT([&] { cpuRes = crackCpuMaskRange(pos, threads, verify, &ctx, ctl); });
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
      const bool cudaBe = engine == "cuda"; // NVRTC/CUDA 后端(探测档)
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

    CrackResult r = crackCpuMask(pos, threads, verify, &ctx);
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
    CrackResult r = crackCpuWordlist(wordlist, threads, verify, &ctx);
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
      if (!line.empty()) words.push_back(line);
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
  const bool gpuDict = useGpu && gpuParamsOk && (gpuish || words.size() >= gpuTh);
  if (gpuDict) {
    // 自适应 stride:按最长词向上取 8 的倍数(上限 32),缩小打包缓冲与上传量。
    // kernel 以 stride 为读长上限,词长恰好等于 stride 时结果仍正确,故仅跳 > stride 的词
    size_t maxLen = 0;
    for (const auto& w : words) if (w.size() > maxLen) maxLen = w.size();
    size_t STRIDE = (maxLen + 7) / 8 * 8;
    if (STRIDE > 32) STRIDE = 32;
    std::vector<uint8_t> packed;
    packed.reserve(words.size() * STRIDE);
    std::vector<size_t> idxMap;     // packed 序号 → words 序号
    std::vector<size_t> skippedIdx; // 超长词(stride 装不下,GPU 跑不了)
    for (size_t i = 0; i < words.size(); i++) {
      if (words[i].size() > STRIDE) { skippedIdx.push_back(i); continue; }
      uint8_t buf[32] = {0};
      memcpy(buf, words[i].data(), words[i].size());
      packed.insert(packed.end(), buf, buf + STRIDE);
      idxMap.push_back(i);
    }
    if (!skippedIdx.empty() && engine != "auto")
      std::cerr << "[*] GPU 路径跳过 " << skippedIdx.size() << " 个超长词(>" << STRIDE
                << "B,GPU 跑完后 CPU 补验)" << std::endl;
    if (!idxMap.empty()) {
      if (engine == "auto") {
        // 混合引擎:序号空间 = 原字典下标(超长词含在内,CPU 侧天然覆盖,免补验)
        HybridCtl ctl;
        ctl.tail.store(words.size());
        CrackResult cpuRes;
        std::thread cpuT([&] { cpuRes = crackCpuWordsRange(words, threads, verify, &ctx, ctl); });
        uint64_t idx = 0, gpuAtt = 0;
        std::string err;
        auto t0 = std::chrono::steady_clock::now();
        int rc = gpuCrackDict(gp, packed.data(), STRIDE, idxMap.size(), idx, err, &ctl, &idxMap,
                              &gpuAtt);
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
      auto t0 = std::chrono::steady_clock::now();
      uint64_t idx = 0;
      std::string err;
      int rc = cudaBe ? cudaCrackDict(gp, packed.data(), STRIDE, idxMap.size(), idx, err)
                      : gpuCrackDict(gp, packed.data(), STRIDE, idxMap.size(), idx, err);
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
      // 显式 gpu/cuda 引擎:GPU 失败直接报错,不静默回退
      std::cerr << "[!] GPU 路径失败: " << err << std::endl;
      return 1;
      }
    }
  }

  CrackResult r = crackCpuWords(words, threads, verify, &ctx);
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
