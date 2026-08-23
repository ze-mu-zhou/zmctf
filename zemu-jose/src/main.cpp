/**
 * zemu-jose:JOSE(JWS/JWT/JWE)工具集 CLI,对标 flask-unsign 四功能 + 自动识别算法。
 *
 * 用法:
 *   zemu-jose decode  --token <t> [--key <k>]    解析 token(自动识别格式/算法)
 *   zemu-jose verify  --token <t> (--secret <s> | --key <pemfile> | --jwk <json>)
 *                                               验证签名(算法自动识别)
 *   zemu-jose sign    --alg <alg> --json <payload> [--header <h>]
 *                     (--secret <s> | --key <pemfile> | --jwk <json>)
 *                                               签发 token
 *   zemu-jose crack   --token <t> (--wordlist <f> | --mask <m>)
 *                     [--threads N] [--engine auto|gpu|cpu]  爆破 HS* 密钥
 *   zemu-jose selftest   自研算法 vs OpenSSL 对拍
 *   zemu-jose gpuinfo    探测 OpenCL GPU
 *   zemu-jose gputest    GPU 冒烟测试
 *   zemu-jose serve      stdin 常驻服务(JSON 行协议)
 *   zemu-jose interactive 交互模式(无参数且 stdin 为终端时自动进入)
 *   zemu-jose help       帮助
 *
 * 构建:MSYS2 UCRT64 MinGW g++(见 build.sh),链接 OpenSSL 3.x(libcrypto)。
 */
#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "gpu/ocl.h"
#include "jose.h"
#include "ossl.h"
#include "rsa.h"
#include "sha2.h"

using namespace jose;

/* ==================== 小工具 ==================== */

static void enableVtColors() {
#ifdef _WIN32
  auto fix = [](DWORD h) {
    HANDLE hh = GetStdHandle(h);
    if (hh == INVALID_HANDLE_VALUE || hh == nullptr) return;
    DWORD mode = 0;
    if (GetConsoleMode(hh, &mode)) SetConsoleMode(hh, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  };
  fix(STD_OUTPUT_HANDLE);
  fix(STD_ERROR_HANDLE);
#endif
}

static bool wantColor(FILE* f) {
  if (std::getenv("ZK_COLOR")) return true;
#ifdef _WIN32
  return _isatty(_fileno(f)) != 0;
#else
  return isatty(fileno(f)) != 0;
#endif
}

static bool stdinIsTty() {
#ifdef _WIN32
  DWORD mode;
  return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
  return isatty(fileno(stdin)) != 0;
#endif
}

static std::string readFile(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

static std::string readKeyArg(const std::string& keyPath) {
  if (keyPath.empty()) return {};
  // 优先按文件读;读不到则视为直接内容(hex 密钥 / PEM 文本)
  std::string s = readFile(keyPath);
  if (!s.empty()) return s;
  // 看起来像路径但读不到 → 提醒用户(防路径笔误被静默当作密钥)
  if (keyPath.find('/') != std::string::npos || keyPath.find('\\') != std::string::npos ||
      keyPath.ends_with(".pem") || keyPath.ends_with(".key"))
    std::cerr << "[!] 注意:无法读取文件 '" << keyPath << "',将其按字面密钥处理" << std::endl;
  return keyPath;
}

static void usage(std::ostream& os, bool color) {
  const char* B = ""; const char* CY = ""; const char* YE = ""; const char* GN = "";
  const char* DIM = ""; const char* R = "";
  if (color) {
    B = "\033[1m"; CY = "\033[36m"; YE = "\033[33m"; GN = "\033[32m";
    DIM = "\033[2m"; R = "\033[0m";
  }
  os << B << "用法:" << R << "\n"
     << "  " << CY << "zemu-jose" << R << "                  " << DIM << "# 无参数:交互模式" << R << "\n"
     << "  " << CY << "zemu-jose" << R << " <命令> [参数]\n\n"
     << B << "命令:" << R << "\n"
     << "  " << CY << "decode" << R << "  " << YE << "--token <t>" << R
     << " [" << YE << "--key <k>" << R << "]  解析 token(自动识别格式与算法)\n"
     << "  " << CY << "verify" << R << "  " << YE << "--token <t>" << R
     << " (" << YE << "--secret <s>" << R << " | " << YE << "--key <f>" << R << " | "
     << YE << "--jwk <json>" << R << ")  验证签名\n"
     << "  " << CY << "sign" << R << "    " << YE << "--alg <alg> --json <payload>" << R
     << " [" << YE << "--header <h>" << R << "] (" << YE << "--secret <s>" << R << " | "
     << YE << "--key <f>" << R << " | " << YE << "--jwk <json>" << R << ")  签发 token\n"
     << "  " << CY << "crack" << R << "   " << YE << "--token <t>" << R
     << " (" << YE << "--wordlist <f>" << R << " | " << YE << "--mask <掩码>" << R << ")\n"
     << "               [" << YE << "--threads N" << R << "] [" << YE << "--engine auto|gpu|cpu" << R
     << "]  爆破 HS* 密钥\n"
     << "  " << CY << "selftest" << R << "        SHA-2/HMAC/RSA 自研 vs OpenSSL 对拍\n"
     << "  " << CY << "gpuinfo" << R << "         探测 OpenCL GPU\n"
     << "  " << CY << "gputest" << R << "         GPU 冒烟测试\n"
     << "  " << CY << "serve" << R << "           stdin 常驻服务(JSON 行协议)\n"
     << "  " << CY << "interactive" << R << "     进入交互模式\n"
     << "  " << CY << "help" << R << "            显示本帮助\n\n"
     << B << "算法自动识别:" << R << "\n"
     << "  3 段 = JWS(JWT),2 段 = alg=none,5 段 = JWE;算法从 header 的 " << YE << "alg" << R
     << " 字段读取:\n"
     << "  " << GN << "HS256/384/512" << R << " HMAC-SHA2(对称,可爆破)  "
     << GN << "RS256/384/512" << R << " RSA PKCS#1 v1.5  "
     << GN << "ES256/384/512" << R << " ECDSA  "
     << GN << "EdDSA" << R << "  Ed25519  "
     << GN << "none" << R << "  无签名\n\n"
     << B << "掩码(" << YE << "--mask" << R << B << "):" << R << "\n"
     << "  " << GN << "?l" << R << " 小写  " << GN << "?u" << R << " 大写  " << GN << "?d" << R
     << " 数字  " << GN << "?s" << R << " 特殊  " << GN << "?a" << R << " 全部  "
     << GN << "??" << R << " 字面?\n"
     << "  例:" << GN << "?l?l?d?d" << R << " = 26×26×10×10;  " << GN << "admin?d?d?d?d" << R
     << " = 前 5 位固定\n\n"
     << B << "示例:" << R << "\n"
     << "  zemu-jose decode --token <jwt>\n"
     << "  zemu-jose crack --token <jwt> --wordlist rockyou.txt\n"
     << "  zemu-jose sign --alg HS256 --secret 'secret' --json '{\"admin\":true}'\n"
     << "  zemu-jose verify --token <jwt> --secret 'secret'\n";
}

/* ==================== selftest(自研 vs OpenSSL 对拍) ==================== */

static int cmdSelftest() {
  std::cout << "SHA-NI vs 便携 对拍:" << std::endl;
  bool ok = true;
  // 1. SHA-256 便携 vs SHA-NI(随机长度 + 边界)
  sha2::g_forceImpl = 1;
  std::mt19937 rng(20260823);
  for (int len : {0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 1000, 100000}) {
    std::string data(len, 0);
    for (auto& c : data) c = (char)rng();
    auto p = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)data.data(), data.size()));
    sha2::g_forceImpl = 2;
    auto n = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)data.data(), data.size()));
    sha2::g_forceImpl = 1;
    if (p != n) { std::cout << "  FAIL len=" << len << std::endl; ok = false; }
  }
  std::cout << (ok ? "  OK(SHA-NI 与便携全一致)" : "  FAIL") << std::endl;

  // 2. HMAC-SHA256 热路径 vs 流式
  {
    std::string msg = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9";
    sha2::HmacSha256FixedMsg fm(std::span<const std::uint8_t>((const std::uint8_t*)msg.data(), msg.size()));
    for (const char* key : {"secret", "password123", "", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}) {
      std::uint8_t m1[32], m2[32];
      sha2::HmacSha<256> h;
      h.init(std::string_view(key));
      h.digest(std::span<const std::uint8_t>((const std::uint8_t*)msg.data(), msg.size()), m1);
      fm.mac((const std::uint8_t*)key, strlen(key), m2);
      if (memcmp(m1, m2, 32) != 0) { std::cout << "  FAIL hmac-fixedmsg key=" << key << std::endl; ok = false; }
    }
    std::cout << (ok ? "  OK(HMAC 热路径与流式一致)" : "  FAIL") << std::endl;
  }

  // 3. RSA vs OpenSSL(生成密钥对拍)
  {
    std::cout << "RSA-PKCS1v1.5 vs OpenSSL:" << std::endl;
    // 用 OpenSSL 生成 RSA 密钥对(PEM),我方签名 → OpenSSL 验签;OpenSSL 签名 → 我方验签
    BIO* bio = BIO_new_file("selftest_rsa.pem", "w");
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (bio && pctx && EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 1024) > 0 &&
        EVP_PKEY_keygen(pctx, &pkey) > 0 && PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
      BIO_flush(bio);  // 缓冲 BIO 须显式 flush 才落盘
      std::string pem = readFile("selftest_rsa.pem");
      auto key = rsa::parsePem(pem);
      if (key && key->hasPrivate()) {
        std::string msg = "selftest message for RSA 对拍";
        // 我方 SHA-256 摘要
        auto digest = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)msg.data(), msg.size()));
        // 我方签名
        auto sig = rsa::sign(*key, digest, 256);
        // OpenSSL 验签
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        int rc = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, pkey);
        if (rc == 1) rc = EVP_DigestVerify(mctx, sig.data(), sig.size(),
                                           (const unsigned char*)msg.data(), msg.size());
        EVP_MD_CTX_free(mctx);
        std::cout << "  我方签名→OpenSSL验签: " << (rc == 1 ? "OK" : "FAIL") << std::endl;
        if (rc != 1) ok = false;
        // OpenSSL 签名 → 我方验签
        mctx = EVP_MD_CTX_new();
        std::vector<unsigned char> osig;
        if (EVP_DigestSignInit(mctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
          size_t slen = 0;
          if (EVP_DigestSign(mctx, nullptr, &slen, (const unsigned char*)msg.data(), msg.size()) == 1) {
            osig.resize(slen);
            if (EVP_DigestSign(mctx, osig.data(), &slen, (const unsigned char*)msg.data(), msg.size()) == 1)
              osig.resize(slen);
          }
        }
        EVP_MD_CTX_free(mctx);
        bool vok = !osig.empty() && rsa::verify(*key, digest, 256, osig);
        std::cout << "  OpenSSL签名→我方验签: " << (vok ? "OK" : "FAIL") << std::endl;
        if (!vok) ok = false;
        // 篡改验签必须失败
        auto bad = sig;
        bad[0] ^= 0x01;
        bool reject = !rsa::verify(*key, digest, 256, bad);
        std::cout << "  篡改签名被拒: " << (reject ? "OK" : "FAIL") << std::endl;
        if (!reject) ok = false;
      } else {
        std::cout << "  FAIL 无法解析 PEM" << std::endl;
        ok = false;
      }
    } else {
      std::cout << "  FAIL 密钥生成失败" << std::endl;
      ok = false;
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (bio) BIO_free(bio);
    std::remove("selftest_rsa.pem");
  }

  std::cout << (ok ? "\nselftest 全部通过" : "\nselftest 存在失败项") << std::endl;
  return ok ? 0 : 1;
}

/* ==================== 命令分发 ==================== */

static int cmdDecode(const Token& t, const std::string& key) {
  std::cout << decodeToString(t, key);
  return 0;
}

static int cmdVerify(const Token& t, const std::string& secret, const std::string& keyPem,
                     const std::string& keyJwk) {
  std::string err;
  int rc = verifyToken(t, secret, keyPem, keyJwk, err);
  if (rc < 0) {
    std::cerr << "[!] " << err << std::endl;
    return 2;
  }
  if (rc == 0) {
    std::cout << "签名有效 (alg=" << t.alg << ")" << std::endl;
    return 0;
  }
  std::cout << "签名无效 (alg=" << t.alg << ")" << std::endl;
  return 1;
}

static int cmdSign(const std::string& alg, const std::string& secret, const std::string& keyPem,
                   const std::string& keyJwk, const std::string& headerJson,
                   const std::string& payloadJson) {
  std::string err;
  auto tok = signToken(alg, secret, keyPem, keyJwk, headerJson, payloadJson, err);
  if (!tok) {
    std::cerr << "[!] " << err << std::endl;
    return 2;
  }
  std::cout << *tok << std::endl;
  return 0;
}

static int cmdCrack(const Token& t, const CrackOptions& opt) {
  if (t.algInfo.algo != Algo::HS256 && t.algInfo.algo != Algo::HS384 && t.algInfo.algo != Algo::HS512) {
    std::cerr << "[!] crack 仅支持 HS*;当前 alg=" << t.alg << std::endl;
    return 2;
  }
  auto res = crackHmac(t, opt);
  if (!res.error.empty()) {
    std::cerr << "[!] " << res.error << std::endl;
    return 2;
  }
  auto fmt = [](double v) -> std::string {
    if (v >= 1e9) return std::to_string(v / 1e9) + " GH/s";
    if (v >= 1e6) return std::to_string(v / 1e6) + " MH/s";
    if (v >= 1e3) return std::to_string(v / 1e3) + " kH/s";
    return std::to_string(v) + " H/s";
  };
  std::cerr << "尝试 " << res.attempts << " 个候选,耗时 " << std::fixed
            << std::setprecision(2) << res.elapsedSec << "s,速率 " << fmt(res.ratePerSec)
            << std::endl;
  if (res.found) {
    std::cout << "SECRET: " << res.secret << std::endl;
    return 0;
  }
  std::cout << "未命中" << std::endl;
  return 1;
}

static int runCommand(int argc, char** argv) {
  std::string cmd = argv[1];
  if (cmd == "selftest") return cmdSelftest();
  if (cmd == "gpuinfo") {
    gpu::GpuProbe pr = gpu::gpuProbe();
    if (pr.ok) {
      std::cout << "GPU 可用: " << pr.deviceName << std::endl;
      return 0;
    }
    std::cout << "GPU 不可用: " << pr.error << std::endl;
    return 1;
  }
  if (cmd == "gputest") {
    gpu::GpuProbe pr = gpu::gpuProbe();
    if (!pr.ok) { std::cout << "GPU 不可用: " << pr.error << std::endl; return 1; }
    // 冒烟:掩码 ?l?l?l(17576 候选,无命中),验证 kernel 可跑
    std::vector<std::uint8_t> msg(128, 0x61), expect(32, 0xff);
    msg[0] = 0x80; msg[127] = 0x02;
    gpu::GpuCrackParams gp{&msg, 2, &expect};
    std::vector<std::string> pos(3, "abcdefghijklmnopqrstuvwxyz");
    std::string err;
    std::uint64_t fidx = 0, tried = 0;
    int rc = gpu::gpuCrackMask(gp, pos, 26ULL*26*26, fidx, tried, err);
    if (rc == 1 && tried == 26ULL*26*26) { std::cout << "OpenCL 链路 OK(冒烟无命中)" << std::endl; return 0; }
    std::cout << "冒烟失败 rc=" << rc << " " << err << std::endl;
    return 1;
  }
  if (cmd == "help" || cmd == "--help" || cmd == "-h") {
    usage(std::cout, wantColor(stdout));
    return 0;
  }

  // 参数解析
  std::string token, secret, keyPath, jwk, alg, headerJson, payloadJson;
  std::string wordlist, mask, engine = "auto";
  int threads = 0;
  for (int i = 2; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--token") token = next();
    else if (a == "--secret") secret = next();
    else if (a == "--key") keyPath = next();
    else if (a == "--jwk") jwk = next();
    else if (a == "--alg") alg = next();
    else if (a == "--header") headerJson = next();
    else if (a == "--json") payloadJson = next();
    else if (a == "--wordlist") wordlist = next();
    else if (a == "--mask") mask = next();
    else if (a == "--threads") {
      std::string v = next();
      std::from_chars(v.data(), v.data() + v.size(), threads);
    } else if (a == "--engine") engine = next();
    else { std::cerr << "[!] 未知参数: " << a << std::endl; usage(std::cerr, wantColor(stderr)); return 2; }
  }

  if (cmd == "decode") {
    if (token.empty()) { usage(std::cerr, wantColor(stderr)); return 2; }
    auto t = parseToken(token);
    return cmdDecode(t, readKeyArg(keyPath));
  }
  if (cmd == "verify") {
    if (token.empty()) { usage(std::cerr, wantColor(stderr)); return 2; }
    auto t = parseToken(token);
    if (t.kind == Token::Kind::INVALID) { std::cerr << "[!] token 解析失败" << std::endl; return 2; }
    return cmdVerify(t, secret, readKeyArg(keyPath), jwk);
  }
  if (cmd == "sign") {
    if (alg.empty() || payloadJson.empty()) { usage(std::cerr, wantColor(stderr)); return 2; }
    return cmdSign(alg, secret, readKeyArg(keyPath), jwk, headerJson, payloadJson);
  }
  if (cmd == "crack") {
    if (token.empty() || (wordlist.empty() && mask.empty())) { usage(std::cerr, wantColor(stderr)); return 2; }
    auto t = parseToken(token);
    if (t.kind == Token::Kind::INVALID) { std::cerr << "[!] token 解析失败" << std::endl; return 2; }
    CrackOptions opt{wordlist, mask, threads, engine, false};
    return cmdCrack(t, opt);
  }

  usage(std::cerr, wantColor(stderr));
  return 2;
}

/* ==================== serve ==================== */

static int cmdServe() {
  std::cerr.rdbuf(std::cout.rdbuf());
  std::string line;
  while (std::getline(std::cin, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    Json j;
    JsonParser parser(line);
    std::vector<std::string> args;
    bool ok = parser.parse(j) && j.type == Json::ARR;
    if (ok) {
      for (const auto& v : j.arr) {
        if (v.type != Json::STR) { ok = false; break; }
        args.push_back(v.str);
      }
    }
    int rc = 2;
    if (ok && !args.empty()) {
      std::vector<char*> argv;
      argv.reserve(args.size() + 1);
      argv.push_back((char*)"zemu-jose");
      for (auto& a : args) argv.push_back(a.data());
      rc = runCommand((int)argv.size(), argv.data());
    } else {
      std::cout << "[!] serve:命令须为非空 JSON 字符串数组" << std::endl;
    }
    std::cout << "<<<zk-rc=" << rc << ">>>" << std::endl;
  }
  return 0;
}

/* ==================== payload 键值表格编辑器 ==================== */

static std::string ask(const std::string& prompt, bool& eof);

// East Asian Wide 码点判定(用于表格对齐,CJK 等宽字符计 2 列)
static bool cpWide(uint32_t cp) {
  return cp >= 0x1100 &&
         (cp <= 0x115F || cp == 0x2329 || cp == 0x232A ||
          (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
          (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
          (cp >= 0xFE30 && cp <= 0xFE6F) || (cp >= 0xFF00 && cp <= 0xFF60) ||
          (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x20000 && cp <= 0x3FFFD));
}

// UTF-8 字符串的终端显示宽度
static size_t dispWidth(const std::string& s) {
  size_t w = 0;
  for (size_t i = 0; i < s.size();) {
    uint32_t cp;
    size_t adv;
    if (!utf8DecodeStrict(s, i, cp, adv)) { w++; i++; continue; }
    i += adv;
    w += cpWide(cp) ? 2 : 1;
  }
  return w;
}

// 截断到指定显示宽度,超出部分以 … 收尾
static std::string dispTrunc(const std::string& s, size_t maxw) {
  if (dispWidth(s) <= maxw) return s;
  std::string out;
  size_t w = 0;
  for (size_t i = 0; i < s.size();) {
    uint32_t cp;
    size_t adv;
    if (!utf8DecodeStrict(s, i, cp, adv)) break;
    size_t cw = cpWide(cp) ? 2 : 1;
    if (w + cw + 1 > maxw) break;
    out.append(s, i, adv);
    w += cw;
    i += adv;
  }
  out += "…";
  return out;
}

// 正式序列化:ensure_ascii 转义(复用 jsonEscape,非法 UTF-8 返回 false),
// 但保持插入顺序不排序 —— 表格行序/dup-key 顺序原样进入 token
// (signToken 对 payload 逐字节使用,不重新解析)
static bool jsonSerializeOrd(const Json& j, std::string& out) {
  switch (j.type) {
    case Json::NIL: out += "null"; break;
    case Json::BOOL: out += j.b ? "true" : "false"; break;
    case Json::NUM: out += j.num; break;
    case Json::STR: if (!jsonEscape(j.str, out)) return false; break;
    case Json::ARR:
      out += '[';
      for (size_t i = 0; i < j.arr.size(); i++) {
        if (i) out += ',';
        if (!jsonSerializeOrd(j.arr[i], out)) return false;
      }
      out += ']';
      break;
    case Json::OBJ:
      out += '{';
      for (size_t i = 0; i < j.obj.size(); i++) {
        if (i) out += ',';
        if (!jsonEscape(j.obj[i].first, out)) return false;
        out += ':';
        if (!jsonSerializeOrd(j.obj[i].second, out)) return false;
      }
      out += '}';
      break;
  }
  return true;
}

// 表格显示用字符串转义:仅转义控制字符/引号/反斜杠,非 ASCII 保持 UTF-8 可读
static void jsonDispEscape(const std::string& s, std::string& out) {
  out += '"';
  for (size_t i = 0; i < s.size();) {
    uint8_t c = (uint8_t)s[i];
    if (c >= 0x20 && c != '"' && c != '\\') { out += (char)c; i++; continue; }
    switch (c) {
      case '"': out += "\\\""; i++; break;
      case '\\': out += "\\\\"; i++; break;
      case '\n': out += "\\n"; i++; break;
      case '\r': out += "\\r"; i++; break;
      case '\t': out += "\\t"; i++; break;
      default: std::format_to(std::back_inserter(out), "\\u{:04x}", (uint32_t)c); i++; break;
    }
  }
  out += '"';
}

// 表格显示用序列化(插入顺序,可读 UTF-8;正式序列化仍由 jsonCanonical 负责)
static void jsonDisp(const Json& j, std::string& out) {
  switch (j.type) {
    case Json::NIL: out += "null"; break;
    case Json::BOOL: out += j.b ? "true" : "false"; break;
    case Json::NUM: out += j.num; break;
    case Json::STR: jsonDispEscape(j.str, out); break;
    case Json::ARR:
      out += '[';
      for (size_t i = 0; i < j.arr.size(); i++) {
        if (i) out += ',';
        jsonDisp(j.arr[i], out);
      }
      out += ']';
      break;
    case Json::OBJ:
      out += '{';
      for (size_t i = 0; i < j.obj.size(); i++) {
        if (i) out += ',';
        jsonDispEscape(j.obj[i].first, out);
        out += ':';
        jsonDisp(j.obj[i].second, out);
      }
      out += '}';
      break;
  }
}

// 值文本 → Json:整体能按 JSON 解析则保留类型("abc"→字符串、123→数字、
// true/false/null、嵌套数组/对象均可),否则按字面字符串处理
static Json parseValueText(const std::string& s) {
  Json j;
  JsonParser p(s);
  if (p.parse(j) && p.atEnd()) return j;
  j = Json{};
  j.type = Json::STR;
  j.str = s;
  return j;
}

// 渲染键值表格:左键右值,底部 [+] 添加行
static void renderKvTable(const std::vector<std::pair<std::string, Json>>& rows, bool color) {
  const char* GN = color ? "\033[32m" : "";
  const char* DIM = color ? "\033[2m" : "";
  const char* R = color ? "\033[0m" : "";
  std::vector<std::pair<std::string, std::string>> cells;
  size_t iw = 1, kw = std::max(dispWidth("键"), (size_t)4), vw = std::max(dispWidth("值"), (size_t)8);
  for (const auto& kv : rows) {
    std::string v;
    jsonDisp(kv.second, v);
    std::string k2 = dispTrunc(kv.first, 24), v2 = dispTrunc(v, 40);
    kw = std::max(kw, dispWidth(k2));
    vw = std::max(vw, dispWidth(v2));
    cells.emplace_back(std::move(k2), std::move(v2));
  }
  for (size_t n = cells.size(); n >= 10; n /= 10) iw++;
  auto bar = [](size_t n) {
    std::string s;
    for (size_t i = 0; i < n; i++) s += "─";
    return s;
  };
  auto pad = [](const std::string& s, size_t w) {
    size_t d = dispWidth(s);
    return d < w ? s + std::string(w - d, ' ') : s;
  };
  const size_t total = iw + kw + vw + 10;  // 整表显示宽度
  std::cerr << "┌" << bar(iw + 2) << "┬" << bar(kw + 2) << "┬" << bar(vw + 2) << "┐\n"
            << "│ " << pad("#", iw) << " │ " << pad("键", kw) << " │ " << pad("值", vw) << " │\n"
            << "├" << bar(iw + 2) << "┼" << bar(kw + 2) << "┼" << bar(vw + 2) << "┤\n";
  if (cells.empty())
    std::cerr << "│ " << DIM << pad("(空,回车加行)", total - 4) << R << " │\n";
  for (size_t i = 0; i < cells.size(); i++)
    std::cerr << "│ " << pad(std::to_string(i + 1), iw) << " │ " << pad(cells[i].first, kw)
              << " │ " << pad(cells[i].second, vw) << " │\n";
  std::cerr << "├" << bar(total - 2) << "┤\n"
            << "│ " << GN << pad("[+] 添加新行", total - 4) << R << " │\n"
            << "└" << bar(total - 2) << "┘" << std::endl;
}

// 交互式 payload 编辑:成功写出 JSON 返回 true;eof 或序列化失败返回 false
static bool payloadTableEditor(std::string& outJson, bool& eof, bool color) {
  std::vector<std::pair<std::string, Json>> rows;
  for (;;) {
    std::cerr << "\npayload 键值表:" << std::endl;
    renderKvTable(rows, color);
    std::string op = ask("操作 [回车/+ = 加行 | e<N> 编辑 | d<N> 删除 | r 原始JSON | done 完成]: ", eof);
    if (eof) return false;
    if (op.empty() || op == "+") {
      std::string k = ask("  键(留空取消): ", eof);
      if (eof) return false;
      if (k.empty()) continue;
      std::string v = ask("  值(数字/true/false/null/JSON 自动识别,其余按字符串): ", eof);
      if (eof) return false;
      Json val = parseValueText(v);
      for (const auto& kv : rows)
        if (kv.first == k) {
          std::cerr << "[*] 键 '" << k << "' 已存在,仍追加为新行(dup-key;要改旧行请用 e<N>)" << std::endl;
          break;
        }
      rows.emplace_back(std::move(k), std::move(val));
    } else if (op == "done" || op == "q" || op == "Q") {
      break;
    } else if (op == "r") {
      std::string raw = ask("payload JSON: ", eof);
      if (eof) return false;
      Json j;
      JsonParser p(raw);
      if (!p.parse(j) || !p.atEnd()) {
        std::cerr << "[!] JSON 解析失败,未采用" << std::endl;
        continue;
      }
      outJson = raw;
      return true;
    } else if ((op[0] == 'e' || op[0] == 'd') && op.size() > 1) {
      int idx = 0;
      auto rs = std::from_chars(op.data() + 1, op.data() + op.size(), idx);
      if (rs.ec != std::errc() || idx < 1 || (size_t)idx > rows.size()) {
        std::cerr << "[!] 无效行号" << std::endl;
        continue;
      }
      if (op[0] == 'd') {
        rows.erase(rows.begin() + (idx - 1));
      } else {
        auto& kv = rows[idx - 1];
        std::string cur;
        jsonDisp(kv.second, cur);
        std::string k = ask("  键(留空=" + kv.first + "): ", eof);
        if (eof) return false;
        std::string v = ask("  值(留空=" + cur + "): ", eof);
        if (eof) return false;
        if (!k.empty()) kv.first = std::move(k);
        if (!v.empty()) kv.second = parseValueText(v);
      }
    } else {
      std::cerr << "[!] 无效操作" << std::endl;
    }
  }
  Json obj;
  obj.type = Json::OBJ;
  obj.obj = std::move(rows);
  outJson.clear();
  if (!jsonSerializeOrd(obj, outJson)) {
    std::cerr << "[!] 含非法 UTF-8,无法序列化" << std::endl;
    return false;
  }
  std::cerr << "payload = " << outJson << std::endl;
  return true;
}

/* ==================== 交互模式 ==================== */

static std::string ask(const std::string& prompt, bool& eof) {
  std::cerr << prompt;
  std::cerr.flush();
  std::string line;
  if (!std::getline(std::cin, line)) eof = true;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  return line;
}

static int cmdInteractive() {
  const bool color = wantColor(stderr);
  const char* B = ""; const char* CY = ""; const char* GN = ""; const char* R = "";
  if (color) { B = "\033[1m"; CY = "\033[36m"; GN = "\033[32m"; R = "\033[0m"; }
  bool eof = false;
  for (;;) {
    std::cerr << "\n" << B << "===== zemu-jose 交互模式 =====" << R << "\n"
              << "  " << CY << "1" << R << ") decode  解析 token(自动识别算法)\n"
              << "  " << CY << "2" << R << ") verify  验证签名(自动识别算法)\n"
              << "  " << CY << "3" << R << ") sign    签发 token\n"
              << "  " << CY << "4" << R << ") crack   爆破 HS* 密钥(字典/掩码)\n"
              << "  " << CY << "0" << R << ") 退出\n";
    std::string c = ask("请选择 [0-4]: ", eof);
    if (eof || c == "0" || c == "q" || c == "Q") break;
    std::vector<std::string> args;
    if (c == "1") {
      args = {"decode", "--token", ask("token: ", eof)};
    } else if (c == "2") {
      args = {"verify", "--token", ask("token: ", eof)};
      std::string mode = ask("密钥类型 [1=secret 2=PEM文件 3=JWK]: ", eof);
      if (mode == "1") { args.push_back("--secret"); args.push_back(ask("secret: ", eof)); }
      else if (mode == "2") { args.push_back("--key"); args.push_back(ask("PEM 文件路径: ", eof)); }
      else if (mode == "3") { args.push_back("--jwk"); args.push_back(ask("JWK JSON: ", eof)); }
      else { std::cerr << "[!] 无效选择" << std::endl; continue; }
    } else if (c == "3") {
      args = {"sign", "--alg", ask("alg [HS256/RS256/ES256/EdDSA/none]: ", eof)};
      if (eof) break;
      std::string payload;
      if (!payloadTableEditor(payload, eof, color)) {
        if (eof) break;
        continue;
      }
      args.push_back("--json");
      args.push_back(payload);
      std::string mode = ask("密钥类型 [1=secret 2=PEM文件 3=JWK]: ", eof);
      if (mode == "1") { args.push_back("--secret"); args.push_back(ask("secret: ", eof)); }
      else if (mode == "2") { args.push_back("--key"); args.push_back(ask("PEM 文件路径: ", eof)); }
      else if (mode == "3") { args.push_back("--jwk"); args.push_back(ask("JWK JSON: ", eof)); }
      else { std::cerr << "[!] 无效选择" << std::endl; continue; }
      std::string h = ask("header JSON(留空=默认): ", eof);
      if (!h.empty()) { args.push_back("--header"); args.push_back(h); }
    } else if (c == "4") {
      args = {"crack", "--token", ask("token: ", eof)};
      std::string mode = ask("模式 [1=字典 2=掩码]: ", eof);
      if (mode == "1") { args.push_back("--wordlist"); args.push_back(ask("wordlist 路径: ", eof)); }
      else if (mode == "2") { args.push_back("--mask"); args.push_back(ask("掩码(?l ?u ?d ?s ?a ??): ", eof)); }
      else { std::cerr << "[!] 无效选择" << std::endl; continue; }
      std::string th = ask("threads(留空=自动): ", eof);
      if (!th.empty()) { args.push_back("--threads"); args.push_back(th); }
    } else {
      std::cerr << "[!] 无效选择,请重新输入" << std::endl;
      continue;
    }
    if (eof) break;
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    argv.push_back((char*)"zemu-jose");
    for (auto& a : args) argv.push_back(a.data());
    runCommand((int)argv.size(), argv.data());
  }
  return 0;
}

int main(int argc, char** argv) {
  enableVtColors();
  if (argc >= 2 && std::string(argv[1]) == "serve") return cmdServe();
  if (argc >= 2) {
    std::string a1 = argv[1];
    if (a1 == "interactive" || a1 == "-i") return cmdInteractive();
    if (a1 == "help" || a1 == "--help" || a1 == "-h") { usage(std::cout, wantColor(stdout)); return 0; }
  }
  if (argc < 2) {
    if (stdinIsTty()) return cmdInteractive();
    usage(std::cerr, wantColor(stderr));
    return 2;
  }
  return runCommand(argc, argv);
}
