/** jose.h — JOSE 核心:自动识别、decode/verify/sign/crack 编排。 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "json_mini.h"

namespace jose {

/** 算法家族 */
enum class Algo {
  HS256, HS384, HS512,      // HMAC-SHA2
  RS256, RS384, RS512,      // RSA PKCS#1 v1.5
  PS256, PS384, PS512,      // RSA-PSS
  ES256, ES384, ES512,      // ECDSA
  ED25519, ED448,           // EdDSA
  NONE,                     // alg=none
  UNKNOWN,
};

struct AlgInfo {
  Algo algo = Algo::UNKNOWN;
  std::string name;      // JWA 名
  int hashBits = 0;      // 摘要位数
  bool symmetric = false;
  bool supported = false;
};

AlgInfo detectAlg(const std::string& name);

/** 解析后的 token */
struct Token {
  enum class Kind { JWS, JWE, JSON, Unsecured, INVALID };
  Kind kind = Kind::INVALID;
  std::string raw;

  // compact 分段
  std::string headerB64, payloadB64, sigB64;
  std::string ekB64, ivB64, ctB64, tagB64;  // JWE
  std::vector<std::uint8_t> headerBytes, payload, sig;
  std::vector<std::uint8_t> ek, iv, ct, tag;
  Json header;                  // 解析后的 protected header(对象)
  std::string alg, enc;         // alg(与 enc,JWE)
  AlgInfo algInfo;

  // JSON 序列化(JWS JSON / JWE JSON)
  std::vector<std::string> jsonProtected;   // 每个签名的 protected b64
  std::string jsonPayloadB64;
};

/** 自动识别:token → Token(含 header 解析、alg 探测) */
Token parseToken(std::string_view raw);

/** 便捷:从 header 取字符串字段 */
std::optional<std::string> headerStr(const Json& h, const char* name);

/* ---- 四个功能 ---- */

/** decode:解析并打印结构(输出走 stdout 字符串返回) */
std::string decodeToString(const Token& t, const std::string& keyHint = "");

/** verify:返回 0=通过,1=不通过,-1=错误/不支持 */
int verifyToken(const Token& t, const std::string& secret, const std::string& keyPem,
                const std::string& keyJwk, std::string& err);

/** sign:构造新 token。alg 显式指定。返回 token 或错误信息 */
std::optional<std::string> signToken(const std::string& alg, const std::string& secret,
                                     const std::string& keyPem, const std::string& keyJwk,
                                     const std::string& headerJson, const std::string& payloadJson,
                                     std::string& err);

/* ---- crack ---- */

struct CrackOptions {
  std::string wordlist;
  std::string mask;          // hashcat 风格
  int threads = 0;           // 0=自动
  std::string engine = "auto";  // auto|gpu|cpu
  bool quiet = false;
};

struct CrackResult {
  bool found = false;
  std::string secret;        // 命中的密钥
  std::uint64_t attempts = 0;
  double elapsedSec = 0;
  std::string error;
  double ratePerSec = 0;
};

/** 爆破 HS* 密钥。返回结果(found 由调用方决定成功与否) */
CrackResult crackHmac(const Token& t, const CrackOptions& opt);

/* ---- 工具 ---- */

std::string sha256Hex(const std::string& s);
void printJson(const Json& j, std::string& out, int indent = 0);

}  // namespace jose
