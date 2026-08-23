/** rsa.h — RSA PKCS#1 v1.5(RS256/384/512)自研实现。
 * 密钥解析:PEM(PKCS#1 / PKCS#8 / SPKI)+ JWK;签名 EMSA-PKCS1-v1_5 编码。
 * 与 cryptography / pyjwt 输出完全对拍(见 tests)。
 * 依赖 bigint.h(模幂)与 sha2.h(摘要)。
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "bigint.h"
#include "json_mini.h"
#include "b64.h"

namespace jose::rsa {

using bn::BigInt;

struct RsaKey {
  BigInt n, e, d;  // d 为空 = 公钥
  bool hasPrivate() const { return !d.isZero(); }
};

/** JWA DigestInfo 前缀(EMSA-PKCS1-v1_5 的 ASN.1 头)*/
inline const std::vector<std::uint8_t>& digestInfoPrefix(int hashBits) {
  static const std::vector<std::uint8_t> P256 = {
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
  static const std::vector<std::uint8_t> P384 = {
      0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
  static const std::vector<std::uint8_t> P512 = {
      0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
  return hashBits == 256 ? P256 : (hashBits == 384 ? P384 : P512);
}

/** EMSA-PKCS1-v1_5:0x00 0x01 0xFF... 0x00 || DigestInfo || digest
 * k 不足以容纳 DigestInfo + 最小 PS(8 字节)时返回空 vector(RFC 8017),调用方必须判空。 */
inline std::vector<std::uint8_t> emsaPkcs1(const std::vector<std::uint8_t>& digest, int hashBits,
                                           std::size_t k) {
  const auto& di = digestInfoPrefix(hashBits);
  std::size_t tLen = di.size() + digest.size();
  if (k < tLen + 11) return {};  // 密钥过短:emLen < tLen + 11,编码失败(防 size_t 下溢)
  std::vector<std::uint8_t> em(k, 0);
  em[0] = 0x00;
  em[1] = 0x01;
  std::size_t psLen = k - tLen - 3;
  std::memset(em.data() + 2, 0xff, psLen);
  em[2 + psLen] = 0x00;
  std::memcpy(em.data() + 3 + psLen, di.data(), di.size());
  std::memcpy(em.data() + 3 + psLen + di.size(), digest.data(), digest.size());
  return em;
}

/** RSASSA-PKCS1-v1_5 签名:s = m^d mod n */
inline std::vector<std::uint8_t> sign(const RsaKey& key, const std::vector<std::uint8_t>& digest,
                                      int hashBits) {
  std::size_t k = (key.n.bits() + 7) / 8;
  auto em = emsaPkcs1(digest, hashBits, k);
  if (em.empty()) return {};  // 密钥过短,无法编码
  auto m = bn::fromBytes(em.data(), em.size());
  auto s = bn::modpow(m, key.d, key.n);
  return bn::toBytes(s, k);
}

/** RSASSA-PKCS1-v1_5 验签 */
inline bool verify(const RsaKey& key, const std::vector<std::uint8_t>& digest, int hashBits,
                   const std::vector<std::uint8_t>& sig) {
  std::size_t k = (key.n.bits() + 7) / 8;
  if (sig.size() != k) return false;
  auto expect = emsaPkcs1(digest, hashBits, k);
  if (expect.empty()) return false;  // 密钥过短
  auto s = bn::fromBytes(sig.data(), sig.size());
  if (cmp(s, key.n) >= 0) return false;
  auto em = bn::toBytes(bn::modpow(s, key.e, key.n), k);
  return em == expect;
}

/* ==================== 密钥解析 ==================== */

namespace der {

struct Reader {
  const std::uint8_t* p;
  std::size_t len;
  std::size_t pos = 0;

  bool readTag(std::uint8_t& tag) {
    if (pos >= len) return false;
    tag = p[pos++];
    return true;
  }
  bool readLength(std::size_t& out) {
    if (pos >= len) return false;
    std::uint8_t b = p[pos++];
    if (!(b & 0x80)) { out = b; return true; }
    std::size_t n = b & 0x7f;
    if (n == 0 || n > 4 || pos + n > len) return false;
    out = 0;
    for (std::size_t i = 0; i < n; i++) out = (out << 8) | p[pos++];
    return true;
  }
  /** 读取一个 TLV,返回其值区间 */
  bool readTlv(std::uint8_t& tag, const std::uint8_t*& val, std::size_t& vlen) {
    if (!readTag(tag)) return false;
    if (!readLength(vlen)) return false;
    if (pos + vlen > len) return false;
    val = p + pos;
    pos += vlen;
    return true;
  }
};

inline std::optional<std::vector<std::uint8_t>> pemDecode(const std::string& pem) {
  // 找 -----BEGIN 行之后、-----END 之前的 base64 正文
  std::size_t i = pem.find("-----BEGIN");
  if (i == std::string::npos) return std::nullopt;
  i = pem.find('\n', i);
  if (i == std::string::npos) return std::nullopt;
  i++;
  std::size_t end = pem.find("-----END", i);
  if (end == std::string::npos) return std::nullopt;
  std::string b64;
  for (; i < end; i++) {
    char c = pem[i];
    if (c != '\n' && c != '\r' && c != ' ' && c != '\t') b64.push_back(c);
  }
  if (b64.empty()) return std::nullopt;
  auto raw = jose::b64::decode(b64);
  if (!raw) return std::nullopt;
  return *raw;
}

/** 解析 SPKI(PUBLIC KEY)或 PKCS#1 公钥(RSA PUBLIC KEY)的 DER */
inline bool parsePublicDer(const std::uint8_t* der, std::size_t len, BigInt& n, BigInt& e) {
  Reader r{der, len};
  std::uint8_t tag;
  const std::uint8_t* seq;
  std::size_t slen;
  if (!r.readTlv(tag, seq, slen) || tag != 0x30) return false;
  Reader s{seq, slen};
  // 可能是 SPKI:SEQUENCE{ SEQUENCE{OID,...}, BIT STRING{...} } 或 PKCS#1:SEQUENCE{INTEGER,INTEGER}
  std::uint8_t t2;
  const std::uint8_t* v2;
  std::size_t l2;
  if (!s.readTlv(t2, v2, l2)) return false;
  if (t2 == 0x30) {
    // SPKI:跳过算法标识符
    std::uint8_t tskip;
    const std::uint8_t* dummy;
    std::size_t dl;
    Reader alg{v2, l2};
    if (!alg.readTlv(tskip, dummy, dl)) return false;
    if (!alg.readTlv(tskip, dummy, dl)) return false;  // 参数(NULL)
    // BIT STRING
    std::uint8_t t3;
    const std::uint8_t* v3;
    std::size_t l3;
    if (!s.readTlv(t3, v3, l3) || t3 != 0x03) return false;
    // 跳过 unused bits 字节,内容应为 RSAPublicKey SEQUENCE
    if (l3 < 1) return false;
    Reader bit{v3 + 1, l3 - 1};
    std::uint8_t t4;
    const std::uint8_t* v4;
    std::size_t l4;
    if (!bit.readTlv(t4, v4, l4) || t4 != 0x30) return false;
    Reader rs{v4, l4};
    if (!rs.readTlv(t4, v4, l4) || t4 != 0x02) return false;
    n = bn::fromBytes(v4, l4);
    if (!rs.readTlv(t4, v4, l4) || t4 != 0x02) return false;
    e = bn::fromBytes(v4, l4);
    return !n.isZero() && !e.isZero();
  } else if (t2 == 0x02) {
    // PKCS#1:INTEGER n, INTEGER e
    n = bn::fromBytes(v2, l2);
    if (!s.readTlv(t2, v2, l2) || t2 != 0x02) return false;
    e = bn::fromBytes(v2, l2);
    return !n.isZero() && !e.isZero();
  }
  return false;
}

/** 解析私钥 DER(PKCS#1 RSA PRIVATE KEY 或 PKCS#8 PRIVATE KEY),取 n,e,d */
inline bool parsePrivateDer(const std::uint8_t* der, std::size_t len, BigInt& n, BigInt& e,
                            BigInt& d) {
  Reader r{der, len};
  std::uint8_t tag;
  const std::uint8_t* seq;
  std::size_t slen;
  if (!r.readTlv(tag, seq, slen) || tag != 0x30) return false;
  Reader s{seq, slen};
  std::uint8_t t2;
  const std::uint8_t* v2;
  std::size_t l2;
  if (!s.readTlv(t2, v2, l2) || t2 != 0x02) return false;  // version INTEGER
  if (!s.readTlv(t2, v2, l2)) return false;
  if (t2 == 0x30) {
    // PKCS#8:SEQUENCE{ INTEGER 0, SEQUENCE{algid}, OCTET STRING{PKCS#1} }
    // 已读 algid,下一个应为 OCTET STRING
    if (!s.readTlv(t2, v2, l2) || t2 != 0x04) return false;
    return parsePrivateDer(v2, l2, n, e, d);
  }
  // PKCS#1:version 后接 INTEGER n, INTEGER e, INTEGER d
  if (t2 != 0x02) return false;
  n = bn::fromBytes(v2, l2);
  if (!s.readTlv(t2, v2, l2) || t2 != 0x02) return false;
  e = bn::fromBytes(v2, l2);
  if (!s.readTlv(t2, v2, l2) || t2 != 0x02) return false;
  d = bn::fromBytes(v2, l2);
  return !n.isZero() && !e.isZero() && !d.isZero();
}

}  // namespace der

/** 从 PEM 字符串解析密钥(自动识别公钥/私钥) */
inline std::optional<RsaKey> parsePem(const std::string& pem) {
  auto der = der::pemDecode(pem);
  if (!der) return std::nullopt;
  RsaKey k;
  if (der::parsePrivateDer(der->data(), der->size(), k.n, k.e, k.d)) return k;
  if (der::parsePublicDer(der->data(), der->size(), k.n, k.e)) return k;
  return std::nullopt;
}

/** 从 JWK JSON 解析(RSA 公钥或私钥) */
inline std::optional<RsaKey> parseJwk(const std::string& jsonText) {
  Json j;
  JsonParser parser(jsonText);
  if (!parser.parse(j) || j.type != Json::OBJ) return std::nullopt;
  RsaKey k;
  auto get = [&](const char* name, BigInt& out) -> bool {
    for (auto& [key, val] : j.obj) {
      if (key == name && val.type == Json::STR) {
        auto raw = jose::b64::decode(val.str);
        if (!raw) return false;
        out = bn::fromBytes(raw->data(), raw->size());
        return true;
      }
    }
    return false;
  };
  if (!get("n", k.n)) return std::nullopt;
  if (!get("e", k.e)) return std::nullopt;
  get("d", k.d);
  return k;
}

}  // namespace jose::rsa
