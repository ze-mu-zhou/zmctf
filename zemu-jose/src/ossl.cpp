/** ossl.cpp — OpenSSL 桥接实现。链接 -lcrypto。
 * EC JWK 手动构造(避免依赖 OSSL_DECODER 的 JWK 支持版本差异):
 * crv P-256/384/521,x,y,d → EC_KEY → EVP_PKEY。
 */
#include "ossl.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstring>
#include <memory>

#include "b64.h"
#include "json_mini.h"

namespace jose::ossl {

namespace {

struct PkeyDeleter {
  void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

struct MdCtxDeleter {
  void operator()(EVP_MD_CTX* c) const { if (c) EVP_MD_CTX_free(c); }
};
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

const EVP_MD* mdFor(int hashBits) {
  return hashBits == 256 ? EVP_sha256() : (hashBits == 384 ? EVP_sha384() : EVP_sha512());
}

/** JWK 取 base64url 字段 */
bool jwkField(const Json& j, const char* name, std::vector<std::uint8_t>& out) {
  if (j.type != Json::OBJ) return false;
  for (auto& [k, v] : j.obj) {
    if (k == name && v.type == Json::STR) {
      auto d = b64::decode(v.str);
      if (!d) return false;
      out = *d;
      return true;
    }
  }
  return false;
}

bool parseJwkJson(const std::string& jsonText, Json& j) {
  JsonParser parser(jsonText);
  return parser.parse(j) && j.type == Json::OBJ;
}

/** crv 名 → EC 曲线 NID */
int curveNid(const std::string& crv) {
  if (crv == "P-256") return NID_X9_62_prime256v1;
  if (crv == "P-384") return NID_secp384r1;
  if (crv == "P-521") return NID_secp521r1;
  return NID_undef;
}

}  // namespace

void freeKey(void* key) {
  if (key) EVP_PKEY_free((EVP_PKEY*)key);
}

void* loadPemKey(const std::string& pem, bool wantPrivate) {
  BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
  if (!bio) return nullptr;
  EVP_PKEY* key = nullptr;
  if (wantPrivate)
    key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  if (!key)
    key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return key;
}

void* loadEcJwk(const std::string& jsonText, bool wantPrivate) {
  Json j;
  if (!parseJwkJson(jsonText, j)) return nullptr;
  std::string crv;
  for (auto& [k, v] : j.obj)
    if (k == "crv" && v.type == Json::STR) crv = v.str;
  int nid = curveNid(crv);
  if (nid == NID_undef) return nullptr;
  std::vector<std::uint8_t> x, y, d;
  if (!jwkField(j, "x", x) || !jwkField(j, "y", y)) return nullptr;
  EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
  if (!ec) return nullptr;
  BN_CTX* ctx = BN_CTX_new();
  bool ok = false;
  if (ctx) {
    BIGNUM* bx = BN_bin2bn(x.data(), (int)x.size(), nullptr);
    BIGNUM* by = BN_bin2bn(y.data(), (int)y.size(), nullptr);
    if (bx && by) {
      EC_POINT* pt = EC_POINT_new(EC_KEY_get0_group(ec));
      if (pt && EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec), pt, bx, by, ctx) &&
          EC_KEY_set_public_key(ec, pt)) {
        ok = true;
      }
      if (pt) EC_POINT_free(pt);
    }
    if (bx) BN_free(bx);
    if (by) BN_free(by);
    BN_CTX_free(ctx);
  }
  if (ok && wantPrivate) {
    std::vector<std::uint8_t> dbytes;
    if (jwkField(j, "d", dbytes)) {
      BIGNUM* bd = BN_bin2bn(dbytes.data(), (int)dbytes.size(), nullptr);
      if (bd && EC_KEY_set_private_key(ec, bd)) {
        // 校验 d 与公钥匹配(可选,直接信任)
        ok = true;
      } else {
        ok = false;
      }
      if (bd) BN_free(bd);
    } else {
      ok = false;
    }
  }
  if (!ok) {
    EC_KEY_free(ec);
    return nullptr;
  }
  EVP_PKEY* key = EVP_PKEY_new();
  if (!key || EVP_PKEY_assign_EC_KEY(key, ec) <= 0) {
    if (key) EVP_PKEY_free(key);
    EC_KEY_free(ec);
    return nullptr;
  }
  return key;
}

void* loadOkpJwk(const std::string& jsonText, bool wantPrivate) {
  Json j;
  if (!parseJwkJson(jsonText, j)) return nullptr;
  std::string kty, crv;
  for (auto& [k, v] : j.obj) {
    if (k == "kty" && v.type == Json::STR) kty = v.str;
    if (k == "crv" && v.type == Json::STR) crv = v.str;
  }
  if (kty != "OKP") return nullptr;
  int nid = NID_undef;
  if (crv == "Ed25519") nid = NID_ED25519;
  else if (crv == "Ed448") nid = NID_ED448;
  if (nid == NID_undef) return nullptr;
  std::vector<std::uint8_t> x, d;
  if (!jwkField(j, "x", x)) return nullptr;
  EVP_PKEY* key = EVP_PKEY_new_raw_public_key(nid, nullptr, x.data(), x.size());
  if (!key) return nullptr;
  if (wantPrivate) {
    if (!jwkField(j, "d", d)) {
      EVP_PKEY_free(key);
      return nullptr;
    }
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(nid, nullptr, d.data(), d.size());
    EVP_PKEY_free(key);
    if (!priv) return nullptr;
    return priv;
  }
  return key;
}

int verifyEs(void* pkey, int hashBits, const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sig, std::size_t siglen) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) return -1;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, mdFor(hashBits), nullptr, (EVP_PKEY*)pkey) <= 0)
    return -1;
  // JWT ES* 签名是 raw r||s,OpenSSL ECDSA 是 DER —— 转 DER
  std::size_t coord = siglen / 2;
  if (coord == 0) return -1;
  BIGNUM* r = BN_bin2bn(sig, (int)coord, nullptr);
  BIGNUM* s = BN_bin2bn(sig + coord, (int)coord, nullptr);
  if (!r || !s) { if (r) BN_free(r); if (s) BN_free(s); return -1; }
  ECDSA_SIG* esig = ECDSA_SIG_new();
  if (!esig || !ECDSA_SIG_set0(esig, r, s)) {
    if (esig) ECDSA_SIG_free(esig);
    BN_free(r); BN_free(s);
    return -1;
  }
  int rc = -1;
  unsigned char* der = nullptr;
  int derlen = i2d_ECDSA_SIG(esig, &der);
  if (derlen > 0) {
    rc = EVP_DigestVerify(ctx.get(), der, (size_t)derlen, msg, mlen);
  }
  if (der) OPENSSL_free(der);
  ECDSA_SIG_free(esig);
  return rc == 1 ? 0 : (rc == 0 ? 1 : -1);
}

int signEs(void* pkey, int hashBits, const std::uint8_t* msg, std::size_t mlen,
           std::vector<std::uint8_t>& sigOut) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) return -1;
  if (EVP_DigestSignInit(ctx.get(), nullptr, mdFor(hashBits), nullptr, (EVP_PKEY*)pkey) <= 0)
    return -1;
  std::size_t derlen = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &derlen, msg, mlen) <= 0) return -1;
  std::vector<std::uint8_t> der(derlen);
  if (EVP_DigestSign(ctx.get(), der.data(), &derlen, msg, mlen) <= 0) return -1;
  // DER → raw r||s
  const unsigned char* p = der.data();
  ECDSA_SIG* esig = d2i_ECDSA_SIG(nullptr, &p, (long)derlen);
  if (!esig) return -1;
  const BIGNUM* r;
  const BIGNUM* s;
  ECDSA_SIG_get0(esig, &r, &s);
  // JWA:坐标长度由曲线固定(ES256→32,ES384→48,ES512→66),
  // 不能按 r/s 实际位数取(前导零时会产出短签名,验签方拒绝)
  std::size_t coord = hashBits == 256 ? 32 : (hashBits == 384 ? 48 : 66);
  sigOut.assign(coord * 2, 0);
  BN_bn2binpad(r, sigOut.data(), (int)coord);
  BN_bn2binpad(s, sigOut.data() + coord, (int)coord);
  ECDSA_SIG_free(esig);
  return 0;
}

int verifyEddsa(void* pkey, const std::uint8_t* msg, std::size_t mlen,
                const std::uint8_t* sig, std::size_t siglen) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) return -1;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey) <= 0)
    return -1;
  int rc = EVP_DigestVerify(ctx.get(), sig, siglen, msg, mlen);
  return rc == 1 ? 0 : (rc == 0 ? 1 : -1);
}

int signEddsa(void* pkey, const std::uint8_t* msg, std::size_t mlen,
              std::vector<std::uint8_t>& sigOut) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) return -1;
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, (EVP_PKEY*)pkey) <= 0)
    return -1;
  std::size_t siglen = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &siglen, msg, mlen) <= 0) return -1;
  sigOut.resize(siglen);
  if (EVP_DigestSign(ctx.get(), sigOut.data(), &siglen, msg, mlen) <= 0) return -1;
  sigOut.resize(siglen);
  return 0;
}

std::optional<std::vector<std::uint8_t>> jweDirDecrypt(
    int keyBits, const std::uint8_t* key, std::size_t keylen,
    const std::uint8_t* iv, std::size_t ivlen,
    const std::uint8_t* aad, std::size_t aadlen,
    const std::uint8_t* ct, std::size_t ctlen,
    const std::uint8_t* tag, std::size_t taglen) {
  const EVP_CIPHER* ciph = nullptr;
  if (keyBits == 128) ciph = EVP_aes_128_gcm();
  else if (keyBits == 192) ciph = EVP_aes_192_gcm();
  else if (keyBits == 256) ciph = EVP_aes_256_gcm();
  if (!ciph || keylen != (std::size_t)keyBits / 8) return std::nullopt;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return std::nullopt;
  std::vector<std::uint8_t> out(ctlen + 16);
  int outl = 0, fin = 0;
  bool ok = false;
  if (EVP_DecryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen, nullptr) == 1 &&
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
      EVP_DecryptUpdate(ctx, nullptr, &outl, aad, (int)aadlen) == 1 &&
      EVP_DecryptUpdate(ctx, out.data(), &outl, ct, (int)ctlen) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)taglen, (void*)tag) == 1 &&
      EVP_DecryptFinal_ex(ctx, out.data() + outl, &fin) == 1) {
    out.resize((std::size_t)outl + (std::size_t)fin);
    ok = true;
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return std::nullopt;
  return out;
}

}  // namespace jose::ossl
