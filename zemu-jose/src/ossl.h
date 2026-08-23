/** ossl.h — OpenSSL 桥接:ES* / EdDSA 验签与签名、JWE dir 模式 AES-GCM 解密。
 * 自研部分(sha2/hmac/bigint/rsa)之外的算法委托 OpenSSL 3.x 标准实现,
 * 其结果天然与标准库一致(对拍测试仍覆盖 HS/RS 自研路径)。
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace jose::ossl {

/** 释放 loadPemKey/loadEcJwk/loadOkpJwk 返回的密钥 */
void freeKey(void* key);

/** 从 PEM 文本加载公钥或私钥(EVP_PKEY* 生命周期归调用方,用后 freeKey) */
void* loadPemKey(const std::string& pem, bool wantPrivate);

/** 从 EC JWK 加载公/私钥(EVP_PKEY*) */
void* loadEcJwk(const std::string& jsonText, bool wantPrivate);

/** 从 EdDSA JWK(OKP 类型)加载公/私钥(EVP_PKEY*) */
void* loadOkpJwk(const std::string& jsonText, bool wantPrivate);

/** ES256/384/512 验签(msg 为签名输入原文,sig 为 JWT 的 raw r||s 格式)。
 * 返回 0=通过,1=不通过,负=错误 */
int verifyEs(void* pkey, int hashBits, const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sig, std::size_t siglen);

/** ES256/384/512 签名,输出 raw r||s */
int signEs(void* pkey, int hashBits, const std::uint8_t* msg, std::size_t mlen,
           std::vector<std::uint8_t>& sigOut);

/** EdDSA(Ed25519/Ed448)验签 */
int verifyEddsa(void* pkey, const std::uint8_t* msg, std::size_t mlen,
                const std::uint8_t* sig, std::size_t siglen);

/** EdDSA 签名 */
int signEddsa(void* pkey, const std::uint8_t* msg, std::size_t mlen,
              std::vector<std::uint8_t>& sigOut);

/** JWE dir 模式:AES-GCM(128/192/256)解密。aad = 完整 protected header 原文。
 * tag = 认证标签(16 字节)。返回明文;失败返回 nullopt */
std::optional<std::vector<std::uint8_t>> jweDirDecrypt(int keyBits,
    const std::uint8_t* key, std::size_t keylen,
    const std::uint8_t* iv, std::size_t ivlen,
    const std::uint8_t* aad, std::size_t aadlen,
    const std::uint8_t* ct, std::size_t ctlen,
    const std::uint8_t* tag, std::size_t taglen);

}  // namespace jose::ossl
