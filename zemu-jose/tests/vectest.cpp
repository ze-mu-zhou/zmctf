/** vectest.cpp — zemu-jose 自研算法向量输出(供 tests/ref.py 对拍)。
 * 输出格式:每行 name=hex/string。
 * 覆盖:sha256/384/512、hmac-256/384/512、base64url、大整数模幂、
 * RSA 签名(用固定向量 key 无法自含,RS 部分由 ref.py 侧与 pyjwt 对拍,
 * 这里输出 RS 对拍所需的摘要与签名:见 tests/run_duipai.sh 编排)。
 */
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "b64.h"
#include "bigint.h"
#include "rsa.h"
#include "sha2.h"

using namespace jose;

static std::string hexStr(const std::vector<std::uint8_t>& d) {
  std::string s;
  for (auto b : d) { char buf[4]; std::snprintf(buf, sizeof buf, "%02x", b); s += buf; }
  return s;
}

int main(int argc, char** argv) {
  // 确定性伪随机:与 Python 侧 (i*131+17)%256 完全一致(跨语言可复现)
  auto randBytes = [](int n, std::size_t off = 0) {
    std::vector<std::uint8_t> v(n);
    for (int i = 0; i < n; i++) v[i] = (std::uint8_t)(((std::size_t)(i + off) * 131 + 17) & 0xff);
    return v;
  };

  // SHA-2
  std::size_t seqOff = 0;
  for (int L : {0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000, 65536}) {
    auto d = randBytes(L, seqOff);
    seqOff += L + 7;
    auto s256 = sha2::sha256(d);
    printf("sha256_len%d=%s\n", L, hexStr(s256).c_str());
    std::uint8_t o[64];
    sha2::Sha512 h384(true); h384.update(d.data(), d.size()); h384.final(o);
    printf("sha384_len%d=", L);
    for (int i = 0; i < 48; i++) printf("%02x", o[i]);
    printf("\n");
    sha2::Sha512 h512(false); h512.update(d.data(), d.size()); h512.final(o);
    printf("sha512_len%d=", L);
    for (int i = 0; i < 64; i++) printf("%02x", o[i]);
    printf("\n");
  }

  // HMAC(固定 msg 200 字节)
  for (int klen : {0, 1, 20, 63, 64, 65, 128}) {
    auto key = randBytes(klen, 100000 + klen);
    auto msg = randBytes(200, 200000 + klen);
    for (int bits : {256, 384, 512}) {
      std::uint8_t mac[64];
      sha2::hmacSha(std::string((const char*)key.data(), key.size()),
                    std::span<const std::uint8_t>(msg.data(), msg.size()), bits, mac);
      std::string name = bits == 256 ? "hmac256" : (bits == 384 ? "hmac384" : "hmac512");
      printf("%s_k%d=", name.c_str(), klen);
      for (int i = 0; i < bits / 8; i++) printf("%02x", mac[i]);
      printf("\n");
    }
  }

  // base64url
  for (int L : {0, 1, 2, 3, 4, 5, 6, 7, 8, 100, 1024}) {
    auto d = randBytes(L, 300000 + L);
    printf("b64_len%d=%s\n", L, b64::encode(d).c_str());
  }

  // 大整数模幂(与 Python pow 对拍)
  for (int bits : {256, 512, 1024, 2048}) {
    auto nb = randBytes(bits / 8, 400000 + bits); nb.back() |= 1;
    auto eb = randBytes(bits / 8, 500000 + bits);
    auto ab = randBytes(bits / 8, 600000 + bits);
    bn::BigInt n = bn::fromBytes(nb.data(), nb.size());
    bn::BigInt e = bn::fromBytes(eb.data(), eb.size());
    bn::BigInt a = bn::fromBytes(ab.data(), ab.size());
    printf("modpow_%d=%s\n", bits, bn::modpow(a, e, n).hex().c_str());
  }

  // RSA 对拍:与 ref.py 共用同一密钥 —— 通过命令行参数传递 PEM 路径
  if (argc >= 2) {
    std::string pem;
    {
      FILE* f = fopen(argv[1], "rb");
      if (f) {
        char buf[8192]; size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) pem.append(buf, n);
        fclose(f);
      }
    }
    auto key = rsa::parsePem(pem);
    if (key) {
      const char* msg = "duipai-vector-message";
      for (int bits : {256, 384, 512}) {
        std::vector<std::uint8_t> digest;
        if (bits == 256) digest = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)msg, strlen(msg)));
        else {
          std::uint8_t d[64];
          sha2::Sha512 h(bits == 384);
          h.update((const std::uint8_t*)msg, strlen(msg));
          h.final(d);
          digest.assign(d, d + bits / 8);
        }
        auto sig = rsa::sign(*key, digest, bits);
        std::string name = bits == 256 ? "rs_RS256_sig" : (bits == 384 ? "rs_RS384_sig" : "rs_RS512_sig");
        printf("%s=%s\n", name.c_str(), hexStr(sig).c_str());
        std::string dn = bits == 256 ? "rs_RS256_digest" : (bits == 384 ? "rs_RS384_digest" : "rs_RS512_digest");
        printf("%s=%s\n", dn.c_str(), hexStr(digest).c_str());
        bool v = rsa::verify(*key, digest, bits, sig);
        printf("rs_%s_self_verify=%s\n", name.c_str() + 3, v ? "ok" : "fail");
      }
      // JWK 输出(与 ref.py 的 rsa_jwk 对拍需同 key——由脚本编排)
      printf("rsa_pem_loaded=ok\n");
    } else {
      printf("rsa_pem_loaded=fail\n");
    }
  }

  return 0;
}
