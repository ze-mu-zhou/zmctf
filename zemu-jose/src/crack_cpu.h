/** crack_cpu.h — HS* 密钥爆破(字典 + hashcat 风格掩码),CPU 多线程。
 * HS256 走 HmacSha256FixedMsg 预计算热路径(SHA-NI);HS384/512 走流式。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "sha2.h"

namespace jose {

/** hashcat 风格掩码 → 每位的字符集 */
inline bool parseMask(const std::string& mask, std::vector<std::string>& pos) {
  static const std::string L = "abcdefghijklmnopqrstuvwxyz";
  static const std::string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const std::string D = "0123456789";
  static const std::string S = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  static const std::string A = L + U + D + S;
  for (std::size_t i = 0; i < mask.size(); i++) {
    if (mask[i] == '?') {
      if (i + 1 >= mask.size()) return false;
      char t = mask[++i];
      if (t == 'l') pos.push_back(L);
      else if (t == 'u') pos.push_back(U);
      else if (t == 'd') pos.push_back(D);
      else if (t == 's') pos.push_back(S);
      else if (t == 'a') pos.push_back(A);
      else if (t == '?') pos.emplace_back("?");
      else return false;
    } else {
      pos.emplace_back(1, mask[i]);
    }
  }
  return !pos.empty();
}

/** 掩码线性序号 → 候选串(栈上缓冲,无分配)。
 * hashcat 语义:最右位变化最快(序号低位对应掩码末位)。 */
inline void maskUnrank(const std::vector<std::string>& pos, std::uint64_t idx, char* out) {
  for (std::size_t i = pos.size(); i-- > 0;) {
    std::uint64_t size = pos[i].size();
    out[i] = pos[i][idx % size];
    idx /= size;
  }
}

/** 掩码总组合数(溢出返回 UINT64_MAX) */
inline std::uint64_t maskTotal(const std::vector<std::string>& pos) {
  std::uint64_t t = 1;
  for (auto& c : pos) {
    if (c.empty()) return 0;
    if (t > UINT64_MAX / c.size()) return UINT64_MAX;
    t *= c.size();
  }
  return t;
}

/** 爆破共享状态 + HS256 预计算(一次性) */
struct CrackShared {
  static constexpr std::size_t MAX_MASK_LEN = 64;  // 掩码位数上限(buf[64] 栈缓冲)
  int hashBits = 256;
  std::vector<std::uint8_t> expect;                  // 期望签名
  std::vector<std::uint8_t> signingInput;            // header.payload 原文(384/512 流式用)
  const std::vector<std::string>* words = nullptr;   // 字典(可空)
  const std::vector<std::string>* pos = nullptr;     // 掩码(可空)
  std::unique_ptr<sha2::HmacSha256FixedMsg> fm;      // HS256 热路径
  std::atomic<std::uint64_t> attempts{0};
  std::atomic<bool> found{false};
  std::atomic<bool> abort{false};
  std::string foundSecret;
};

/** 尝试一个候选密钥(keyLen ≤ 64),命中则记录 */
inline void tryCandidate(CrackShared& s, const char* key, std::size_t keyLen,
                         std::uint64_t& localCount) {
  if (s.found.load(std::memory_order_relaxed)) return;
  if (s.hashBits == 256) {
    std::uint8_t mac[32];
    s.fm->mac((const std::uint8_t*)key, keyLen, mac);
    if (std::memcmp(mac, s.expect.data(), 32) == 0) {
      bool expected = false;
      if (s.found.compare_exchange_strong(expected, true)) s.foundSecret.assign(key, keyLen);
    }
  } else {
    std::uint8_t mac[64];
    sha2::hmacSha(std::string_view(key, keyLen),
                  std::span<const std::uint8_t>(s.signingInput.data(), s.signingInput.size()),
                  s.hashBits, mac);
    if (std::memcmp(mac, s.expect.data(), s.hashBits / 8) == 0) {
      bool expected = false;
      if (s.found.compare_exchange_strong(expected, true)) s.foundSecret.assign(key, keyLen);
    }
  }
  // 本地计数,每 256 次同步一次(避免原子竞争)
  if ((++localCount & 255) == 0) s.attempts.fetch_add(256, std::memory_order_relaxed);
}

/** 字典区间 [begin, end) */
inline void crackDictRange(CrackShared& s, std::size_t begin, std::size_t end) {
  std::uint64_t local = 0;
  for (std::size_t i = begin; i < end && !s.abort.load(); i++) {
    if (s.found.load(std::memory_order_relaxed)) break;
    const std::string& w = (*s.words)[i];
    tryCandidate(s, w.data(), w.size(), local);
  }
  s.attempts.fetch_add(local & 255, std::memory_order_relaxed);
}

/** 掩码区间 [begin, end)。要求 pos->size() ≤ CrackShared::MAX_MASK_LEN(入口处校验) */
inline void crackMaskRange(CrackShared& s, std::uint64_t begin, std::uint64_t end) {
  std::uint64_t local = 0;
  char buf[CrackShared::MAX_MASK_LEN];
  for (std::uint64_t i = begin; i < end && !s.abort.load(); i++) {
    if (s.found.load(std::memory_order_relaxed)) break;
    maskUnrank(*s.pos, i, buf);
    tryCandidate(s, buf, s.pos->size(), local);
  }
  s.attempts.fetch_add(local & 255, std::memory_order_relaxed);
}

}  // namespace jose
