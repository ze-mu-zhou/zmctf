/** b64.h:base64url 编解码(无 '=' 填充,与 itsdangerous 对齐)。 */
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace b64detail {
inline constexpr char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** 解码表:字符 → 6 位值,非法字符 -1(编译期生成) */
consteval std::array<int, 256> makeDecodeTable() {
  std::array<int, 256> t{};
  t.fill(-1);
  for (int i = 0; i < 64; i++) t[(uint8_t)ALPHABET[i]] = i;
  return t;
}
} // namespace b64detail

inline std::string b64urlEncode(const uint8_t* d, size_t n) {
  static constexpr const char* B64 = b64detail::ALPHABET;
  std::string s;
  s.reserve((n + 2) / 3 * 4);
  for (size_t i = 0; i + 3 <= n; i += 3) {
    uint32_t v = (uint32_t)d[i] << 16 | (uint32_t)d[i + 1] << 8 | d[i + 2];
    s += B64[v >> 18]; s += B64[v >> 12 & 63]; s += B64[v >> 6 & 63]; s += B64[v & 63];
  }
  size_t rem = n % 3;
  if (rem) {
    uint32_t v = (uint32_t)d[n - rem] << 16;
    if (rem == 2) v |= (uint32_t)d[n - 1] << 8;
    s += B64[v >> 18]; s += B64[v >> 12 & 63];
    if (rem == 2) s += B64[v >> 6 & 63];
  }
  return s;
}

inline bool b64urlDecode(std::string_view s, std::vector<uint8_t>& out) {
  static constexpr auto tbl = b64detail::makeDecodeTable();
  out.clear();
  // Unpadded Base64 cannot have a single trailing character.
  if ((s.size() & 3u) == 1u) return false;
  uint32_t acc = 0;
  int nbits = 0;
  for (char ch : s) {
    int v = tbl[(uint8_t)ch];
    if (v < 0) return false;
    acc = (acc << 6) | (uint32_t)v;
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      out.push_back((uint8_t)(acc >> nbits));
    }
  }
  // Unused trailing bits must be zero for a canonical encoding.
  if (nbits && (acc & ((1u << nbits) - 1u)) != 0) {
    out.clear();
    return false;
  }
  return true;
}
