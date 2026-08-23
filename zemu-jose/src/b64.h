/** b64.h — base64url(无填充,JOSE 规范 RFC 7515 附录 C)自研实现。
 * 与标准实现(如 Python base64.urlsafe_b64encode、OpenSSL EVP_EncodeBlock)
 * 输出完全对拍:见 tests/vectest.cpp + tests/ref.py。
 * C++26:constexpr 容器、std::span。
 */
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace jose::b64 {

/** 编码表:标准 base64 + URL-safe 替换 -_ */
inline constexpr std::array<char, 64> ENC = [] {
  std::array<char, 64> t{};
  for (int i = 0; i < 26; i++) t[i] = char('A' + i);
  for (int i = 0; i < 26; i++) t[26 + i] = char('a' + i);
  for (int i = 0; i < 10; i++) t[52 + i] = char('0' + i);
  t[62] = '-';
  t[63] = '_';
  return t;
}();

/** 解码表:URL-safe 变体 -_ 与标准 +/ 均接受(宽松);-1 = 非法字符 */
inline constexpr std::array<int8_t, 256> DEC = [] {
  std::array<int8_t, 256> t{};
  t.fill(-1);
  for (int i = 0; i < 64; i++) t[(uint8_t)ENC[i]] = (int8_t)i;
  t[(uint8_t)'+'] = 62;  // 宽松:接受标准 base64
  t[(uint8_t)'/'] = 63;
  t[(uint8_t)'='] = -2;  // 填充符,跳过
  return t;
}();

/** 编码(无填充)。len=0 返回空串。 */
inline std::string encode(std::span<const uint8_t> data) {
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= data.size(); i += 3) {
    uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8 | data[i + 2];
    out.push_back(ENC[(v >> 18) & 63]);
    out.push_back(ENC[(v >> 12) & 63]);
    out.push_back(ENC[(v >> 6) & 63]);
    out.push_back(ENC[v & 63]);
  }
  size_t rem = data.size() - i;
  if (rem == 1) {
    uint32_t v = (uint32_t)data[i] << 16;
    out.push_back(ENC[(v >> 18) & 63]);
    out.push_back(ENC[(v >> 12) & 63]);
  } else if (rem == 2) {
    uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8;
    out.push_back(ENC[(v >> 18) & 63]);
    out.push_back(ENC[(v >> 12) & 63]);
    out.push_back(ENC[(v >> 6) & 63]);
  }
  return out;
}

inline std::string encode(std::string_view s) {
  return encode(std::span<const uint8_t>((const uint8_t*)s.data(), s.size()));
}

/** 解码(无填充输入)。返回 false 表示非法输入。 */
inline bool decode(std::string_view in, std::vector<uint8_t>& out) {
  out.clear();
  out.reserve(in.size() / 4 * 3 + 3);
  uint32_t acc = 0;
  int nbits = 0;
  for (char c : in) {
    int8_t v = DEC[(uint8_t)c];
    if (v == -2) continue;  // '=' 填充符
    if (v < 0) return false;
    acc = acc << 6 | (uint32_t)v;
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      out.push_back((uint8_t)(acc >> nbits));
      acc &= (1u << nbits) - 1;
    }
  }
  if (nbits >= 6) return false;  // 尾部残留 ≥6 bit:非法(非 4 的倍数)
  return true;
}

/** 便捷解码:成功返回字节,失败返回 nullopt */
inline std::optional<std::vector<uint8_t>> decode(std::string_view in) {
  std::vector<uint8_t> out;
  if (!decode(in, out)) return std::nullopt;
  return out;
}

}  // namespace jose::b64
