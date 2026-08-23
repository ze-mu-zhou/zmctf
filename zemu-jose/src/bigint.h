/** bigint.h — 无符号任意精度整数(小端 limb 序,uint32 基底 2^32)。
 * 实现:加减乘除(mod)、二进制模幂。与 Python int / cryptography 输出完全对拍,
 * 见 tests/vectest.cpp + tests/ref.py。
 */
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace jose::bn {

using Limb = std::uint32_t;
using Wide = std::uint64_t;

struct BigInt {
  std::vector<Limb> v;  // 小端 limb 序,无前导零(0 = 空)

  BigInt() = default;
  BigInt(std::uint64_t x) {
    if (x) {
      v.push_back((Limb)(x & 0xffffffffu));
      if (x >> 32) v.push_back((Limb)(x >> 32));
    }
  }
  BigInt(std::vector<Limb>&& l) : v(std::move(l)) { trim(); }

  void trim() {
    while (!v.empty() && v.back() == 0) v.pop_back();
  }
  bool isZero() const { return v.empty(); }
  std::size_t bits() const {
    if (isZero()) return 0;
    return (v.size() - 1) * 32 + (32 - __builtin_clz(v.back()));
  }
  std::string hex() const {
    if (isZero()) return "0";
    std::string s;
    for (auto it = v.rbegin(); it != v.rend(); ++it) {
      char buf[9];
      std::snprintf(buf, sizeof buf, "%08x", *it);
      s += buf;
    }
    // 去掉前导零
    std::size_t i = 0;
    while (i + 1 < s.size() && s[i] == '0') i++;
    return s.substr(i);
  }
};

inline int cmp(const BigInt& a, const BigInt& b) {
  if (a.v.size() != b.v.size()) return a.v.size() < b.v.size() ? -1 : 1;
  for (std::size_t i = a.v.size(); i-- > 0;) {
    if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
  }
  return 0;
}

/** a + b(无符号) */
inline BigInt add(const BigInt& a, const BigInt& b) {
  BigInt r;
  r.v.resize(std::max(a.v.size(), b.v.size()) + 1, 0);
  Wide carry = 0;
  for (std::size_t i = 0; i < r.v.size(); i++) {
    Wide s = carry;
    if (i < a.v.size()) s += a.v[i];
    if (i < b.v.size()) s += b.v[i];
    r.v[i] = (Limb)s;
    carry = s >> 32;
  }
  r.trim();
  return r;
}

/** a - b(要求 a >= b) */
inline BigInt sub(const BigInt& a, const BigInt& b) {
  BigInt r;
  r.v.resize(a.v.size(), 0);
  std::int64_t borrow = 0;
  for (std::size_t i = 0; i < a.v.size(); i++) {
    std::int64_t s = (std::int64_t)a.v[i] - (i < b.v.size() ? (std::int64_t)b.v[i] : 0) - borrow;
    if (s < 0) { s += (std::int64_t)1 << 32; borrow = 1; }
    else borrow = 0;
    r.v[i] = (Limb)s;
  }
  r.trim();
  return r;
}

/** a * b(学校乘法) */
inline BigInt mul(const BigInt& a, const BigInt& b) {
  if (a.isZero() || b.isZero()) return BigInt{};
  BigInt r;
  r.v.assign(a.v.size() + b.v.size(), 0);
  for (std::size_t i = 0; i < a.v.size(); i++) {
    Wide carry = 0;
    for (std::size_t j = 0; j < b.v.size(); j++) {
      Wide cur = (Wide)a.v[i] * b.v[j] + r.v[i + j] + carry;
      r.v[i + j] = (Limb)cur;
      carry = cur >> 32;
    }
    std::size_t k = i + b.v.size();
    while (carry) {
      Wide cur = (Wide)r.v[k] + carry;
      r.v[k] = (Limb)cur;
      carry = cur >> 32;
      k++;
    }
  }
  r.trim();
  return r;
}

/** 左移 1 bit(就地)*/
inline void shl1(BigInt& a) {
  if (a.isZero()) return;
  Wide carry = 0;
  for (auto& l : a.v) {
    Wide nv = ((Wide)l << 1) | carry;
    l = (Limb)nv;
    carry = nv >> 32;
  }
  if (carry) a.v.push_back((Limb)carry);
}

/** 右移 1 bit(就地)*/
inline void shr1(BigInt& a) {
  if (a.isZero()) return;
  for (std::size_t i = 0; i < a.v.size(); i++) {
    Limb lo = (i + 1 < a.v.size()) ? a.v[i + 1] : 0;
    a.v[i] = (a.v[i] >> 1) | (lo << 31);
  }
  a.trim();
}

/** 判断第 b 位是否为 1 */
inline bool testBit(const BigInt& a, std::size_t b) {
  std::size_t limb = b >> 5, off = b & 31;
  return limb < a.v.size() && ((a.v[limb] >> off) & 1);
}

inline void divmod(const BigInt& a, const BigInt& b, BigInt& q, BigInt& r);  // fwd

/** 二进制模幂:a^e mod m(m 非零)*/
inline BigInt modpow(const BigInt& a, const BigInt& e, const BigInt& m) {
  BigInt result{1};
  if (m.isZero()) return BigInt{};
  BigInt base = a;
  // base = a mod m
  if (cmp(base, m) >= 0) {
    BigInt q, r;
    divmod(base, m, q, r);
    base = r;
  }
  for (std::size_t i = 0; i < e.bits(); i++) {
    if (testBit(e, i)) {
      result = mul(result, base);
      BigInt q, r;
      divmod(result, m, q, r);
      result = r;
    }
    base = mul(base, base);
    BigInt q, r;
    divmod(base, m, q, r);
    base = r;
  }
  return result;
}

/** 长除法:a / b 和 a % b(基于按位长除)*/
inline void divmod(const BigInt& a, const BigInt& b, BigInt& q, BigInt& r) {
  q = BigInt{};
  r = BigInt{};
  if (b.isZero()) return;  // 除零:调用方应避免
  if (cmp(a, b) < 0) { r = a; return; }
  std::size_t bits = a.bits();
  for (std::size_t i = bits; i-- > 0;) {
    shl1(r);
    if (testBit(a, i)) {
      if (r.isZero()) r.v.push_back(1);
      else r.v[0] |= 1;
    }
    if (cmp(r, b) >= 0) {
      r = sub(r, b);
      // 置 q 的第 i 位
      std::size_t limb = i >> 5, off = i & 31;
      if (q.v.size() <= limb) q.v.resize(limb + 1, 0);
      q.v[limb] |= (Limb)1 << off;
    }
  }
  q.trim();
  r.trim();
}

/** 从大端字节(可带前导 0)构造 */
inline BigInt fromBytes(const std::uint8_t* p, std::size_t n) {
  BigInt r;
  if (n == 0) return r;
  r.v.resize((n + 3) / 4, 0);
  for (std::size_t i = 0; i < n; i++) {
    std::size_t limb = (n - 1 - i) / 4;
    r.v[limb] |= (Limb)p[i] << (((n - 1 - i) % 4) * 8);
  }
  r.trim();
  return r;
}

/** 序列化为定长大端字节(长度不足补前导零;len=0 返回最短表示) */
inline std::vector<std::uint8_t> toBytes(const BigInt& x, std::size_t len = 0) {
  std::size_t nbits = x.bits();
  std::size_t need = (nbits + 7) / 8;
  if (len < need) len = need;
  std::vector<std::uint8_t> out(len, 0);
  for (std::size_t i = 0; i < x.v.size(); i++) {
    Limb l = x.v[i];
    for (int j = 0; j < 4; j++) {
      std::size_t byte = i * 4 + j;
      if (byte < len) out[len - 1 - byte] = (std::uint8_t)(l >> (j * 8));
    }
  }
  return out;
}

/** 从十六进制字符串构造 */
inline BigInt fromHex(const std::string& h) {
  std::string s = h;
  if (s.size() % 2) s = "0" + s;
  std::vector<std::uint8_t> bytes;
  bytes.reserve(s.size() / 2);
  for (std::size_t i = 0; i < s.size(); i += 2) {
    auto hv = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return 0;
    };
    bytes.push_back((std::uint8_t)((hv(s[i]) << 4) | hv(s[i + 1])));
  }
  return fromBytes(bytes.data(), bytes.size());
}

}  // namespace jose::bn
