#include "md5_avx512.hpp"

#if defined(ZM_HASH_AVX512_COMPILED) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86))
#include <cstring>
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {

constexpr std::array<std::uint32_t, 64> K = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

constexpr std::array<unsigned, 64> SHIFT = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// One MD5 compression over 16 lanes; h carries the chaining state in and out.
void transform_16(const __m512i m[16], __m512i h[4]) noexcept {
  __m512i a = h[0], b = h[1], c = h[2], d = h[3];
  for (unsigned i = 0; i != 64; ++i) {
    __m512i f, g;
    if (i < 16) { f = _mm512_or_si512(_mm512_and_si512(b, c), _mm512_andnot_si512(b, d)); g = m[i]; }
    else if (i < 32) { f = _mm512_or_si512(_mm512_and_si512(d, b), _mm512_andnot_si512(d, c)); g = m[(5 * i + 1) & 15]; }
    else if (i < 48) { f = _mm512_xor_si512(_mm512_xor_si512(b, c), d); g = m[(3 * i + 5) & 15]; }
    else { f = _mm512_xor_si512(c, _mm512_or_si512(b, _mm512_xor_si512(d, _mm512_set1_epi32(~0u)))); g = m[(7 * i) & 15]; }
    const auto sum = _mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(a, f), _mm512_set1_epi32(K[i])), g);
    const auto rotated = _mm512_or_si512(_mm512_slli_epi32(sum, SHIFT[i]), _mm512_srli_epi32(sum, 32 - SHIFT[i]));
    const auto next = _mm512_add_epi32(b, rotated);
    a = d; d = c; c = b; b = next;
  }
  h[0] = _mm512_add_epi32(h[0], a);
  h[1] = _mm512_add_epi32(h[1], b);
  h[2] = _mm512_add_epi32(h[2], c);
  h[3] = _mm512_add_epi32(h[3], d);
}

// hashcat hc_bytealign (inc_common.cl): (b << 8*(c&3)) | (a >> (32 - 8*(c&3)))
__m512i bytealign(__m512i a, __m512i b, unsigned c) noexcept {
  const unsigned s = (c & 3u) * 8u;
  if (s == 0) return b;
  return _mm512_or_si512(_mm512_slli_epi32(b, s), _mm512_srli_epi32(a, 32 - s));
}

// hashcat switch_buffer_by_offset_le: shift the 64-byte buffer right by `offset` bytes
void switch_buffer_by_offset(__m512i w[16], unsigned offset) noexcept {
  const unsigned words = offset / 4;
  const __m512i z = _mm512_setzero_si512();
  __m512i t[16];
  for (int i = 15; i >= 0; --i) {
    const int src = i - static_cast<int>(words);
    const __m512i b = src >= 0 ? w[src] : z;
    const __m512i a = src >= 1 ? w[src - 1] : z;
    t[i] = bytealign(a, b, offset);
  }
  std::memcpy(w, t, sizeof t);
}

// hashcat switch_buffer_by_offset_carry_le: same shift, overflow lands in c
void switch_buffer_by_offset_carry(__m512i w[16], __m512i c[16], unsigned offset) noexcept {
  const unsigned words = offset / 4;
  const __m512i z = _mm512_setzero_si512();
  __m512i t[32];
  for (int i = 31; i >= 0; --i) {
    const int src = i - static_cast<int>(words);
    const __m512i b = (src >= 0 && src < 16) ? w[src] : z;
    const __m512i a = (src >= 1 && src <= 16) ? w[src - 1] : z;
    t[i] = bytealign(a, b, offset);
  }
  std::memcpy(w, t, 16 * sizeof(__m512i));
  std::memcpy(c, t + 16, 16 * sizeof(__m512i));
}

void load_h(const Md5Avx512Ctx &ctx, __m512i h[4]) noexcept {
  for (unsigned i = 0; i != 4; ++i) h[i] = _mm512_load_si512(ctx.h.data() + i * 16);
}

void store_h(Md5Avx512Ctx &ctx, const __m512i h[4]) noexcept {
  for (unsigned i = 0; i != 4; ++i) _mm512_store_si512(ctx.h.data() + i * 16, h[i]);
}

} // namespace

void md5_avx512_transform_blocks(const std::uint32_t *mw, std::size_t blocks,
                                 std::uint32_t *h_out) noexcept {
  __m512i h[4] = {_mm512_set1_epi32(0x67452301u), _mm512_set1_epi32(0xefcdab89u),
                  _mm512_set1_epi32(0x98badcfeu), _mm512_set1_epi32(0x10325476u)};
  __m512i m[16];
  for (std::size_t block = 0; block != blocks; ++block) {
    for (unsigned word = 0; word != 16; ++word)
      m[word] = _mm512_loadu_si512(mw + block * 256 + word * 16);
    transform_16(m, h);
  }
  for (unsigned word = 0; word != 4; ++word) _mm512_storeu_si512(h_out + word * 16, h[word]);
}

std::uint32_t md5_avx512_match_mask(const std::uint32_t *h, const Md5Avx512Match &m) noexcept {
  __mmask16 r = 0xffff;
  for (unsigned b = 0; b != 16 && r; ++b) {
    if (!m.mask[b]) continue;
    const __m512i v = _mm512_and_si512(
        _mm512_srli_epi32(_mm512_loadu_si512(h + (b / 4) * 16), 8 * (b % 4)),
        _mm512_set1_epi32(0xff));
    const __mmask16 eq = _mm512_cmpeq_epi32_mask(
        _mm512_and_si512(v, _mm512_set1_epi32(m.mask[b])),
        _mm512_set1_epi32(m.value[b] & m.mask[b]));
    r &= eq;
  }
  return r;
}

std::uint32_t md5_avx512_php_magic_mask(const std::uint32_t *h) noexcept {
  const __m512i w0 = _mm512_loadu_si512(h);
  __mmask16 r = _mm512_cmpeq_epi32_mask(_mm512_and_si512(w0, _mm512_set1_epi32(0xff)),
                                        _mm512_set1_epi32(0x0e));
  const __m512i nine = _mm512_set1_epi32(9);
  for (unsigned b = 1; b != 16 && r; ++b) {
    const __m512i v = _mm512_and_si512(
        _mm512_srli_epi32(_mm512_loadu_si512(h + (b / 4) * 16), 8 * (b % 4)),
        _mm512_set1_epi32(0xff));
    r &= _mm512_cmple_epu32_mask(_mm512_srli_epi32(v, 4), nine) &
         _mm512_cmple_epu32_mask(_mm512_and_si512(v, _mm512_set1_epi32(0xf)), nine);
  }
  return r;
}

void md5_avx512_init(Md5Avx512Ctx &ctx) noexcept {
  ctx.len = 0;
  ctx.w.fill(0);
  for (unsigned lane = 0; lane != 16; ++lane) {
    ctx.h[0 * 16 + lane] = 0x67452301u;
    ctx.h[1 * 16 + lane] = 0xefcdab89u;
    ctx.h[2 * 16 + lane] = 0x98badcfeu;
    ctx.h[3 * 16 + lane] = 0x10325476u;
  }
}

void md5_avx512_update_64(Md5Avx512Ctx &ctx, const std::uint32_t *words, std::uint32_t len) noexcept {
  if (len == 0) return;
  __m512i h[4], in[16];
  load_h(ctx, h);
  for (unsigned i = 0; i != 16; ++i) in[i] = _mm512_load_si512(words + i * 16);
  const unsigned pos = static_cast<unsigned>(ctx.len & 63u);
  ctx.len += len;
  if (pos == 0) {
    if (len == 64) {
      transform_16(in, h);
      ctx.w.fill(0);
    } else {
      for (unsigned i = 0; i != 16; ++i) _mm512_store_si512(ctx.w.data() + i * 16, in[i]);
    }
  } else if (pos + len < 64) {
    switch_buffer_by_offset(in, pos);
    for (unsigned i = 0; i != 16; ++i)
      _mm512_store_si512(ctx.w.data() + i * 16,
                         _mm512_or_si512(_mm512_load_si512(ctx.w.data() + i * 16), in[i]));
  } else {
    __m512i w[16], carry[16];
    for (unsigned i = 0; i != 16; ++i) carry[i] = _mm512_setzero_si512();
    switch_buffer_by_offset_carry(in, carry, pos);
    for (unsigned i = 0; i != 16; ++i)
      w[i] = _mm512_or_si512(_mm512_load_si512(ctx.w.data() + i * 16), in[i]);
    transform_16(w, h);
    for (unsigned i = 0; i != 16; ++i) _mm512_store_si512(ctx.w.data() + i * 16, carry[i]);
  }
  store_h(ctx, h);
}

void md5_avx512_final(Md5Avx512Ctx &ctx) noexcept {
  __m512i h[4], w[16];
  load_h(ctx, h);
  for (unsigned i = 0; i != 16; ++i) w[i] = _mm512_load_si512(ctx.w.data() + i * 16);
  const unsigned pos = static_cast<unsigned>(ctx.len & 63u);
  w[pos / 4] = _mm512_or_si512(w[pos / 4], _mm512_set1_epi32(static_cast<int>(0x80u << (8 * (pos % 4)))));
  if (pos >= 56) {
    transform_16(w, h);
    for (unsigned i = 0; i != 16; ++i) w[i] = _mm512_setzero_si512();
  }
  const std::uint64_t bits = ctx.len * 8;
  w[14] = _mm512_set1_epi32(static_cast<std::uint32_t>(bits));
  w[15] = _mm512_set1_epi32(static_cast<std::uint32_t>(bits >> 32));
  transform_16(w, h);
  store_h(ctx, h);
}

void md5_avx512_store(const Md5Avx512Ctx &ctx, std::array<Md5Digest, 16> &outputs) noexcept {
  for (unsigned lane = 0; lane != 16; ++lane) {
    auto &out = outputs[lane];
    for (unsigned word = 0; word != 4; ++word) {
      const auto v = ctx.h[word * 16 + lane];
      out[word * 4 + 0] = static_cast<std::uint8_t>(v);
      out[word * 4 + 1] = static_cast<std::uint8_t>(v >> 8);
      out[word * 4 + 2] = static_cast<std::uint8_t>(v >> 16);
      out[word * 4 + 3] = static_cast<std::uint8_t>(v >> 24);
    }
  }
}

bool md5_avx512_available() noexcept {
#if defined(_MSC_VER)
  int regs[4]{};
  __cpuid(regs, 0);
  if (static_cast<unsigned>(regs[0]) < 7) return false;
  __cpuidex(regs, 7, 0);
  if ((regs[1] & (1 << 16)) == 0) return false;
  return (_xgetbv(0) & 0xe6u) == 0xe6u;
#else
  __builtin_cpu_init();
  return __builtin_cpu_supports("avx512f") != 0;
#endif
}

#else

void md5_avx512_transform_blocks(const std::uint32_t *, std::size_t, std::uint32_t *) noexcept {}
std::uint32_t md5_avx512_match_mask(const std::uint32_t *, const Md5Avx512Match &) noexcept { return 0; }
std::uint32_t md5_avx512_php_magic_mask(const std::uint32_t *) noexcept { return 0; }
void md5_avx512_init(Md5Avx512Ctx &) noexcept {}
void md5_avx512_update_64(Md5Avx512Ctx &, const std::uint32_t *, std::uint32_t) noexcept {}
void md5_avx512_final(Md5Avx512Ctx &) noexcept {}
void md5_avx512_store(const Md5Avx512Ctx &, std::array<Md5Digest, 16> &) noexcept {}
bool md5_avx512_available() noexcept { return false; }

#endif
