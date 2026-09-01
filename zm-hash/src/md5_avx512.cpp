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

} // namespace

void md5_avx512_16(std::span<const std::array<std::uint8_t, 56>, 16> inputs,
                   std::size_t length, std::array<Md5Digest, 16> &outputs) {
  alignas(64) std::uint32_t lane_words[16][16]{};
  for (unsigned lane = 0; lane != 16; ++lane) {
    std::memcpy(lane_words[lane], inputs[lane].data(), length);
    auto *bytes = reinterpret_cast<std::uint8_t *>(lane_words[lane]);
    bytes[length] = 0x80;
    const auto bits = static_cast<std::uint64_t>(length) * 8;
    lane_words[lane][14] = static_cast<std::uint32_t>(bits);
    lane_words[lane][15] = static_cast<std::uint32_t>(bits >> 32);
  }
  __m512i m[16];
  alignas(64) std::uint32_t packed[16];
  for (unsigned word = 0; word != 16; ++word) {
    for (unsigned lane = 0; lane != 16; ++lane) packed[lane] = lane_words[lane][word];
    m[word] = _mm512_load_si512(packed);
  }
  __m512i a = _mm512_set1_epi32(0x67452301u);
  __m512i b = _mm512_set1_epi32(0xefcdab89u);
  __m512i c = _mm512_set1_epi32(0x98badcfeu);
  __m512i d = _mm512_set1_epi32(0x10325476u);
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
  a = _mm512_add_epi32(a, _mm512_set1_epi32(0x67452301u));
  b = _mm512_add_epi32(b, _mm512_set1_epi32(0xefcdab89u));
  c = _mm512_add_epi32(c, _mm512_set1_epi32(0x98badcfeu));
  d = _mm512_add_epi32(d, _mm512_set1_epi32(0x10325476u));
  alignas(64) std::uint32_t state[4][16];
  _mm512_store_si512(state[0], a); _mm512_store_si512(state[1], b);
  _mm512_store_si512(state[2], c); _mm512_store_si512(state[3], d);
  for (unsigned lane = 0; lane != 16; ++lane) {
    auto &out = outputs[lane];
    out[0] = static_cast<std::uint8_t>(state[0][lane]); out[1] = static_cast<std::uint8_t>(state[0][lane] >> 8);
    out[2] = static_cast<std::uint8_t>(state[0][lane] >> 16); out[3] = static_cast<std::uint8_t>(state[0][lane] >> 24);
    out[4] = static_cast<std::uint8_t>(state[1][lane]); out[5] = static_cast<std::uint8_t>(state[1][lane] >> 8);
    out[6] = static_cast<std::uint8_t>(state[1][lane] >> 16); out[7] = static_cast<std::uint8_t>(state[1][lane] >> 24);
    out[8] = static_cast<std::uint8_t>(state[2][lane]); out[9] = static_cast<std::uint8_t>(state[2][lane] >> 8);
    out[10] = static_cast<std::uint8_t>(state[2][lane] >> 16); out[11] = static_cast<std::uint8_t>(state[2][lane] >> 24);
    out[12] = static_cast<std::uint8_t>(state[3][lane]); out[13] = static_cast<std::uint8_t>(state[3][lane] >> 8);
    out[14] = static_cast<std::uint8_t>(state[3][lane] >> 16); out[15] = static_cast<std::uint8_t>(state[3][lane] >> 24);
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

void md5_avx512_16(std::span<const std::array<std::uint8_t, 56>, 16>, std::size_t, std::array<Md5Digest, 16> &) {}
bool md5_avx512_available() noexcept { return false; }

#endif
