#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

using Md5Digest = std::array<std::uint8_t, 16>;

// Streaming multi-block MD5 context for the 16-lane AVX-512 kernel, ported
// from hashcat's md5_ctx_vector_t (OpenCL/inc_hash_md5.cl). Storage is
// word-major: element [word * 16 + lane] holds `word` of lane `lane`.
struct Md5Avx512Ctx {
  alignas(64) std::array<std::uint32_t, 4 * 16> h{};
  alignas(64) std::array<std::uint32_t, 16 * 16> w{};
  std::uint64_t len = 0;
};

// Per-byte match constraints compiled from a digest pattern or target digest.
// mask[b] selects which nibbles of byte b are fixed (0xF0 high, 0x0F low).
struct Md5Avx512Match {
  std::array<std::uint8_t, 16> value{};
  std::array<std::uint8_t, 16> mask{};
};

bool md5_avx512_available() noexcept;

// Chained MD5 over `blocks` 64-byte blocks, 16 lanes at once. `mw` is
// word-major block message words: mw[block * 256 + word * 16 + lane].
// Padding must already be present in `mw`. Writes the 4 digest words per lane
// to h_out[word * 16 + lane].
void md5_avx512_transform_blocks(const std::uint32_t *mw, std::size_t blocks,
                                 std::uint32_t *h_out) noexcept;

// Vectorized digest checks; return a bitmask of matching lanes (bit = lane).
std::uint32_t md5_avx512_match_mask(const std::uint32_t *h, const Md5Avx512Match &m) noexcept;
std::uint32_t md5_avx512_php_magic_mask(const std::uint32_t *h) noexcept;

// Streaming API (hashcat md5_init/md5_update_64/md5_final semantics).
// `words` must be 64-byte aligned and hold 16 little-endian words per lane in
// word-major order (word * 16 + lane); each update carries at most 64 bytes.
void md5_avx512_init(Md5Avx512Ctx &ctx) noexcept;
void md5_avx512_update_64(Md5Avx512Ctx &ctx, const std::uint32_t *words, std::uint32_t len) noexcept;
void md5_avx512_final(Md5Avx512Ctx &ctx) noexcept;
void md5_avx512_store(const Md5Avx512Ctx &ctx, std::array<Md5Digest, 16> &outputs) noexcept;
