#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <vector>

// GPU (OpenCL) match search, kernel structure ported from hashcat's
// m00000_a3-optimized: the host decodes each "root" candidate (trailing
// positions) into 16 pre-packed message words; each GPU thread iterates the
// leading bytes (message word 0) via a precomputed OR table with all fixed
// words folded into per-step constants, and exact 128-bit targets early-reject
// after step 47 by reversing round 4 from the digest.
struct GpuMatchParams {
  std::uint32_t length = 0;
  std::vector<std::uint8_t> chars;     // concatenated per-position charsets
  std::vector<std::uint32_t> offsets;  // length + 1 entries
  std::vector<std::uint32_t> radix;    // per position
  std::uint64_t limit = 0;             // candidates to search
  std::array<std::uint32_t, 4> value{};  // digest word match, little-endian words
  std::array<std::uint32_t, 4> mask{};
  std::uint64_t max_hits = 4096;       // hit buffer capacity
  std::atomic<bool> *interrupted = nullptr;
};

struct GpuMatchHit {
  std::uint64_t index;
  std::array<std::uint32_t, 4> digest;
};

struct GpuMatchResult {
  std::vector<GpuMatchHit> hits;
  std::uint64_t hit_total = 0;  // may exceed hits.size() when the buffer capped
  std::uint64_t processed = 0;
  double seconds = 0;
};

bool gpu_available() noexcept;
// Throws std::runtime_error on OpenCL errors.
GpuMatchResult gpu_match(const GpuMatchParams &params);
