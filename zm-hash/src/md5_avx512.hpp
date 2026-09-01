#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

using Md5Digest = std::array<std::uint8_t, 16>;

bool md5_avx512_available() noexcept;

void md5_avx512_16(std::span<const std::array<std::uint8_t, 56>, 16> inputs,
                   std::size_t length,
                   std::array<Md5Digest, 16> &outputs);
