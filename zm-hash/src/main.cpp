#include <array>
#include <algorithm>
#include <atomic>
#include <bit>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <condition_variable>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <vector>

#include "md5_avx512.hpp"

#if defined(ZM_HASH_USE_LIBDIVIDE)
#include <libdivide.h>
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

using Digest = Md5Digest;

std::atomic<bool> interrupted{false};

void handle_sigint(int) noexcept {
  interrupted.store(true, std::memory_order_relaxed);
}

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

constexpr std::uint32_t load32(const std::uint8_t *p) noexcept {
  return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
         (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}

constexpr void store32(std::uint8_t *p, std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v);
  p[1] = static_cast<std::uint8_t>(v >> 8);
  p[2] = static_cast<std::uint8_t>(v >> 16);
  p[3] = static_cast<std::uint8_t>(v >> 24);
}

struct Md5Scratch {
  std::array<std::uint8_t, 64> block{};
  std::array<std::uint32_t, 16> words{};
};

using Md5State = std::array<std::uint32_t, 4>;

void compress(Md5State &state, const std::array<std::uint32_t, 16> &m) {
  auto [a0, b0, c0, d0] = state;
  std::uint32_t a = a0, b = b0, c = c0, d = d0;
  for (unsigned i = 0; i != 64; ++i) {
    std::uint32_t f, g;
    if (i < 16) { f = (b & c) | (~b & d); g = i; }
    else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
    else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
    else { f = c ^ (b | ~d); g = (7 * i) & 15; }
    const std::uint32_t next = b + std::rotl(a + f + K[i] + m[g], SHIFT[i]);
    a = d; d = c; c = b; b = next;
  }
  state = {a0 + a, b0 + b, c0 + c, d0 + d};
}

Digest finish(const Md5State &state) {
  Digest out{};
  store32(out.data(), state[0]); store32(out.data() + 4, state[1]);
  store32(out.data() + 8, state[2]); store32(out.data() + 12, state[3]);
  return out;
}

Digest md5(std::span<const std::uint8_t> input, Md5Scratch &scratch) {
  Md5State state = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
  // Most search candidates fit in one MD5 block. On little-endian hosts, write
  // directly into the message words and avoid the generic block loop.
  if (input.size() <= 55 && std::endian::native == std::endian::little) {
    scratch.words.fill(0);
    if (!input.empty()) std::memcpy(scratch.words.data(), input.data(), input.size());
    auto *bytes = reinterpret_cast<std::uint8_t *>(scratch.words.data());
    bytes[input.size()] = 0x80;
    const auto bits = static_cast<std::uint64_t>(input.size()) * 8;
    scratch.words[14] = static_cast<std::uint32_t>(bits);
    scratch.words[15] = static_cast<std::uint32_t>(bits >> 32);
    compress(state, scratch.words);
    return finish(state);
  }

  const std::size_t blocks = (input.size() + 9 + 63) / 64;
  for (std::size_t bi = 0; bi < blocks; ++bi) {
    scratch.block.fill(0);
    const std::size_t begin = bi * 64;
    const std::size_t n = begin < input.size() ? std::min<std::size_t>(64, input.size() - begin) : 0;
    if (n) std::copy_n(input.data() + begin, n, scratch.block.data());
    if (begin + n == input.size() && n < 64) scratch.block[n] = 0x80;
    if (bi + 1 == blocks) {
      const std::uint64_t bits = static_cast<std::uint64_t>(input.size()) * 8;
      for (unsigned i = 0; i != 8; ++i) scratch.block[56 + i] = static_cast<std::uint8_t>(bits >> (8 * i));
    }
    for (unsigned i = 0; i != 16; ++i) scratch.words[i] = load32(scratch.block.data() + i * 4);
    compress(state, scratch.words);
  }
  return finish(state);
}

Digest md5(std::span<const std::uint8_t> input) {
  Md5Scratch scratch;
  return md5(input, scratch);
}

std::string hex(Digest d, bool upper) {
  constexpr char lower[] = "0123456789abcdef";
  constexpr char upper_chars[] = "0123456789ABCDEF";
  const char *digits = upper ? upper_chars : lower;
  std::string out(32, '0');
  for (unsigned i = 0; i != 16; ++i) { out[2 * i] = digits[d[i] >> 4]; out[2 * i + 1] = digits[d[i] & 15]; }
  return out;
}

std::uint64_t digest_checksum(const Digest &digest) noexcept {
  std::uint64_t value = 1469598103934665603ull;
  for (const auto byte : digest) { value ^= byte; value *= 1099511628211ull; }
  return value;
}

struct KeyHash {
  std::size_t operator()(const Digest &d) const noexcept {
    std::size_t h = 1469598103934665603ull;
    for (auto b : d) { h ^= b; h *= 1099511628211ull; }
    return h;
  }
};

struct Seen {
  std::string candidate;
  Digest digest{};
};

unsigned default_thread_count() noexcept {
#ifdef _WIN32
  const auto groups = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  if (groups != 0) return groups;
#endif
  const auto detected = std::thread::hardware_concurrency();
  return std::max(1u, detected);
}

struct Config {
  enum class Mode { Hash, Match, PhpWeak, Prefix, Collision, Benchmark } mode = Mode::Match;
  std::size_t length = 1;
  std::string charset = "lower", custom_charset;
  std::string allow, deny, position_spec, pattern, target;
  unsigned weak_hex = 8;
  unsigned threads = default_thread_count();
  std::uint64_t max_candidates = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t max_output = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t bench_candidates = 5'000'000;
  unsigned bench_repeats = 5;
  unsigned bench_warmup = 1;
  bool upper_output = false;
  bool color = true;
  bool simd = true;
  std::string text;
};

struct Ansi {
  static constexpr std::string_view reset = "\x1b[0m";
  static constexpr std::string_view cyan = "\x1b[36m";
  static constexpr std::string_view green = "\x1b[32m";
  static constexpr std::string_view yellow = "\x1b[33m";
  static constexpr std::string_view red = "\x1b[31m";
};

std::string paint(std::string_view value, std::string_view color, bool enabled) {
  if (!enabled) return std::string(value);
  return std::string(color) + std::string(value) + std::string(Ansi::reset);
}

void enable_terminal_colors() {
#ifdef _WIN32
  for (const DWORD id : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
    const HANDLE output = GetStdHandle(id);
    DWORD mode = 0;
    if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode)) SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
#endif
}

[[noreturn]] void usage_error(std::string_view msg) { throw std::runtime_error(std::string(msg) + "\n请使用 --help 查看选项。"); }

std::uint64_t number(std::string_view s) {
  std::size_t pos = 0; const auto v = std::stoull(std::string(s), &pos, 0);
  if (pos != s.size()) usage_error("无效数字：" + std::string(s));
  return v;
}

void print_help(bool color) {
  std::cout << paint("zm-hash：高性能 C++26 MD5 约束搜索工具", Ansi::cyan, color) << R"(
用法：
  zm-hash --mode hash --text TEXT
  zm-hash --mode match|weak-collision|prefix-collision|collision|benchmark [选项]

选项：
  --length N                 输入长度（默认 1）
  --charset 名称             upper、lower、digits、alnum 或 hex
  --charset-custom 字符      使用自定义输入字符集
  --allow 字符               白名单（与 charset 取交集）
  --deny 字符                黑名单
  --position 位置=字符集     按位置限制，例如 0=AB,1=37,4=xyz
  --digest-pattern 模式      32 位十六进制模式，? 表示任意字符
  --target-digest 摘要       匹配指定的完整 MD5
  --weak-hex N               prefix-collision 比较前 N 个十六进制字符
  --threads N                工作线程数（默认自动使用全部逻辑处理器，0 也是自动）
  --max-candidates N         最多搜索的候选数
  --max-output N             match 模式最多输出的结果数
  --bench-candidates N       benchmark 每轮候选数（默认 5000000）
  --bench-repeats N          benchmark 正式测量轮数（默认 5）
  --bench-warmup N           benchmark 预热轮数（默认 1）
  --output-case upper|lower  摘要输出大小写（默认 lower）
  --no-color                 关闭彩色输出，适合重定向到文件
  --no-simd                  benchmark 强制使用标量路径
  --mode hash|match|weak-collision|prefix-collision|collision|benchmark

weak-collision 使用 PHP magic hash 语义：两个 MD5 都必须匹配 ^0e[0-9]+$。
)";
}

std::vector<std::string> split(std::string_view s, char sep) {
  std::vector<std::string> out; std::size_t start = 0;
  while (start <= s.size()) { auto end = s.find(sep, start); if (end == std::string_view::npos) end = s.size(); out.emplace_back(s.substr(start, end - start)); if (end == s.size()) break; start = end + 1; }
  return out;
}

Config parse(int argc, char **argv) {
  Config c;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    auto value = [&]() -> std::string { if (++i >= argc) usage_error("选项缺少参数：" + std::string(a)); return argv[i]; };
    if (a == "--help" || a == "-h") { print_help(c.color); std::exit(0); }
    else if (a == "--mode") { auto v = value(); if (v == "hash") c.mode = Config::Mode::Hash; else if (v == "match") c.mode = Config::Mode::Match; else if (v == "weak-collision" || v == "php-weak" || v == "0e") c.mode = Config::Mode::PhpWeak; else if (v == "prefix-collision") c.mode = Config::Mode::Prefix; else if (v == "collision") c.mode = Config::Mode::Collision; else if (v == "benchmark" || v == "bench") c.mode = Config::Mode::Benchmark; else usage_error("未知模式：" + v); }
    else if (a == "--length") c.length = number(value());
    else if (a == "--charset") c.charset = value();
    else if (a == "--charset-custom") c.custom_charset = value();
    else if (a == "--allow") c.allow = value();
    else if (a == "--deny") c.deny = value();
    else if (a == "--position") c.position_spec = value();
    else if (a == "--digest-pattern") c.pattern = value();
    else if (a == "--target-digest") c.target = value();
    else if (a == "--weak-hex") c.weak_hex = static_cast<unsigned>(number(value()));
    else if (a == "--threads") c.threads = static_cast<unsigned>(number(value()));
    else if (a == "--max-candidates") c.max_candidates = number(value());
    else if (a == "--max-output") c.max_output = number(value());
    else if (a == "--bench-candidates") c.bench_candidates = number(value());
    else if (a == "--bench-repeats") c.bench_repeats = static_cast<unsigned>(number(value()));
    else if (a == "--bench-warmup") c.bench_warmup = static_cast<unsigned>(number(value()));
    else if (a == "--output-case") { auto v = value(); if (v == "upper") c.upper_output = true; else if (v != "lower") usage_error("output-case 必须是 upper 或 lower"); }
    else if (a == "--no-color") c.color = false;
    else if (a == "--no-simd") c.simd = false;
    else if (a == "--text") c.text = value();
    else usage_error("未知选项：" + std::string(a));
  }
  if (c.threads == 0) c.threads = default_thread_count();
  return c;
}

std::string preset(std::string_view name) {
  if (name == "upper") return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (name == "lower") return "abcdefghijklmnopqrstuvwxyz";
  if (name == "digits") return "0123456789";
  if (name == "alnum") return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  if (name == "hex") return "0123456789abcdefABCDEF";
  usage_error("未知字符集名称：" + std::string(name) + "；可用名称为 upper、lower、digits、alnum、hex，或使用 --charset-custom");
}

struct SearchSpace {
  std::vector<std::vector<std::uint8_t>> chars;
  std::vector<std::uint64_t> radix;
#if defined(ZM_HASH_USE_LIBDIVIDE)
  std::vector<libdivide::divider<std::uint64_t>> dividers;
#endif
  std::uint64_t total = 0;
};

SearchSpace make_space(const Config &c) {
  if (!c.custom_charset.empty() && c.charset != "lower") usage_error("--charset 与 --charset-custom 不能同时指定");
  std::string base = c.custom_charset.empty() ? preset(c.charset) : c.custom_charset;
  if (!c.allow.empty()) {
    std::string filtered; for (char x : base) if (c.allow.find(x) != std::string::npos) filtered += x; base = filtered;
  }
  if (!c.deny.empty()) { std::string filtered; for (char x : base) if (c.deny.find(x) == std::string::npos) filtered += x; base = filtered; }
  if (base.empty() && c.length != 0) usage_error("应用白名单/黑名单后的字符集为空");
  SearchSpace s; s.chars.assign(c.length, std::vector<std::uint8_t>(base.begin(), base.end()));
  s.radix.resize(c.length);
#if defined(ZM_HASH_USE_LIBDIVIDE)
  s.dividers.reserve(c.length);
#endif
  for (const auto &entry : split(c.position_spec, ',')) {
    if (entry.empty()) continue;
    const auto eq = entry.find('=');
    if (eq == std::string::npos) usage_error("position 必须是 位置=字符集");
    const auto idx = number(entry.substr(0, eq)); if (idx >= c.length) usage_error("position 位置超出输入长度");
    std::string p = entry.substr(eq + 1); if (p.empty()) usage_error("position 字符集不能为空");
    std::vector<std::uint8_t> v;
    for (char x : p) if (base.find(x) != std::string::npos) v.push_back(static_cast<std::uint8_t>(x));
    if (v.empty()) usage_error("position 字符集经过白名单/黑名单过滤后为空");
    s.chars[idx] = std::move(v);
  }
  s.total = 1;
  for (std::size_t i = 0; i != s.chars.size(); ++i) {
    const auto &v = s.chars[i];
    s.radix[i] = v.size();
#if defined(ZM_HASH_USE_LIBDIVIDE)
    if (!v.empty()) s.dividers.emplace_back(static_cast<std::uint64_t>(v.size()));
#endif
    if (v.empty()) { s.total = 0; break; }
    if (s.total > std::numeric_limits<std::uint64_t>::max() / v.size()) { s.total = std::numeric_limits<std::uint64_t>::max(); break; }
    s.total *= v.size();
  }
  return s;
}

void decode(std::uint64_t index, const SearchSpace &space, std::vector<std::uint8_t> &out) {
  out.resize(space.chars.size());
  for (std::size_t i = space.chars.size(); i-- > 0;) {
    const auto radix = space.radix[i];
#if defined(ZM_HASH_USE_LIBDIVIDE)
    const auto quotient = index / space.dividers[i];
    out[i] = space.chars[i][index - quotient * radix];
    index = quotient;
#else
    out[i] = space.chars[i][index % radix];
    index /= radix;
#endif
  }
}

bool matches_pattern(const std::string &digest, std::string_view pattern) {
  if (pattern.empty()) return true;
  if (pattern.size() != 32) return false;
  for (std::size_t i = 0; i != 32; ++i) if (pattern[i] != '?' && std::tolower(static_cast<unsigned char>(pattern[i])) != digest[i]) return false;
  return true;
}

bool is_php_magic_hash(const std::string &digest) {
  if (digest.size() != 32 || digest[0] != '0' || digest[1] != 'e') return false;
  for (std::size_t i = 2; i != digest.size(); ++i) if (digest[i] < '0' || digest[i] > '9') return false;
  return true;
}

std::string normalize_digest(std::string value) {
  if (value.size() != 32) usage_error("MD5 摘要必须是 32 个十六进制字符");
  for (char &ch : value) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) usage_error("MD5 摘要包含非十六进制字符");
  }
  return value;
}

std::string normalize_pattern(std::string value) {
  if (value.empty()) return value;
  if (value.size() != 32) usage_error("MD5 模式必须是 32 个字符");
  for (char &ch : value) {
    if (ch != '?') {
      ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
      if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) usage_error("MD5 模式包含非十六进制字符");
    }
  }
  return value;
}

Digest collision_key(Digest d, unsigned weak_hex) {
  if (weak_hex >= 32) return d;
  const unsigned full = weak_hex / 2; const bool half = weak_hex % 2;
  for (unsigned i = full + (half ? 1u : 0u); i < 16; ++i) d[i] = 0;
  if (half) d[full] &= 0xf0;
  return d;
}

std::pair<double, std::uint64_t> benchmark_once(const SearchSpace &space, std::uint64_t count, unsigned threads, bool use_simd) {
  std::atomic<std::uint64_t> next{0};
  std::vector<std::uint64_t> sinks(threads);
  std::mutex gate_mutex;
  std::condition_variable gate_cv;
  unsigned ready_count = 0;
  bool start = false;
  std::atomic<bool> startup_failed{false};
  std::exception_ptr worker_error;
  std::atomic<bool> stop{false};
  std::vector<std::jthread> workers;
  workers.reserve(threads);
  try {
    for (unsigned t = 0; t < threads; ++t) {
      workers.emplace_back([&, t](std::stop_token) {
        try {
          std::vector<std::uint8_t> candidate;
          candidate.reserve(space.chars.size());
          Md5Scratch scratch;
          std::uint64_t sink = 0;
          {
            std::unique_lock lock(gate_mutex);
            ++ready_count;
            gate_cv.notify_all();
            gate_cv.wait(lock, [&] { return start || startup_failed.load(std::memory_order_relaxed); });
            if (startup_failed.load(std::memory_order_relaxed)) return;
          }
          if (use_simd) {
            std::array<std::array<std::uint8_t, 56>, 16> batch{};
            std::array<Digest, 16> digests{};
            while (!stop.load(std::memory_order_relaxed)) {
              const auto begin = next.fetch_add(256, std::memory_order_relaxed);
              if (begin >= count) break;
              const auto end = std::min<std::uint64_t>(count, begin + 256);
              auto i = begin;
              for (; i + 16 <= end; i += 16) {
                for (unsigned lane = 0; lane != 16; ++lane) {
                  batch[lane].fill(0);
                  decode(space.total == 0 ? 0 : (i + lane) % space.total, space, candidate);
                  std::copy(candidate.begin(), candidate.end(), batch[lane].begin());
                }
                md5_avx512_16(std::span<const std::array<std::uint8_t, 56>, 16>(batch), space.chars.size(), digests);
                for (const auto &d : digests) sink ^= digest_checksum(d);
              }
              for (; i < end && !stop.load(std::memory_order_relaxed); ++i) {
                decode(space.total == 0 ? 0 : i % space.total, space, candidate);
                sink ^= digest_checksum(md5(candidate, scratch));
              }
            }
          } else {
            while (!stop.load(std::memory_order_relaxed)) {
              const auto begin = next.fetch_add(256, std::memory_order_relaxed);
              if (begin >= count) break;
              const auto end = std::min<std::uint64_t>(count, begin + 256);
              for (auto i = begin; i < end && !stop.load(std::memory_order_relaxed); ++i) {
                decode(space.total == 0 ? 0 : i % space.total, space, candidate);
                sink ^= digest_checksum(md5(candidate, scratch));
              }
            }
          }
          sinks[t] = sink;
        } catch (...) {
          std::scoped_lock lock(gate_mutex);
          if (!worker_error) worker_error = std::current_exception();
          startup_failed = true;
          stop.store(true, std::memory_order_relaxed);
          gate_cv.notify_all();
        }
      });
    }
  } catch (...) {
    {
      std::scoped_lock lock(gate_mutex);
      startup_failed = true;
      start = true;
      stop.store(true, std::memory_order_relaxed);
    }
    gate_cv.notify_all();
    for (auto &worker : workers) worker.join();
    throw;
  }
  {
    std::unique_lock lock(gate_mutex);
    gate_cv.wait(lock, [&] { return ready_count == threads || startup_failed.load(std::memory_order_relaxed); });
    if (startup_failed.load(std::memory_order_relaxed)) {
      start = true;
      stop.store(true, std::memory_order_relaxed);
    } else {
      start = true;
    }
  }
  gate_cv.notify_all();
  if (startup_failed.load(std::memory_order_relaxed)) {
    for (auto &worker : workers) worker.join();
    if (worker_error) std::rethrow_exception(worker_error);
    throw std::runtime_error("benchmark worker 启动失败");
  }
  const auto start_time = std::chrono::steady_clock::now();
  for (auto &worker : workers) worker.join();
  const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
  std::uint64_t checksum = 0;
  for (const auto sink : sinks) checksum ^= sink;
  return {elapsed, checksum};
}

int run_benchmark(const Config &c) {
  if (c.bench_candidates == 0 || c.bench_repeats == 0) usage_error("benchmark 候选数和测量轮数必须大于 0");
  auto space = make_space(c);
  if (space.total == 0) usage_error("benchmark 字符空间为空");
  const auto threads = std::max(1u, c.threads);
  const bool use_simd = c.simd && c.length <= 55 && md5_avx512_available();
  std::cerr << paint("benchmark：", Ansi::cyan, c.color) << c.bench_candidates << " 个候选，" << threads << " 个线程，"
            << (use_simd ? "AVX-512 16 路" : "标量") << "\n";
  for (unsigned i = 0; i < c.bench_warmup; ++i) benchmark_once(space, c.bench_candidates, threads, use_simd);
  std::vector<double> samples;
  samples.reserve(c.bench_repeats);
  std::uint64_t checksum = 0;
  for (unsigned i = 0; i < c.bench_repeats; ++i) {
    const auto [seconds, sink] = benchmark_once(space, c.bench_candidates, threads, use_simd);
    samples.push_back(seconds); checksum ^= sink;
    std::cout << "第 " << (i + 1) << " 轮：" << std::fixed << std::setprecision(6) << seconds << " 秒，"
              << std::setprecision(2) << (static_cast<double>(c.bench_candidates) / seconds) << " hashes/s\n";
  }
  std::ranges::sort(samples);
  const double median = samples[samples.size() / 2];
  std::cout << paint("中位数：", Ansi::yellow, c.color) << std::fixed << std::setprecision(6) << median << " 秒，"
            << std::setprecision(2) << (static_cast<double>(c.bench_candidates) / median) << " hashes/s\n"
            << "校验值：" << std::hex << checksum << std::dec << "\n";
  return 0;
}

int run(const Config &c) {
  if (c.mode == Config::Mode::Benchmark) return run_benchmark(c);
  if (c.mode == Config::Mode::Hash) {
    const auto d = md5(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(c.text.data()), c.text.size()));
    std::cout << hex(d, c.upper_output) << "  " << c.text << '\n'; return 0;
  }
  if (c.length > 1'000'000) usage_error("输入长度过大");
  interrupted.store(false, std::memory_order_relaxed);
  const std::string target = c.target.empty() ? std::string{} : normalize_digest(c.target);
  const std::string pattern = normalize_pattern(c.pattern);
  if (c.mode == Config::Mode::Prefix && (c.weak_hex == 0 || c.weak_hex > 32)) usage_error("weak-hex 必须在 1 到 32 之间");
  auto space = make_space(c); if (space.total == 0) return 0;
  const auto limit = std::min(space.total, c.max_candidates);
  std::atomic<std::uint64_t> next{0};
  std::atomic<bool> stop{false};
  std::atomic<bool> found{false};
  std::atomic<std::uint64_t> output_count{0};
  std::atomic<bool> output_limit_hit{false};
  std::mutex output_mutex;
  std::vector<std::jthread> workers;
  std::array<std::unordered_map<Digest, Seen, KeyHash>, 32> tables;
  std::array<std::mutex, 32> locks;
  const unsigned thread_count = static_cast<unsigned>(std::min<std::uint64_t>(c.threads, std::max<std::uint64_t>(1, limit)));
  for (unsigned t = 0; t < thread_count; ++t) workers.emplace_back([&](std::stop_token token) {
    std::vector<std::uint8_t> candidate; candidate.reserve(c.length);
    Md5Scratch scratch;
    while (!token.stop_requested() && !stop.load(std::memory_order_relaxed) && !interrupted.load(std::memory_order_relaxed)) {
      const auto begin = next.fetch_add(256, std::memory_order_relaxed); if (begin >= limit) break;
      const auto end = std::min<std::uint64_t>(limit, begin + 256);
      for (auto i = begin; i < end && !stop.load(std::memory_order_relaxed) && !interrupted.load(std::memory_order_relaxed); ++i) {
        decode(i, space, candidate); const auto d = md5(candidate, scratch);
        if (c.mode == Config::Mode::Match) {
          const auto canonical = hex(d, false);
          const auto ds = hex(d, c.upper_output);
          if ((!target.empty() && canonical == target) || (target.empty() && matches_pattern(canonical, pattern))) {
            const auto ordinal = output_count.fetch_add(1, std::memory_order_relaxed);
            if (ordinal < c.max_output) {
              std::scoped_lock lock(output_mutex);
              std::cout << ds << "  " << std::string(candidate.begin(), candidate.end()) << '\n';
              if (ordinal + 1 >= c.max_output) {
                output_limit_hit.store(true, std::memory_order_relaxed);
                stop.store(true, std::memory_order_relaxed);
              }
            } else {
              output_limit_hit.store(true, std::memory_order_relaxed);
              stop.store(true, std::memory_order_relaxed);
            }
          }
        } else {
          const auto candidate_text = std::string(candidate.begin(), candidate.end());
          const auto canonical = hex(d, false);
          if (c.mode == Config::Mode::PhpWeak && !is_php_magic_hash(canonical)) continue;
          const auto key = c.mode == Config::Mode::Prefix ? collision_key(d, c.weak_hex) : (c.mode == Config::Mode::PhpWeak ? Digest{} : d);
          const auto shard = KeyHash{}(key) & 31u;
          std::scoped_lock lock(locks[shard]); auto [it, inserted] = tables[shard].try_emplace(key, Seen{candidate_text, d});
          if (!inserted && it->second.candidate != candidate_text) {
            stop.store(true, std::memory_order_relaxed);
            if (!found.exchange(true, std::memory_order_acq_rel)) {
              std::scoped_lock out_lock(output_mutex);
              const auto label = c.mode == Config::Mode::PhpWeak ? "PHP 弱碰撞" : (c.mode == Config::Mode::Prefix ? "前缀碰撞" : "真碰撞");
              std::cout << paint(label, Ansi::yellow, c.color) << '\n'
                        << "  A: " << paint(hex(it->second.digest, c.upper_output), Ansi::cyan, c.color) << "  " << paint(it->second.candidate, Ansi::green, c.color) << '\n'
                        << "  B: " << paint(hex(d, c.upper_output), Ansi::cyan, c.color) << "  " << paint(candidate_text, Ansi::green, c.color) << '\n';
            }
          }
        }
      }
    }
  });
  for (auto &worker : workers) worker.join();
  workers.clear();
  if (interrupted.load(std::memory_order_relaxed)) std::cerr << paint("已收到 Ctrl+C，搜索已停止。", Ansi::yellow, c.color) << '\n';
  else if (output_limit_hit.load(std::memory_order_relaxed)) std::cerr << paint("已达到输出上限，搜索已停止。", Ansi::yellow, c.color) << '\n';
  else if (c.mode == Config::Mode::Match) std::cerr << paint("已搜索候选数：", Ansi::yellow, c.color) << limit << '\n';
  else if (!stop.load()) std::cerr << paint("未在指定候选空间中找到碰撞，已搜索：", Ansi::yellow, c.color) << limit << '\n';
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  enable_terminal_colors();
  std::signal(SIGINT, handle_sigint);
  try { return run(parse(argc, argv)); }
  catch (const std::exception &e) { std::cerr << paint("错误：", Ansi::red, true) << e.what() << '\n'; return 2; }
}
