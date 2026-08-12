#include "crack_cpu.h"

#include <atomic>
#include <chrono>
#include <fstream>
#include <thread>

std::atomic<bool> g_crackAbort{false};

bool parseMask(const std::string& mask, std::vector<std::string>& pos) {
  static const std::string L = "abcdefghijklmnopqrstuvwxyz";
  static const std::string U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const std::string D = "0123456789";
  static const std::string S = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // hashcat ?s(含空格)
  static const std::string A = L + U + D + S;                          // hashcat ?a = 95 可打印
  for (size_t i = 0; i < mask.size(); i++) {
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
      pos.emplace_back(1, mask[i]); // 字面字符原样保留
    }
  }
  return !pos.empty();
}

std::string maskCandidate(uint64_t idx, const std::vector<std::string>& pos) {
  std::string s(pos.size(), ' ');
  for (int k = (int)pos.size() - 1; k >= 0; k--) {
    const std::string& cs = pos[k];
    s[k] = cs[idx % cs.size()];
    idx /= cs.size();
  }
  return s;
}

/** 通用多线程引擎:原子游标取块,verify 回调判定 */
template <typename NextBatch>
static CrackResult runEngine(int threads, NextBatch nextBatch,
                             bool (*verify)(const uint8_t*, size_t, void*), void* ctx) {
  CrackResult res;
  std::atomic<bool> found{false};
  std::string foundSecret;
  std::atomic<uint64_t> attempts{0};
  auto t0 = std::chrono::steady_clock::now();

  auto worker = [&]() {
    uint64_t local = 0;
    std::vector<std::string> batch;
    while (!found.load(std::memory_order_relaxed) && !g_crackAbort.load(std::memory_order_relaxed)) {
      size_t n = nextBatch(batch); // 0 = 无更多候选
      if (n == 0) break;
      for (size_t i = 0; i < n; i++) {
        const std::string& cand = batch[i];
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          foundSecret = cand;
          found.store(true);
          break;
        }
      }
    }
    attempts += local;
  };

  int n = threads > 0 ? threads : (int)std::thread::hardware_concurrency();
  if (n < 1) n = 1;
  std::vector<std::thread> pool;
  for (int i = 0; i < n; i++) pool.emplace_back(worker);
  for (auto& t : pool) t.join();

  auto t1 = std::chrono::steady_clock::now();
  res.seconds = std::chrono::duration<double>(t1 - t0).count();
  res.attempts = attempts.load();
  res.found = found.load();
  res.secret = foundSecret;
  return res;
}

CrackResult crackCpuWordlist(const std::string& wordlistPath, int threads,
                             bool (*verify)(const uint8_t*, size_t, void*), void* ctx) {
  std::ifstream f(wordlistPath, std::ios::binary);
  CrackResult res;
  if (!f) {
    res.error = "打不开字典: " + wordlistPath;
    return res;
  }
  std::vector<std::string> words;
  std::string line;
  while (std::getline(f, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    if (!line.empty()) words.push_back(line);
  }
  if (words.empty()) {
    res.error = "字典为空";
    return res;
  }
  std::atomic<size_t> idx{0};
  return runEngine(threads,
    [&](std::vector<std::string>& batch) -> size_t {
      batch.clear();
      // 每线程每次领 1024 个,减少原子争抢
      size_t begin = idx.fetch_add(1024, std::memory_order_relaxed);
      for (size_t i = begin; i < begin + 1024 && i < words.size(); i++) batch.push_back(words[i]);
      return batch.size();
    },
    verify, ctx);
}

CrackResult crackCpuMask(const std::vector<std::string>& pos, int threads,
                         bool (*verify)(const uint8_t*, size_t, void*), void* ctx) {
  CrackResult res;
  uint64_t total = 1;
  for (const auto& cs : pos) {
    if (total > UINT64_MAX / cs.size()) {
      res.error = "组合数过大(超过 2^64)";
      return res;
    }
    total *= (uint64_t)cs.size();
  }
  const uint64_t CHUNK = 4096;
  const size_t L = pos.size();
  std::atomic<uint64_t> base{0};
  std::atomic<bool> found{false};
  std::string foundSecret;
  std::atomic<uint64_t> attempts{0};
  auto t0 = std::chrono::steady_clock::now();

  auto worker = [&]() {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表),进位递增替代逐候选除法链
    std::string cand(L, ' ');     // 定长候选缓冲,原地改写,无逐候选 string 构造
    while (!found.load(std::memory_order_relaxed) && !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = base.fetch_add(CHUNK, std::memory_order_relaxed);
      if (start >= total) break;
      uint64_t end = start + CHUNK < total ? start + CHUNK : total;
      // 块首:序号 → 里程表(混合进制除法链,每块仅一次),与 maskCandidate 序一致
      uint64_t v = start;
      for (size_t k = L; k-- > 0;) { idx[k] = (uint32_t)(v % pos[k].size()); v /= pos[k].size(); }
      for (size_t k = 0; k < L; k++) cand[k] = pos[k][idx[k]];
      for (uint64_t i = start; i < end; i++) {
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          foundSecret = cand;
          found.store(true);
          break;
        }
        // 里程表进位:末位最快,绝大多数迭代 O(1)
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
      }
    }
    attempts += local;
  };

  int n = threads > 0 ? threads : (int)std::thread::hardware_concurrency();
  if (n < 1) n = 1;
  std::vector<std::thread> pool;
  for (int i = 0; i < n; i++) pool.emplace_back(worker);
  for (auto& t : pool) t.join();

  auto t1 = std::chrono::steady_clock::now();
  res.seconds = std::chrono::duration<double>(t1 - t0).count();
  res.attempts = attempts.load();
  res.found = found.load();
  res.secret = foundSecret;
  return res;
}
