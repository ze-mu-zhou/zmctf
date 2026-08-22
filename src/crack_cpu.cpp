#include "crack_cpu.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <thread>

#ifdef _WIN32
#include <windows.h> // 原生 Sleep:winpthreads 的 sleep_for 会拖慢同进程线程池(实测 -30%)
#endif

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

/**
 * 线程内联进度上报:worker 在批次边界自查时钟(每批一次 QPC,~0.2% 开销),
 * 首个到点的线程负责打印。不用独立监视线程——实测多一个睡眠线程会把
 * 32 线程池的字典吞吐拖慢 ~30%(调度扰动),winpthreads/native Sleep 均如此。
 */
struct ProgressInl {
  std::chrono::steady_clock::time_point t0;
  std::atomic<uint64_t> lastMs{0}; // 上次打印时刻(ms since t0);CAS 保证只一个线程打
  uint64_t total = 0;
  bool on = true;

  void begin(uint64_t total_) {
    t0 = std::chrono::steady_clock::now();
    total = total_;
    on = !std::getenv("ZK_NOPROG");
  }
  void tick(const std::atomic<uint64_t>& att) {
    if (!on) return;
    uint64_t ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0).count();
    uint64_t last = lastMs.load(std::memory_order_relaxed);
    if (ms < last + 10000) return; // 10s 一报(10s 内完成的任务无输出)
    if (!lastMs.compare_exchange_strong(last, ms, std::memory_order_relaxed)) return;
    double el = ms / 1000.0;
    uint64_t a = att.load(std::memory_order_relaxed);
    double rate = el > 0 ? a / el : 0;
    char line[128];
    if (total > 0)
      snprintf(line, sizeof line, "[~] 进度 %llu/%llu(%.1f%%),%.0fM/s\n",
               (unsigned long long)a, (unsigned long long)total,
               a * 100.0 / total, rate / 1e6);
    else
      snprintf(line, sizeof line, "[~] 已尝试 %llu,%.0fM/s\n",
               (unsigned long long)a, rate / 1e6);
    std::cerr << line;
  }
};

/** 引擎运行时共享态:worker 里周期回写 attempts 供进度显示;命中写 secret(仅一个真命中) */
struct RunCtx {
  std::atomic<uint64_t> attempts{0};
  std::atomic<bool> found{false};
  std::string secret;
};

/** 线程池骨架:计时 + 汇总 */
template <typename Worker>
static CrackResult runPool(int threads, uint64_t total, RunCtx& rc, ProgressInl& prog, Worker worker) {
  CrackResult res;
  auto t0 = std::chrono::steady_clock::now();
  int n = threads > 0 ? threads : (int)std::thread::hardware_concurrency();
  if (n < 1) n = 1;
  std::vector<std::thread> pool;
  for (int i = 0; i < n; i++) pool.emplace_back(worker);
  for (auto& t : pool) t.join();
  res.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  res.attempts = rc.attempts.load();
  res.found = rc.found.load();
  res.secret = rc.secret;
  return res;
}

/** 加载字典文件(去 \r\n,跳过空行);失败置 error */
static bool loadWords(const std::string& path, std::vector<std::string>& words, std::string& error) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    error = "打不开字典: " + path;
    return false;
  }
  std::string line;
  while (std::getline(f, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    if (!line.empty()) words.push_back(line);
  }
  if (words.empty()) {
    error = "字典为空";
    return false;
  }
  return true;
}

CrackResult crackCpuWordlist(const std::string& wordlistPath, int threads,
                             bool (*verify)(const uint8_t*, size_t, void*), void* ctx) {
  std::vector<std::string> words;
  CrackResult res;
  if (!loadWords(wordlistPath, words, res.error)) return res;
  return crackCpuWords(words, threads, verify, ctx);
}

/** CPU 字典爆破(内存字典:与 GPU 路径共用一次加载,避免二次读盘) */
CrackResult crackCpuWords(const std::vector<std::string>& words, int threads,
                          bool (*verify)(const uint8_t*, size_t, void*), void* ctx) {
  RunCtx rc;
  if (words.empty()) {
    CrackResult res;
    res.error = "字典为空";
    return res;
  }
  std::atomic<size_t> idx{0};
  ProgressInl prog;
  prog.begin(words.size());
  return runPool(threads, words.size(), rc, prog, [&] {
    uint64_t local = 0;
    // 先整批拷出再验证:拷贝遍是散射大字典的预取流水,验证遍打 L1 热数据;
    // 实测去掉拷贝(直读 words[i])在 32 线程下慢 ~30%(访存延迟暴露),勿"优化"掉
    std::vector<std::string> batch;
    while (!rc.found.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      // 每线程每次领 1024 个,减少原子争抢
      size_t begin = idx.fetch_add(1024, std::memory_order_relaxed);
      if (begin >= words.size()) break;
      size_t end = begin + 1024 < words.size() ? begin + 1024 : words.size();
      batch.clear();
      for (size_t i = begin; i < end; i++) batch.push_back(words[i]);
      for (const auto& cand : batch) {
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          rc.secret = cand;
          rc.found.store(true, std::memory_order_relaxed);
          break;
        }
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      prog.tick(rc.attempts);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
}

/* ============ 混合模式:CPU 从尾部降序吃块,与 GPU(头部升序)对向推进 ============ */

// CPU 侧领块粒度:太大则命中/取消的停止延迟高,太小则游标原子争抢;64K ≈ 0.6ms/线程
static const uint64_t HYBRID_CHUNK = 65536;

CrackResult crackCpuMaskRange(const std::vector<std::string>& pos, int threads,
                              bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                              HybridCtl& ctl) {
  CrackResult res;
  uint64_t total = 1; // 与 flaskCrack 同式;tail 下溢检测的基准
  for (const auto& cs : pos) total *= (uint64_t)cs.size();
  const size_t L = pos.size();
  RunCtx rc;
  ProgressInl prog;
  prog.on = false; // 混合模式进度由 GPU 侧统一汇报
  res = runPool(threads, 0, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表)
    std::string cand(L, ' ');
    while (!ctl.stop.load(std::memory_order_relaxed) &&
           !rc.found.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t end = ctl.tail.fetch_sub(HYBRID_CHUNK, std::memory_order_relaxed);
      if (end > total) break; // 块粒度大于剩余空间时下溢回绕:空间已尽,退出
      uint64_t h = ctl.head.load(std::memory_order_relaxed);
      if (end <= h) break; // 剩余空间已全被 GPU 认领
      uint64_t start = end > HYBRID_CHUNK ? end - HYBRID_CHUNK : 0;
      if (start < h) start = h; // 与 GPU 认领区重叠部分丢弃:可能重复验,不会漏
      uint64_t v = start;
      for (size_t k = L; k-- > 0;) { idx[k] = (uint32_t)(v % pos[k].size()); v /= pos[k].size(); }
      for (size_t k = 0; k < L; k++) cand[k] = pos[k][idx[k]];
      for (uint64_t i = start; i < end; i++) {
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          rc.secret = cand;
          rc.found.store(true, std::memory_order_relaxed);
          ctl.stop.store(true, std::memory_order_relaxed);
          break;
        }
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
  return res;
}

CrackResult crackCpuWordsRange(const std::vector<std::string>& words, int threads,
                               bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                               HybridCtl& ctl) {
  RunCtx rc;
  ProgressInl prog;
  prog.on = false;
  const uint64_t N = (uint64_t)words.size(); // tail 下溢检测的基准
  return runPool(threads, 0, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<std::string> batch; // 同 crackCpuWords:拷贝遍是散射访存的预取流水,勿省
    while (!ctl.stop.load(std::memory_order_relaxed) &&
           !rc.found.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t end = ctl.tail.fetch_sub(HYBRID_CHUNK, std::memory_order_relaxed);
      if (end > N) break; // 块粒度大于剩余空间时下溢回绕:空间已尽,退出
      uint64_t h = ctl.head.load(std::memory_order_relaxed);
      if (end <= h) break;
      uint64_t start = end > HYBRID_CHUNK ? end - HYBRID_CHUNK : 0;
      if (start < h) start = h;
      batch.clear();
      for (uint64_t i = start; i < end; i++) batch.push_back(words[(size_t)i]);
      for (const auto& cand : batch) {
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          rc.secret = cand;
          rc.found.store(true, std::memory_order_relaxed);
          ctl.stop.store(true, std::memory_order_relaxed);
          break;
        }
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
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
  RunCtx rc;
  ProgressInl prog;
  prog.begin(total);
  res = runPool(threads, total, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表),进位递增替代逐候选除法链
    std::string cand(L, ' ');     // 定长候选缓冲,原地改写,无逐候选 string 构造
    while (!rc.found.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
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
          rc.secret = cand;
          rc.found.store(true, std::memory_order_relaxed);
          break;
        }
        // 里程表进位:末位最快,绝大多数迭代 O(1)
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      prog.tick(rc.attempts);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
  return res;
}
