#include "crack_cpu.h"
#include "thread_group.h"

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
  std::atomic<bool> stop{false};
  std::string secret;
};

/** 线程池骨架:计时 + 汇总 */
template <typename Worker>
static CrackResult runPool(int threads, uint64_t total, RunCtx& rc, ProgressInl& prog, Worker worker,
                           std::atomic<bool>* peerStop = nullptr) {
  CrackResult res;
  auto t0 = std::chrono::steady_clock::now();
  int n = threads > 0 ? threads : (int)std::thread::hardware_concurrency();
  if (n < 1) n = 1;
  try {
    ThreadGroup pool(rc.stop, peerStop);
    for (int i = 0; i < n && !pool.stopped(); i++) pool.launch(worker);
    pool.finish();
  } catch (const std::exception& e) {
    res.error = e.what();
    return res;
  }
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
                             bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                             VerifyBatchFn verifyBatch, int batchSize) {
  std::vector<std::string> words;
  CrackResult res;
  if (!loadWords(wordlistPath, words, res.error)) return res;
  return crackCpuWords(words, threads, verify, ctx, verifyBatch, batchSize);
}

/** CPU 字典爆破(内存字典:与 GPU 路径共用一次加载,避免二次读盘) */
CrackResult crackCpuWords(const std::vector<std::string>& words, int threads,
                          bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                          VerifyBatchFn verifyBatch, int batchSize) {
  RunCtx rc;
  if (words.empty()) {
    CrackResult res;
    res.error = "字典为空";
    return res;
  }
  std::atomic<size_t> idx{0};
  ProgressInl prog;
  prog.begin(words.size());
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  return runPool(threads, words.size(), rc, prog, [&] {
    uint64_t local = 0;
    // 直读 words(不整批拷贝):标量时代拷贝曾当预取流水(32 线程 +30%),
    // 批量验证快 8~16 倍后拷贝变成纯开销(长词实测直读 +40%),结论已反转
    std::vector<const uint8_t*> bkeys((size_t)B); // 批量槽:直接指进 words
    std::vector<size_t> bklen((size_t)B);
    while (!rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      // 每线程每次领 1024 个,减少原子争抢
      size_t begin = idx.fetch_add(1024, std::memory_order_relaxed);
      if (begin >= words.size()) break;
      size_t end = begin + 1024 < words.size() ? begin + 1024 : words.size();
      const size_t m = end - begin;
      const std::string* src = words.data() + begin; // 直读实验:跳过 batch 拷贝
      for (size_t i = 0; i < m;) {
        if (B > 1 && m - i >= (size_t)B) {
          // —— 批量路径:一次 SIMD 验证 B 个变长候选 ——
          for (int b = 0; b < B; b++) {
            const std::string& w = src[i + (size_t)b];
            bkeys[(size_t)b] = (const uint8_t*)w.data();
            bklen[(size_t)b] = w.size();
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret = src[i + (size_t)hit];
            break;
          }
          local += (uint64_t)B;
          i += (size_t)B;
          continue;
        }
        // —— 标量路径:批尾余数 / 未启用批量 ——
        local++;
        const std::string& cand = src[i];
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret = cand;
          break;
        }
        i++;
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

// 从尾部无下溢地领取一段区间;不足一个 chunk 时把 tail 钳到 0。
static bool claimHybridTail(HybridCtl& ctl, uint64_t& start, uint64_t& end) {
  uint64_t hi = ctl.tail.load(std::memory_order_relaxed);
  while (hi != 0) {
    uint64_t lo = hi > HYBRID_CHUNK ? hi - HYBRID_CHUNK : 0;
    if (ctl.tail.compare_exchange_weak(hi, lo, std::memory_order_relaxed)) {
      start = lo;
      end = hi;
      return true;
    }
  }
  return false;
}

CrackResult crackCpuMaskRange(const std::vector<std::string>& pos, int threads,
                              bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                              HybridCtl& ctl,
                              VerifyBatchFn verifyBatch, int batchSize) {
  CrackResult res;
  const size_t L = pos.size();
  RunCtx rc;
  ProgressInl prog;
  prog.on = false; // 混合模式进度由 GPU 侧统一汇报
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  res = runPool(threads, 0, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表)
    std::string cand(L, ' ');
    // 批量流专用状态:每槽持有独立候选拷贝(与 crackCpuMask 批量段同构)
    std::vector<std::string> bcand((size_t)B, std::string(L, ' '));
    std::vector<const uint8_t*> bkeys((size_t)B);
    std::vector<size_t> bklen((size_t)B);
    while (!ctl.stop.load(std::memory_order_relaxed) &&
           !rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = 0, end = 0;
      if (!claimHybridTail(ctl, start, end)) break;
      uint64_t h = ctl.head.load(std::memory_order_relaxed);
      if (end <= h) break; // 剩余空间已全被 GPU 认领
      if (start < h) start = h; // 与 GPU 认领区重叠部分丢弃:可能重复验,不会漏
      uint64_t v = start;
      for (size_t k = L; k-- > 0;) { idx[k] = (uint32_t)(v % pos[k].size()); v /= pos[k].size(); }
      for (size_t k = 0; k < L; k++) cand[k] = pos[k][idx[k]];
      for (uint64_t i = start; i < end;) {
        if (B > 1 && end - i >= (uint64_t)B) {
          // 批量路径:槽位 b = 候选 i+b,先推进滚动源再整串拷入(顺序不能反)
          for (int b = 0; b < B; b++) {
            if (b > 0) {
              for (size_t k = L; k-- > 0;) {
                if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
                idx[k] = 0; cand[k] = pos[k][0];
              }
            }
            bcand[(size_t)b] = cand;
            bkeys[(size_t)b] = (const uint8_t*)bcand[(size_t)b].data(); bklen[(size_t)b] = L;
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret = bcand[(size_t)hit];
            ctl.stop.store(true, std::memory_order_relaxed);
            break;
          }
          // 批内推进了 B-1 次;再进一位对齐下批起点 i+B
          for (size_t k = L; k-- > 0;) {
            if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
            idx[k] = 0; cand[k] = pos[k][0];
          }
          local += (uint64_t)B;
          i += (uint64_t)B;
          continue;
        }
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret = cand;
          ctl.stop.store(true, std::memory_order_relaxed);
          break;
        }
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  }, &ctl.stop);
  return res;
}

CrackResult crackCpuWordsRange(const std::vector<std::string>& words, int threads,
                               bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                               HybridCtl& ctl,
                               VerifyBatchFn verifyBatch, int batchSize) {
  RunCtx rc;
  ProgressInl prog;
  prog.on = false;
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  return runPool(threads, 0, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<const uint8_t*> bkeys((size_t)B); // 批量槽:直接指进 words
    std::vector<size_t> bklen((size_t)B);
    while (!ctl.stop.load(std::memory_order_relaxed) &&
           !rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = 0, end = 0;
      if (!claimHybridTail(ctl, start, end)) break;
      uint64_t h = ctl.head.load(std::memory_order_relaxed);
      if (end <= h) break;
      if (start < h) start = h;
      const uint64_t m = end - start;
      const std::string* src = words.data() + start; // 直读:批量时代拷贝纯亏(实测 -40% 长词)
      for (uint64_t i = 0; i < m;) {
        if (B > 1 && m - i >= (uint64_t)B) {
          // 批量路径:一次 SIMD 验证 B 个变长候选
          for (int b = 0; b < B; b++) {
            const std::string& w = src[(size_t)(i + (uint64_t)b)];
            bkeys[(size_t)b] = (const uint8_t*)w.data();
            bklen[(size_t)b] = w.size();
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret = src[(size_t)(i + (uint64_t)hit)];
            ctl.stop.store(true, std::memory_order_relaxed);
            break;
          }
          local += (uint64_t)B;
          i += (uint64_t)B;
          continue;
        }
        local++;
        const std::string& cand = src[(size_t)i];
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret = cand;
          ctl.stop.store(true, std::memory_order_relaxed);
          break;
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  }, &ctl.stop);
}

CrackResult crackCpuMask(const std::vector<std::string>& pos, int threads,
                         bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                         VerifyBatchFn verifyBatch, int batchSize) {
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
  const int B = (verifyBatch && batchSize > 1) ? batchSize : 1; // 批量宽度
  res = runPool(threads, total, rc, prog, [&] {
    uint64_t local = 0;
    std::vector<uint32_t> idx(L); // 每位字符集下标(里程表),进位递增替代逐候选除法链
    std::string cand(L, ' ');     // 定长候选缓冲,原地改写,无逐候选 string 构造

    // 批量流专用状态:每槽持有独立候选拷贝(bkeys 必须各指各的)
    std::vector<std::string> bcand((size_t)B, std::string(L, ' '));
    std::vector<const uint8_t*> bkeys((size_t)B);
    std::vector<size_t> bklen((size_t)B);

    while (!rc.found.load(std::memory_order_relaxed) &&
           !rc.stop.load(std::memory_order_relaxed) &&
           !g_crackAbort.load(std::memory_order_relaxed)) {
      uint64_t start = base.fetch_add(CHUNK, std::memory_order_relaxed);
      if (start >= total) break;
      uint64_t end = start + CHUNK < total ? start + CHUNK : total;
      // 块首:序号 → 里程表(混合进制除法链,每块仅一次),与 maskCandidate 序一致
      uint64_t v = start;
      for (size_t k = L; k-- > 0;) { idx[k] = (uint32_t)(v % pos[k].size()); v /= pos[k].size(); }
      for (size_t k = 0; k < L; k++) cand[k] = pos[k][idx[k]];
      for (uint64_t i = start; i < end;) {
        if (B > 1 && end - i >= (uint64_t)B) {
          // —— 批量路径:组装 B 个连续候选(先推进滚动源,再整串拷入槽位) ——
          // 槽位 b 的内容必须等于候选 i+b:推进一步后再拷贝,顺序不能反
          for (int b = 0; b < B; b++) {
            if (b > 0) {
              for (size_t k = L; k-- > 0;) {
                if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
                idx[k] = 0; cand[k] = pos[k][0];
              }
            }
            bcand[(size_t)b] = cand;
            bkeys[(size_t)b] = (const uint8_t*)bcand[(size_t)b].data(); bklen[(size_t)b] = L;
          }
          int hit = verifyBatch(bkeys.data(), bklen.data(), ctx);
          if (hit >= 0) {
            local += (uint64_t)hit + 1;
            bool expected = false;
            if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
              rc.secret = bcand[(size_t)hit];
            break;
          }
          // 批内推进了 B-1 次(cand=i+B-1);再进一位对齐下批起点 i+B
          for (size_t k = L; k-- > 0;) {
            if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
            idx[k] = 0; cand[k] = pos[k][0];
          }
          local += (uint64_t)B;
          i += (uint64_t)B;
          continue;
        }
        // —— 标量路径:块尾余数 / 未启用批量 ——
        local++;
        if (verify((const uint8_t*)cand.data(), cand.size(), ctx)) {
          bool expected = false;
          if (rc.found.compare_exchange_strong(expected, true, std::memory_order_relaxed))
            rc.secret = cand;
          break;
        }
        // 里程表进位:末位最快,绝大多数迭代 O(1)
        for (size_t k = L; k-- > 0;) {
          if (++idx[k] < pos[k].size()) { cand[k] = pos[k][idx[k]]; break; }
          idx[k] = 0; cand[k] = pos[k][0];
        }
        i++;
      }
      rc.attempts.fetch_add(local, std::memory_order_relaxed);
      prog.tick(rc.attempts);
      local = 0;
    }
    rc.attempts.fetch_add(local, std::memory_order_relaxed);
  });
  return res;
}
