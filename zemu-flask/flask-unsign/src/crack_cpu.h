/**
 * crack_cpu.h:CPU 多线程爆破引擎(字典 / 掩码),SHA-NI 自动调度。
 * 候选统一走 verifyHmac 回调比对(与具体 cookie 格式解耦)。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

/** 批量验证回调:对 n 个候选逐个算 MAC(不提前退出),返回首个命中下标或 -1。
 * 语义与单候选回调一致(同一 ctx),但允许实现用 SIMD 纵向多候选等手段加速。 */
using VerifyBatchFn = int (*)(const uint8_t* const*, const size_t*, void*);

/** 取消钩:置 true 后 CPU/GPU 爆破在批次/分块边界尽快退出(供 serve 模式的调用方取消;CLI 恒 false) */
extern std::atomic<bool> g_crackAbort;

/** 掩码(hashcat 风格:?l/?u/?d/?s/?a + 字面字符)→ 每位字符集;?? 转义字面 ? */
bool parseMask(const std::string& mask, std::vector<std::string>& pos);

/** 序号 → 掩码候选串(混合进制,末位变化最快) */
std::string maskCandidate(uint64_t idx, const std::vector<std::string>& pos);

struct CrackResult {
  bool found = false;
  std::string secret;      // 命中时的密钥
  uint64_t attempts = 0;   // 已汇总尝试数;异常时可能缺少线程局部批次,为下界
  double seconds = 0;      // 耗时
  std::string error;       // 参数/IO 错误(found=false 且 error 非空)
};

/**
 * CPU 字典爆破:读 wordlist 逐行试。
 * verify(key, keyLen) 返回 true 即命中(内部完成派生+HMAC 比对)。
 */
CrackResult crackCpuWordlist(const std::string& wordlistPath, int threads,
                             bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                             VerifyBatchFn verifyBatch = nullptr, int batchSize = 0);

/** CPU 字典爆破(字典已在内存:与 GPU 打包共用一次加载,免二次读盘) */
CrackResult crackCpuWords(const std::vector<std::string>& words, int threads,
                          bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                          VerifyBatchFn verifyBatch = nullptr, int batchSize = 0);

/** CPU 掩码爆破:组合空间按块分配给线程。
 *  verifyBatch/batchSize 提供时(SIMD 可用)热路径走批量验证,否则纯标量。 */
CrackResult crackCpuMask(const std::vector<std::string>& pos, int threads,
                         bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                         VerifyBatchFn verifyBatch = nullptr, int batchSize = 0);

/**
 * 混合(CPU+GPU)爆破共享控制块:GPU 从 head 升序吃块,CPU 从 tail 降序吃块,
 * 任一侧命中/取消/出错置 stop。块单位与两侧游标都在同一候选序号空间。
 */
struct HybridCtl {
  std::atomic<uint64_t> head{0};  // GPU 下一块起点
  std::atomic<uint64_t> tail{0};  // CPU 下一块终点(exclusive;初值=总数)
  std::atomic<bool> stop{false};  // 任一侧命中/取消
};

/** 掩码混合模式:CPU 只处理 [head, tail) 内的块,命中置 ctl.stop */
CrackResult crackCpuMaskRange(const std::vector<std::string>& pos, int threads,
                              bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                              HybridCtl& ctl,
                              VerifyBatchFn verifyBatch = nullptr, int batchSize = 0);

/** 字典混合模式:同上,序号空间为 words 下标(含 GPU 打包跳过的超长词) */
CrackResult crackCpuWordsRange(const std::vector<std::string>& words, int threads,
                               bool (*verify)(const uint8_t*, size_t, void*), void* ctx,
                               HybridCtl& ctl,
                               VerifyBatchFn verifyBatch = nullptr, int batchSize = 0);
