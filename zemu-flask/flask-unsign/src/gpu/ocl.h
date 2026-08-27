/**
 * ocl.h:OpenCL 主机端(运行时 LoadLibrary 动态加载,零构建期依赖)。
 * GPU 不可用(无设备/无驱动/kernel 编译失败)时返回错误,调用方回退 CPU。
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct GpuProbe {
  bool ok = false;
  std::string deviceName;
  std::string error;
};

struct HybridCtl; // crack_cpu.h 定义:GPU/CPU 对向吃块的共享游标

/** 探测 OpenCL GPU 并预编译 kernel(进程内只初始化一次) */
GpuProbe gpuProbe();

/** 上下文是否已初始化且可用(不触发初始化;serve 常驻进程用它降低 GPU 介入阈值) */
bool gpuWarm();

/** 冒烟测试:跑一个只写常量的 kernel,验证 OpenCL 基础链路(0=通过) */
int gpuSmokeTest(std::string& err);

struct GpuCrackParams {
  const uint8_t* value;   // 待验签内容(payload.ts)
  size_t vlen;            // ≤ 512
  uint8_t expect[20];     // 期望的 HMAC-SHA1
  const uint8_t* salt;    // ≤ 32
  size_t slen;
};

/**
 * pinned 主机缓冲(字典打包直写用):上传走 DMA,免 CL_MEM_COPY_HOST_PTR 的内部二次拷贝。
 * oclHostAlloc 会触发 OpenCL 初始化;失败返回空(ptr=nullptr),调用方回退普通 vector。
 * 交给 gpuCrackDict 的 pinned 参数后所有权转移(其负责 unmap/拷贝/释放),
 * 只有未交付时才由调用方 oclHostFree。
 */
struct OclHostBuf {
  void* ptr = nullptr;  // 可写主机地址(已 map)
  size_t size = 0;
  void* mem = nullptr;  // 内部句柄(cl_mem),勿动
};
OclHostBuf oclHostAlloc(size_t bytes);
void oclHostFree(OclHostBuf& b);

/**
 * GPU 掩码爆破:返回 0=命中(foundIdx=候选序号),1=跑完未命中,-1=GPU 不可用/出错。
 * hybrid 非空时混合调度:从 ctl.head 升序领块,CPU 侧从 ctl.tail 降序对向推进;
 * attemptsOut 非空时回写 GPU 侧实际尝试数(raw 计数,供组合速率)。
 */
int gpuCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos, uint64_t total,
                 uint64_t& foundIdx, std::string& err, HybridCtl* hybrid = nullptr,
                 uint64_t* attemptsOut = nullptr);

/**
 * GPU 字典爆破:words 按 stride 定长打包(零填充),count 条。
 * hybrid 时 rawMap(packed 序号 → 原字典序号)把 GPU 领块映射到与 CPU 侧一致的
 * 原字典序号空间(含被打包跳过的超长词);foundIdx 返回原字典序号。
 * pinned 非空且 pinned->ptr == words 时走 DMA 分段流水上传(拷贝与 kernel 重叠),
 * 并接收 pinned 的所有权;否则回退 CL_MEM_COPY_HOST_PTR 一次性上传。
 */
int gpuCrackDict(const GpuCrackParams& p, const uint8_t* words, size_t stride, uint64_t count,
                 uint64_t& foundIdx, std::string& err, HybridCtl* hybrid = nullptr,
                 const std::vector<size_t>* rawMap = nullptr, uint64_t* attemptsOut = nullptr,
                 OclHostBuf* pinned = nullptr);
