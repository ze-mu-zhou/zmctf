/**
 * nvrtc.h:CUDA 后端主机端(NVRTC 运行时编译 + Driver API 发射,
 * 与 ocl.cpp 同为运行时 LoadLibrary 动态加载,零构建期依赖)。
 * 探测失败(无 NVRTC/无 CUDA 驱动)时返回错误,调用方自行回退。
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ocl.h" // GpuProbe / GpuCrackParams 复用

/** 探测 CUDA 后端并预编译 kernel(进程内只初始化一次) */
GpuProbe cudaProbe();

/** CUDA 掩码爆破:语义同 gpuCrackMask(0=命中,1=跑完未命中,-1=不可用/出错) */
int cudaCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos, uint64_t total,
                  uint64_t& foundIdx, std::string& err);

/**
 * pinned 主机缓冲(CUDA 字典打包直写用):cuMemAllocHost 分配 page-locked,
 * 直写后 cuMemcpyHtoD 走 DMA(免驱动对 pageable 源的内部二次拷贝)。
 * 分配失败返回空(ptr=nullptr),调用方回退普通 vector。
 * 交给 cudaCrackDict 的 pinned 参数后所有权转移(其负责 cuMemcpyHtoD 后 cuMemFreeHost),
 * 只有未交付时才由调用方 cudaHostFree。
 */
struct CudaHostBuf {
  void* ptr = nullptr;  // 可写 page-locked 主机地址
  size_t size = 0;
};
CudaHostBuf cudaHostAlloc(size_t bytes);
void cudaHostFree(CudaHostBuf& b);

/**
 * CUDA 字典爆破:语义同 gpuCrackDict(words 按 stride 定长打包)。
 * pinned 非空且 pinned->ptr == words 时视为 page-locked 源(cuMemcpyHtoD 走 DMA)
 * 并接收其所有权;否则按普通 pageable 内存处理。
 */
int cudaCrackDict(const GpuCrackParams& p, const uint8_t* words, size_t stride, uint64_t count,
                  uint64_t& foundIdx, std::string& err, CudaHostBuf* pinned = nullptr);
