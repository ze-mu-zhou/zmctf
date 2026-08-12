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

/** 探测 OpenCL GPU 并预编译 kernel(进程内只初始化一次) */
GpuProbe gpuProbe();

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
 * GPU 掩码爆破:返回 0=命中(foundIdx=候选序号),1=跑完未命中,-1=GPU 不可用/出错。
 */
int gpuCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos, uint64_t total,
                 uint64_t& foundIdx, std::string& err);

/** GPU 字典爆破:words 按 stride 定长打包(零填充),count 条 */
int gpuCrackDict(const GpuCrackParams& p, const uint8_t* words, size_t stride, uint64_t count,
                 uint64_t& foundIdx, std::string& err);
