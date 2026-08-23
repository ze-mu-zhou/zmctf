/** ocl.h — OpenCL GPU 爆破接口(HS256)。运行时 LoadLibrary 动态加载,零构建期依赖。 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace jose::gpu {

struct GpuProbe {
  bool ok = false;
  std::string deviceName;
  std::string error;
};

/** 探测 OpenCL GPU 并预编译 kernel(进程内只初始化一次) */
GpuProbe gpuProbe();

struct GpuCrackParams {
  const std::vector<std::uint8_t>* msgBlocks = nullptr;  // 签名输入完整填充块
  int nBlocks = 0;
  const std::vector<std::uint8_t>* expect = nullptr;     // 期望签名 32B
};

/** 掩码爆破:返回 0=命中(foundIdx=候选序号),1=跑完未命中,-1=GPU 出错。
 * 分块调度覆盖完整 keyspace,命中提前退出;tried 输出实际计算的候选数。 */
int gpuCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos,
                 std::uint64_t total, std::uint64_t& foundIdx, std::uint64_t& tried,
                 std::string& err);

/** 字典爆破:words 定长打包(stride),count 条;tried 输出实际计算的候选数。 */
int gpuCrackDict(const GpuCrackParams& p, const std::uint8_t* words, std::size_t stride,
                 std::uint64_t count, std::uint64_t& foundIdx, std::uint64_t& tried,
                 std::string& err);

}  // namespace jose::gpu
