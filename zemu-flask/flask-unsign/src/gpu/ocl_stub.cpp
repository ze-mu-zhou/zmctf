#include "ocl.h"

#ifndef _WIN32

GpuProbe gpuProbe() {
  return {false, {}, "OpenCL 后端仅在 Windows 构建启用"};
}

bool gpuWarm() { return false; }

int gpuSmokeTest(std::string& err) {
  err = "Linux 构建未启用 OpenCL 后端";
  return -1;
}

OclHostBuf oclHostAlloc(size_t) { return {}; }

void oclHostFree(OclHostBuf& b) { b = OclHostBuf(); }

int gpuCrackMask(const GpuCrackParams&, const std::vector<std::string>&, uint64_t,
                 uint64_t&, std::string& err, HybridCtl*, uint64_t*) {
  err = "Linux 构建未启用 OpenCL 后端";
  return -1;
}

int gpuCrackDict(const GpuCrackParams&, const uint8_t*, size_t, uint64_t,
                 uint64_t&, std::string& err, HybridCtl*, const std::vector<size_t>*,
                 uint64_t*, OclHostBuf*) {
  err = "Linux 构建未启用 OpenCL 后端";
  return -1;
}

#endif
