/** ocl.cpp — OpenCL 动态加载 + JWT HS256 爆破调度。
 * 自声明 API 子集(不透明句柄),LoadLibrary("OpenCL.dll") 动态解析
 * (与 flask-unsign 的 ocl.cpp 同构,Win64 cdecl 兼容 ICD 导出)。
 */
#include "ocl.h"
#include "kernel_jwt.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <windows.h>

/* ---------- OpenCL API 子集 ---------- */
using cl_int = int32_t;
using cl_uint = uint32_t;
using cl_ulong = uint64_t;
using cl_platform_id = struct _cl_platform_id*;
using cl_device_id = struct _cl_device_id*;
using cl_context = struct _cl_context*;
using cl_command_queue = struct _cl_command_queue*;
using cl_program = struct _cl_program*;
using cl_kernel = struct _cl_kernel*;
using cl_mem = struct _cl_mem*;
using cl_event = struct _cl_event*;
using cl_device_type = cl_ulong;
using cl_platform_info = cl_uint;
using cl_device_info = cl_uint;
using cl_program_build_info = cl_uint;
using cl_mem_flags = cl_ulong;
using cl_command_queue_properties = cl_ulong;

#define CL_SUCCESS 0
#define CL_TRUE 1
#define CL_DEVICE_TYPE_GPU (1ULL << 2)
#define CL_DEVICE_NAME 0x102B
#define CL_DEVICE_MAX_COMPUTE_UNITS 0x102D
#define CL_MEM_READ_WRITE (1ULL << 0)
#define CL_MEM_READ_ONLY (1ULL << 2)
#define CL_MEM_COPY_HOST_PTR (1ULL << 5)
#define CL_PROGRAM_BUILD_LOG 0x1183

#define CL_FN(ret, name, args) typedef ret (*PFN_##name) args; static PFN_##name p_##name = nullptr
CL_FN(cl_int, clGetPlatformIDs, (cl_uint, cl_platform_id*, cl_uint*));
CL_FN(cl_int, clGetPlatformInfo, (cl_platform_id, cl_platform_info, size_t, void*, size_t*));
CL_FN(cl_int, clGetDeviceIDs, (cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*));
CL_FN(cl_int, clGetDeviceInfo, (cl_device_id, cl_device_info, size_t, void*, size_t*));
CL_FN(cl_context, clCreateContext, (const void*, cl_uint, const cl_device_id*, void*, void*, cl_int*));
CL_FN(cl_command_queue, clCreateCommandQueue, (cl_context, cl_device_id, cl_command_queue_properties, cl_int*));
CL_FN(cl_program, clCreateProgramWithSource, (cl_context, cl_uint, const char**, const size_t*, cl_int*));
CL_FN(cl_int, clBuildProgram, (cl_program, cl_uint, const cl_device_id*, const char*, void*, void*));
CL_FN(cl_int, clGetProgramBuildInfo, (cl_program, cl_device_id, cl_program_build_info, size_t, void*, size_t*));
CL_FN(cl_kernel, clCreateKernel, (cl_program, const char*, cl_int*));
CL_FN(cl_mem, clCreateBuffer, (cl_context, cl_mem_flags, size_t, void*, cl_int*));
CL_FN(cl_int, clSetKernelArg, (cl_kernel, cl_uint, size_t, const void*));
CL_FN(cl_int, clEnqueueWriteBuffer, (cl_command_queue, cl_mem, cl_uint, size_t, size_t, const void*, cl_uint, const cl_event*, cl_event*));
CL_FN(cl_int, clEnqueueReadBuffer, (cl_command_queue, cl_mem, cl_uint, size_t, size_t, void*, cl_uint, const cl_event*, cl_event*));
CL_FN(cl_int, clEnqueueNDRangeKernel, (cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, const cl_event*, cl_event*));
CL_FN(cl_int, clFinish, (cl_command_queue));
CL_FN(cl_int, clReleaseMemObject, (cl_mem));
CL_FN(cl_int, clReleaseKernel, (cl_kernel));
CL_FN(cl_int, clReleaseProgram, (cl_program));
CL_FN(cl_int, clReleaseCommandQueue, (cl_command_queue));
CL_FN(cl_int, clReleaseContext, (cl_context));
#undef CL_FN

namespace jose::gpu {

struct BufGuard {
  cl_mem m = nullptr;
  ~BufGuard() { if (m) p_clReleaseMemObject(m); }
};

static cl_mem makeRoBuf(cl_context ctx, const void* data, size_t n, cl_int* e) {
  return p_clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, n, const_cast<void*>(data), e);
}

struct OclCtx {
  bool ready = false;
  std::string deviceName;
  std::string error;
  cl_device_id dev = nullptr;
  cl_context ctx = nullptr;
  cl_command_queue q = nullptr;
  cl_program prog = nullptr;
  cl_kernel kMask = nullptr;
  cl_kernel kDict = nullptr;
};

static OclCtx g_ocl;

static bool resolveApi(HMODULE h) {
#define LOAD(name) p_##name = (PFN_##name)GetProcAddress(h, #name); if (!p_##name) return false
  LOAD(clGetPlatformIDs); LOAD(clGetPlatformInfo); LOAD(clGetDeviceIDs); LOAD(clGetDeviceInfo);
  LOAD(clCreateContext); LOAD(clCreateCommandQueue); LOAD(clCreateProgramWithSource);
  LOAD(clBuildProgram); LOAD(clGetProgramBuildInfo); LOAD(clCreateKernel);
  LOAD(clCreateBuffer); LOAD(clSetKernelArg); LOAD(clEnqueueWriteBuffer);
  LOAD(clEnqueueReadBuffer); LOAD(clEnqueueNDRangeKernel); LOAD(clFinish);
  LOAD(clReleaseMemObject); LOAD(clReleaseKernel); LOAD(clReleaseProgram);
  LOAD(clReleaseCommandQueue); LOAD(clReleaseContext);
#undef LOAD
  return true;
}

GpuProbe gpuProbe() {
  GpuProbe pr;
  if (g_ocl.ready) { pr.ok = true; pr.deviceName = g_ocl.deviceName; return pr; }
  HMODULE h = LoadLibraryA("OpenCL.dll");
  if (!h) { pr.error = "OpenCL.dll 不存在"; return pr; }
  if (!resolveApi(h)) { pr.error = "OpenCL API 解析失败"; return pr; }

  cl_uint nplat = 0;
  if (p_clGetPlatformIDs(0, nullptr, &nplat) != CL_SUCCESS || nplat == 0) {
    pr.error = "无 OpenCL 平台"; return pr;
  }
  std::vector<cl_platform_id> plats(nplat);
  p_clGetPlatformIDs(nplat, plats.data(), nullptr);
  cl_device_id dev = nullptr;
  std::string devName;
  for (auto plat : plats) {
    cl_uint ndev = 0;
    if (p_clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 0, nullptr, &ndev) != CL_SUCCESS || ndev == 0) continue;
    std::vector<cl_device_id> devs(ndev);
    p_clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, ndev, devs.data(), nullptr);
    dev = devs[0];
    char name[256] = {};
    size_t n = 0;
    if (p_clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof name - 1, name, &n) == CL_SUCCESS)
      devName = name;
    break;
  }
  if (!dev) { pr.error = "无 GPU 设备"; return pr; }

  cl_int e = CL_SUCCESS;
  cl_context ctx = p_clCreateContext(nullptr, 1, &dev, nullptr, nullptr, &e);
  if (!ctx) { pr.error = "clCreateContext 失败"; return pr; }
  cl_command_queue q = p_clCreateCommandQueue(ctx, dev, 0, &e);
  if (!q) { pr.error = "clCreateCommandQueue 失败"; return pr; }
  const char* src = JWT_KERNEL_SRC;
  size_t srclen = strlen(src);
  cl_program prog = p_clCreateProgramWithSource(ctx, 1, &src, &srclen, &e);
  if (!prog) { pr.error = "clCreateProgramWithSource 失败"; return pr; }
  e = p_clBuildProgram(prog, 1, &dev, "-cl-std=CL1.2", nullptr, nullptr);
  if (e != CL_SUCCESS) {
    char log[8192] = {};
    size_t l = 0;
    p_clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, sizeof log - 1, log, &l);
    pr.error = "kernel 编译失败: " + std::string(log);
    return pr;
  }
  cl_kernel kMask = p_clCreateKernel(prog, "jwt_crack_mask", &e);
  cl_kernel kDict = p_clCreateKernel(prog, "jwt_crack_dict", &e);
  if (!kMask || !kDict) { pr.error = "kernel 创建失败"; return pr; }

  g_ocl.ready = true;
  g_ocl.deviceName = devName;
  g_ocl.dev = dev;
  g_ocl.ctx = ctx;
  g_ocl.q = q;
  g_ocl.prog = prog;
  g_ocl.kMask = kMask;
  g_ocl.kDict = kDict;
  pr.ok = true;
  pr.deviceName = devName;
  return pr;
}

namespace {
struct KernelArgs {
  cl_context ctx;
  cl_command_queue q;
  cl_kernel k;
  BufGuard msgBuf, expectBuf, csetsBuf, csoffBuf, cslenBuf, wordsBuf, foundBuf;
  cl_int err = CL_SUCCESS;
};

void setIntArg(cl_kernel k, cl_uint idx, int v) {
  cl_int iv = v;
  p_clSetKernelArg(k, idx, sizeof iv, &iv);
}
void setUintArg(cl_kernel k, cl_uint idx, uint32_t v) {
  p_clSetKernelArg(k, idx, sizeof v, &v);
}
void setUlongArg(cl_kernel k, cl_uint idx, uint64_t v) {
  p_clSetKernelArg(k, idx, sizeof v, &v);
}
void setPtrArg(cl_kernel k, cl_uint idx, cl_mem m) {
  p_clSetKernelArg(k, idx, sizeof m, &m);
}
}  // namespace

namespace {
/** 执行一轮 NDRange 并检查错误;出错返回 false 并填充 err。lws=0 表示由 runtime 自选。 */
bool runChunk(cl_command_queue q, cl_kernel k, size_t gws, std::string& err, size_t lws = 0) {
  cl_int e = p_clEnqueueNDRangeKernel(q, k, 1, nullptr, &gws, lws ? &lws : nullptr, 0, nullptr, nullptr);
  if (e != CL_SUCCESS) { err = "clEnqueueNDRangeKernel 失败: " + std::to_string(e); return false; }
  e = p_clFinish(q);
  if (e != CL_SUCCESS) { err = "clFinish 失败: " + std::to_string(e); return false; }
  return true;
}

bool readFound(cl_command_queue q, cl_mem buf, uint32_t found[3], std::string& err) {
  cl_int e = p_clEnqueueReadBuffer(q, buf, CL_TRUE, 0, 12, found, 0, nullptr, nullptr);
  if (e != CL_SUCCESS) { err = "clEnqueueReadBuffer 失败: " + std::to_string(e); return false; }
  return true;
}

/** 字节流 → 大端 u32 字(kernel 零字节数组,全部按字加载) */
uint32_t be32(const uint8_t* p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

std::vector<uint32_t> packBe32(const std::vector<uint8_t>& in) {
  std::vector<uint32_t> out(in.size() / 4);
  for (std::size_t i = 0; i < out.size(); i++) out[i] = be32(in.data() + i * 4);
  return out;
}

/** 每 work-item 内层候选数(hashcat Loops 同款摊薄) */
constexpr std::uint64_t LOOP_N = 256;
}  // namespace

int gpuCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos,
                 std::uint64_t total, std::uint64_t& foundIdx, std::uint64_t& tried,
                 std::string& err) {
  if (!g_ocl.ready) { err = "GPU 未初始化"; return -1; }
  if (pos.size() > 64) { err = "掩码超过 64 位上限(GPU)"; return -1; }

  KernelArgs a;
  a.ctx = g_ocl.ctx;
  a.q = g_ocl.q;
  a.k = g_ocl.kMask;
  std::vector<uint32_t> msgW = packBe32(*p.msgBlocks);
  std::vector<uint32_t> expectW = packBe32(*p.expect);
  a.msgBuf.m = makeRoBuf(a.ctx, msgW.data(), msgW.size() * 4, &a.err);
  a.expectBuf.m = makeRoBuf(a.ctx, expectW.data(), expectW.size() * 4, &a.err);
  uint32_t found[3] = {0, 0, 0};
  a.foundBuf.m = p_clCreateBuffer(a.ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof found, found, &a.err);
  if (!a.msgBuf.m || !a.expectBuf.m || !a.foundBuf.m) { err = "显存分配失败"; return -1; }

  // 字符集打包
  std::vector<uint8_t> csets;
  std::vector<uint32_t> csoff, cslen;
  for (auto& c : pos) {
    csoff.push_back((uint32_t)csets.size());
    cslen.push_back((uint32_t)c.size());
    csets.insert(csets.end(), c.begin(), c.end());
  }
  a.csetsBuf.m = makeRoBuf(a.ctx, csets.data(), csets.size(), &a.err);
  a.csoffBuf.m = makeRoBuf(a.ctx, csoff.data(), csoff.size() * 4, &a.err);
  a.cslenBuf.m = makeRoBuf(a.ctx, cslen.data(), cslen.size() * 4, &a.err);
  if (!a.csetsBuf.m || !a.csoffBuf.m || !a.cslenBuf.m) { err = "显存分配失败"; return -1; }

  setPtrArg(a.k, 0, a.msgBuf.m);
  setIntArg(a.k, 1, p.nBlocks);
  setPtrArg(a.k, 2, a.expectBuf.m);
  setPtrArg(a.k, 3, a.csetsBuf.m);
  setPtrArg(a.k, 4, a.csoffBuf.m);
  setPtrArg(a.k, 5, a.cslenBuf.m);
  setUintArg(a.k, 6, (uint32_t)pos.size());
  setUintArg(a.k, 7, (uint32_t)LOOP_N);
  setPtrArg(a.k, 8, a.foundBuf.m);

  // 分块 enqueue:覆盖完整 keyspace,命中即提前退出
  // (kernel 每 work-item 处理 LOOP_N 个候选 → work-item 数 = ceil(n / LOOP_N))
  const std::uint64_t CHUNK = 1ULL << 28;  // 2.68 亿/块(提前退出粒度更细)
  tried = 0;
  for (std::uint64_t base = 0; base < total; base += CHUNK) {
    std::uint64_t n = std::min<std::uint64_t>(total - base, CHUNK);
    setUlongArg(a.k, 9, base);
    size_t gws = (size_t)((n + LOOP_N - 1) / LOOP_N);
    if (!runChunk(a.q, a.k, gws, err)) return -1;
    tried += n;
    if (!readFound(a.q, a.foundBuf.m, found, err)) return -1;
    if (found[0]) {
      foundIdx = (std::uint64_t)found[1] | ((std::uint64_t)found[2] << 32);
      return 0;
    }
  }
  return 1;
}

int gpuCrackDict(const GpuCrackParams& p, const std::uint8_t* words, std::size_t stride,
                 std::uint64_t count, std::uint64_t& foundIdx, std::uint64_t& tried,
                 std::string& err) {
  if (!g_ocl.ready) { err = "GPU 未初始化"; return -1; }
  if (stride != 64) { err = "字典 stride 必须为 64 字节"; return -1; }

  KernelArgs a;
  a.ctx = g_ocl.ctx;
  a.q = g_ocl.q;
  a.k = g_ocl.kDict;
  std::vector<uint32_t> msgW = packBe32(*p.msgBlocks);
  std::vector<uint32_t> expectW = packBe32(*p.expect);
  a.msgBuf.m = makeRoBuf(a.ctx, msgW.data(), msgW.size() * 4, &a.err);
  a.expectBuf.m = makeRoBuf(a.ctx, expectW.data(), expectW.size() * 4, &a.err);
  // 词条重打包为 BE u32(kernel 零字节数组,按字加载)
  std::vector<uint32_t> wordsW(count * 16);
  for (std::uint64_t i = 0; i < count * 16; i++) wordsW[i] = be32(words + i * 4);
  a.wordsBuf.m = makeRoBuf(a.ctx, wordsW.data(), wordsW.size() * 4, &a.err);
  uint32_t found[3] = {0, 0, 0};
  a.foundBuf.m = p_clCreateBuffer(a.ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof found, found, &a.err);
  if (!a.msgBuf.m || !a.expectBuf.m || !a.wordsBuf.m || !a.foundBuf.m) {
    err = "显存分配失败"; return -1;
  }

  setPtrArg(a.k, 0, a.msgBuf.m);
  setIntArg(a.k, 1, p.nBlocks);
  setPtrArg(a.k, 2, a.expectBuf.m);
  setPtrArg(a.k, 3, a.wordsBuf.m);
  setUlongArg(a.k, 4, (uint64_t)count);
  setUintArg(a.k, 5, (uint32_t)LOOP_N);
  setPtrArg(a.k, 6, a.foundBuf.m);

  // 分块 enqueue:命中即提前退出(kernel 每 work-item 处理 LOOP_N 个词条)
  const std::uint64_t CHUNK = 1ULL << 24;  // 1677 万/块
  tried = 0;
  for (std::uint64_t base = 0; base < count; base += CHUNK) {
    std::uint64_t n = std::min<std::uint64_t>(count - base, CHUNK);
    setUlongArg(a.k, 7, base);
    size_t gws = (size_t)((n + LOOP_N - 1) / LOOP_N);
    if (!runChunk(a.q, a.k, gws, err)) return -1;
    tried += n;
    if (!readFound(a.q, a.foundBuf.m, found, err)) return -1;
    if (found[0]) { foundIdx = found[1]; return 0; }
  }
  return 1;
}

}  // namespace jose::gpu
