/**
 * ocl.cpp:OpenCL 动态加载 + 爆破调度。
 * 自声明 API 子集(不透明句柄 + 少量常量),LoadLibrary("OpenCL.dll") +
 * GetProcAddress 解析,免去 Khronos 头文件/导入库依赖;Win64 统一调用约定,
 * 与 ICD  cdecl 导出兼容。
 */
#include "ocl.h"
#include "kernel_cl.h"
#include "divmagic.h"
#include "../crack_cpu.h"
#include "../sha1.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <windows.h>

/* ---------- OpenCL API 子集声明 ---------- */
using cl_int = int32_t;
using cl_uint = uint32_t;
using cl_ulong = uint64_t;
using cl_platform_id = struct _cl_platform_id*; // 不透明句柄,前置声明内联完成
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
#define CL_MEM_READ_WRITE (1ULL << 0)
#define CL_MEM_READ_ONLY (1ULL << 2)
#define CL_MEM_COPY_HOST_PTR (1ULL << 5)
#define CL_PROGRAM_BUILD_LOG 0x1183
#define CL_PROGRAM_BINARY_SIZES 0x1165
#define CL_PROGRAM_BINARIES 0x1166

#define CL_FN(ret, name, args) typedef ret (*PFN_##name) args; static PFN_##name p_##name = nullptr
CL_FN(cl_int, clGetPlatformIDs, (cl_uint, cl_platform_id*, cl_uint*));
CL_FN(cl_int, clGetPlatformInfo, (cl_platform_id, cl_platform_info, size_t, void*, size_t*));
CL_FN(cl_int, clGetDeviceIDs, (cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*));
CL_FN(cl_int, clGetDeviceInfo, (cl_device_id, cl_device_info, size_t, void*, size_t*));
CL_FN(cl_context, clCreateContext, (const void*, cl_uint, const cl_device_id*, void*, void*, cl_int*));
CL_FN(cl_command_queue, clCreateCommandQueue, (cl_context, cl_device_id, cl_command_queue_properties, cl_int*));
CL_FN(cl_program, clCreateProgramWithSource, (cl_context, cl_uint, const char**, const size_t*, cl_int*));
CL_FN(cl_program, clCreateProgramWithBinary, (cl_context, cl_uint, const cl_device_id*, const size_t*, const unsigned char**, cl_int*, cl_int*));
CL_FN(cl_int, clGetProgramInfo, (cl_program, cl_uint, size_t, void*, size_t*));
CL_FN(cl_int, clBuildProgram, (cl_program, cl_uint, const cl_device_id*, const char*, void*, void*));
CL_FN(cl_int, clGetProgramBuildInfo, (cl_program, cl_device_id, cl_program_build_info, size_t, void*, size_t*));
CL_FN(cl_kernel, clCreateKernel, (cl_program, const char*, cl_int*));
CL_FN(cl_int, clGetKernelWorkGroupInfo, (cl_kernel, cl_device_id, cl_uint, size_t, void*, size_t*));
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

/* ---------- 缓冲区助手 ---------- */
struct BufGuard {
  cl_mem m = nullptr;
  ~BufGuard() { if (m) p_clReleaseMemObject(m); }
};

static cl_mem makeRoBuf(cl_context ctx, const void* data, size_t n, cl_int* e) {
  return p_clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, n, const_cast<void*>(data), e);
}

/* ---------- 运行时上下文(进程内单例) ---------- */
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
  size_t lws = 0; // 调参得到的 local work size;0 = 驱动自选
};

/**
 * LWS 微基准调参(借鉴 hashcat autotune 的 Threads 维度,只做安全的 host 侧旋钮):
 * 合成掩码负载(expect 永不命中)逐档位计时取最快。仅冷缓存时跑一次(~0.4s),
 * 结果随编译产物写进 flask_crack_ocl.bin;ZK_LWS=<n> 强制,ZK_NOTUNE=1 跳过。
 * 档位超出 kernel 上限(本 kernel wgs=256)会被驱动拒绝,自动跳过。
 */
static size_t tuneLws(OclCtx& c) {
  const uint64_t TOTAL = 1ULL << 25; // 32M 候选/档/遍,~50ms 量级
  uint32_t saltTw[16] = {0}, valueTw[16] = {0}, ew[5];
  memset(ew, 0xAA, sizeof ew);
  uint8_t csbuf[208]; // 8 位 ×26 字母:与真实掩码的候选生成开销占比一致
  uint32_t csoff[8], cslen[8];
  for (int k = 0; k < 8; k++) {
    csoff[k] = k * 26;
    cslen[k] = 26;
    for (int i = 0; i < 26; i++) csbuf[k * 26 + i] = (uint8_t)('a' + i);
  }
  cl_int e = CL_SUCCESS;
  uint64_t mag[8];
  uint32_t flg[8];
  for (int k = 0; k < 8; k++) {
    DivMagic dm = divMagicFor(26);
    mag[k] = dm.m;
    flg[k] = dm.flag;
  }
  BufGuard bSalt, bValue, bCsbuf, bCsoff, bCslen, bCsmag, bCsflg, bFound;
  bSalt.m = makeRoBuf(c.ctx, saltTw, sizeof saltTw, &e);
  bValue.m = makeRoBuf(c.ctx, valueTw, sizeof valueTw, &e);
  bCsbuf.m = makeRoBuf(c.ctx, csbuf, sizeof csbuf, &e);
  bCsoff.m = makeRoBuf(c.ctx, csoff, sizeof csoff, &e);
  bCslen.m = makeRoBuf(c.ctx, cslen, sizeof cslen, &e);
  bCsmag.m = makeRoBuf(c.ctx, mag, sizeof mag, &e);
  bCsflg.m = makeRoBuf(c.ctx, flg, sizeof flg, &e);
  bFound.m = p_clCreateBuffer(c.ctx, CL_MEM_READ_WRITE, 8, nullptr, &e);
  if (!bSalt.m || !bValue.m || !bCsbuf.m || !bCsoff.m || !bCslen.m ||
      !bCsmag.m || !bCsflg.m || !bFound.m)
    return 0;
  cl_kernel k = c.kMask;
  uint32_t one = 1, npos = 8;
  uint64_t total64 = TOTAL, base0 = 0;
  p_clSetKernelArg(k, 0, sizeof(cl_mem), &bSalt.m);
  p_clSetKernelArg(k, 1, 4, &one);
  p_clSetKernelArg(k, 2, sizeof(cl_mem), &bValue.m);
  p_clSetKernelArg(k, 3, 4, &one);
  for (int i = 0; i < 5; i++) p_clSetKernelArg(k, 4 + i, 4, &ew[i]);
  p_clSetKernelArg(k, 9, sizeof(cl_mem), &bCsbuf.m);
  p_clSetKernelArg(k, 10, sizeof(cl_mem), &bCsoff.m);
  p_clSetKernelArg(k, 11, sizeof(cl_mem), &bCslen.m);
  p_clSetKernelArg(k, 12, sizeof(cl_mem), &bCsmag.m);
  p_clSetKernelArg(k, 13, sizeof(cl_mem), &bCsflg.m);
  p_clSetKernelArg(k, 14, 4, &npos);
  p_clSetKernelArg(k, 15, 8, &base0);
  p_clSetKernelArg(k, 16, 8, &total64);
  p_clSetKernelArg(k, 17, sizeof(cl_mem), &bFound.m);
  LARGE_INTEGER freq;
  QueryPerformanceFrequency(&freq);
  // 全尺寸热身:让 GPU 完成升频/驱动就绪,避免首个测量档吃顺序亏
  size_t off = 0;
  if (p_clEnqueueNDRangeKernel(c.q, k, 1, &off, (const size_t[]){(size_t)TOTAL}, nullptr, 0, nullptr, nullptr) != CL_SUCCESS)
    return 0;
  p_clFinish(c.q);
  static const size_t CANDS[] = {0, 64, 128, 256, 512, 1024}; // 0 = 驱动自选
  double msBest[sizeof CANDS / sizeof CANDS[0]];
  for (size_t i = 0; i < sizeof CANDS / sizeof CANDS[0]; i++) msBest[i] = 1e30;
  for (int rep = 0; rep < 2; rep++) { // 两遍全表取最小,压住热噪声与顺序偏差
    for (size_t i = 0; i < sizeof CANDS / sizeof CANDS[0]; i++) {
      size_t L = CANDS[i];
      size_t gws = L ? (size_t)((TOTAL + L - 1) / L) * L : (size_t)TOTAL;
      const size_t* plws = L ? &CANDS[i] : nullptr;
      int64_t neg = -1;
      p_clEnqueueWriteBuffer(c.q, bFound.m, CL_TRUE, 0, 8, &neg, 0, nullptr, nullptr);
      LARGE_INTEGER t0, t1;
      QueryPerformanceCounter(&t0);
      cl_int ee = p_clEnqueueNDRangeKernel(c.q, k, 1, &off, &gws, plws, 0, nullptr, nullptr);
      if (ee != CL_SUCCESS) continue; // 超 kernel/设备上限,该档作废
      p_clFinish(c.q);
      QueryPerformanceCounter(&t1);
      double m = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
      if (m < msBest[i]) msBest[i] = m;
    }
  }
  size_t best = 0;
  double bestMs = 1e30;
  std::string dbg;
  for (size_t i = 0; i < sizeof CANDS / sizeof CANDS[0]; i++) {
    if (msBest[i] >= 1e29) continue;
    if (getenv("ZK_KINFO")) {
      char line[64];
      snprintf(line, sizeof line, "  lws=%zu: %.1f ms", CANDS[i], msBest[i]);
      dbg += line;
    }
    if (msBest[i] < bestMs) { bestMs = msBest[i]; best = CANDS[i]; }
  }
  if (getenv("ZK_KINFO"))
    fprintf(stderr, "[kinfo] LWS 调参:%s → 选 %zu\n", dbg.c_str(), best);
  return best;
}

static bool loadApi(std::string& err) {
  static HMODULE dll = [] {
    HMODULE h = LoadLibraryA("OpenCL.dll");
    return h;
  }();
  if (!dll) {
    err = "OpenCL.dll 加载失败(无显卡驱动?)";
    return false;
  }
  bool ok = true;
#define RESOLVE(name) \
  if (!p_##name) { p_##name = (PFN_##name)(void*)GetProcAddress(dll, #name); ok = ok && p_##name; }
  RESOLVE(clGetPlatformIDs) RESOLVE(clGetPlatformInfo) RESOLVE(clGetDeviceIDs)
  RESOLVE(clGetDeviceInfo) RESOLVE(clCreateContext) RESOLVE(clCreateCommandQueue)
  RESOLVE(clCreateProgramWithSource) RESOLVE(clCreateProgramWithBinary) RESOLVE(clGetProgramInfo)
  RESOLVE(clBuildProgram) RESOLVE(clGetProgramBuildInfo)
  RESOLVE(clCreateKernel) RESOLVE(clGetKernelWorkGroupInfo) RESOLVE(clCreateBuffer) RESOLVE(clSetKernelArg)
  RESOLVE(clEnqueueWriteBuffer) RESOLVE(clEnqueueReadBuffer) RESOLVE(clEnqueueNDRangeKernel)
  RESOLVE(clFinish) RESOLVE(clReleaseMemObject) RESOLVE(clReleaseKernel)
  RESOLVE(clReleaseProgram) RESOLVE(clReleaseCommandQueue) RESOLVE(clReleaseContext)
#undef RESOLVE
  if (!ok) err = "OpenCL.dll 导出函数不完整";
  return ok;
}

static OclCtx* g_peek = nullptr; // ocl() 初始化后指向单例;gpuWarm() 无副作用窥视用

static OclCtx& ocl() {
  static OclCtx c;
  static bool inited = false;
  if (inited) return c;
  inited = true;
  g_peek = &c;

  if (!loadApi(c.error)) return c;

  // 枚举平台,取第一个有 GPU 设备的
  cl_uint nplat = 0;
  p_clGetPlatformIDs(0, nullptr, &nplat);
  if (nplat == 0) { c.error = "无 OpenCL 平台"; return c; }
  std::vector<cl_platform_id> plats(nplat);
  p_clGetPlatformIDs(nplat, plats.data(), nullptr);
  cl_platform_id plat = nullptr;
  for (auto p : plats) {
    cl_uint ndev = 0;
    if (p_clGetDeviceIDs(p, CL_DEVICE_TYPE_GPU, 0, nullptr, &ndev) == CL_SUCCESS && ndev > 0) {
      plat = p;
      break;
    }
  }
  if (!plat) { c.error = "无 OpenCL GPU 设备"; return c; }
  cl_int e = CL_SUCCESS;
  if (p_clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &c.dev, nullptr) != CL_SUCCESS) {
    c.error = "取 GPU 设备失败";
    return c;
  }
  char name[256] = {0};
  p_clGetDeviceInfo(c.dev, CL_DEVICE_NAME, sizeof name, name, nullptr);
  c.deviceName = name;

  c.ctx = p_clCreateContext(nullptr, 1, &c.dev, nullptr, nullptr, &e);
  if (e != CL_SUCCESS) { c.error = "创建 context 失败"; return c; }
  c.q = p_clCreateCommandQueue(c.ctx, c.dev, 0, &e);
  if (e != CL_SUCCESS) { c.error = "创建 queue 失败"; return c; }
  const char* src = FLASK_CRACK_CL;
  size_t srcLen = strlen(src);

  // ---- 编译产物缓存:NVIDIA 从源码 JIT 要 0.1~2s,落盘后启动 <10ms ----
  // 文件格式:[u32 magic][u32 devNameLen][devName][u32 tunedLws][binary]
  // magic 含版本号,kernel 签名/缓存格式变更即 bump,旧缓存自动失效重建
  const uint32_t CACHE_MAGIC = 0x5A4B4E11; // "ZKN" v17(v17:tail 预转大端字 + expect 按值传参)
  char exePath[MAX_PATH] = {0};
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  std::string cachePath = exePath;
  size_t slash = cachePath.find_last_of("\\/");
  cachePath = (slash == std::string::npos ? "." : cachePath.substr(0, slash)) + "\\flask_crack_ocl.bin";

  bool loaded = false;
  uint32_t cachedLws = 0;
  if (FILE* f = fopen(cachePath.c_str(), "rb")) {
    uint32_t magic = 0, nameLen = 0;
    if (fread(&magic, 4, 1, f) == 1 && magic == CACHE_MAGIC &&
        fread(&nameLen, 4, 1, f) == 1 && nameLen < 256) {
      char devName[256] = {0};
      if (fread(devName, 1, nameLen, f) == nameLen && c.deviceName == devName) {
        uint32_t lws32 = 0;
        fseek(f, 0, SEEK_END);
        long binSize = ftell(f) - 12 - (long)nameLen;
        fseek(f, 8 + (long)nameLen, SEEK_SET);
        if (binSize > 0 && fread(&lws32, 4, 1, f) == 1) {
          std::vector<uint8_t> bin((size_t)binSize);
          if (fread(bin.data(), 1, bin.size(), f) == bin.size()) {
            const unsigned char* pb = bin.data();
            size_t sz = bin.size();
            cl_int bs = 0;
            c.prog = p_clCreateProgramWithBinary(c.ctx, 1, &c.dev, &sz, &pb, &bs, &e);
            if (c.prog && e == CL_SUCCESS &&
                p_clBuildProgram(c.prog, 1, &c.dev, "", nullptr, nullptr) == CL_SUCCESS) {
              loaded = true;
              cachedLws = lws32;
            } else if (c.prog) {
              p_clReleaseProgram(c.prog);
              c.prog = nullptr;
            }
          }
        }
      }
    }
    fclose(f);
  }

  if (!loaded) {
    c.prog = p_clCreateProgramWithSource(c.ctx, 1, &src, &srcLen, &e);
    if (e != CL_SUCCESS) { c.error = "创建 program 失败"; return c; }
    // 注:-cl-nv-maxrregcount 在现行 NVIDIA OpenCL 驱动上被静默忽略(实测 wgs 不变)。
    // NVRTC/CUDA 第二后端(src/gpu/nvrtc.cpp,--engine cuda,掩码+字典)与 OpenCL
    // 后端速率相当——"CUDA 工具链更快"对本 kernel 结构不成立;hashcat CUDA 的
    // 优势来自其 kernel 结构(Loops 摊销),非编译链。块大小 128/256/512 实测全平
    // (占用率非瓶颈,指令吞吐 bound)。
    e = p_clBuildProgram(c.prog, 1, &c.dev, "", nullptr, nullptr);
    if (e != CL_SUCCESS) {
      char log[4096] = {0};
      p_clGetProgramBuildInfo(c.prog, c.dev, CL_PROGRAM_BUILD_LOG, sizeof log, log, nullptr);
      c.error = std::string("kernel 编译失败: ") + log;
      return c;
    }
  }

  c.kMask = p_clCreateKernel(c.prog, "crack_mask", &e);
  c.kDict = p_clCreateKernel(c.prog, "crack_dict", &e);
  if (!c.kMask || !c.kDict) { c.error = "创建 kernel 失败"; return c; }

  // ---- LWS:ZK_LWS 强制 > 缓存值 > 冷缓存现场调参(结果随缓存落盘) ----
  if (const char* v = getenv("ZK_LWS")) {
    long n = atol(v);
    c.lws = n > 0 ? (size_t)n : 0;
  } else if (loaded) {
    c.lws = cachedLws;
  } else {
    c.lws = getenv("ZK_NOTUNE") ? 0 : tuneLws(c);
    // 保存编译产物 + 调参结果(失败不影响功能)
    size_t binSize = 0;
    if (p_clGetProgramInfo(c.prog, CL_PROGRAM_BINARY_SIZES, sizeof binSize, &binSize, nullptr) == CL_SUCCESS && binSize > 0) {
      std::vector<uint8_t> bin(binSize);
      uint8_t* pb = bin.data();
      if (p_clGetProgramInfo(c.prog, CL_PROGRAM_BINARIES, sizeof pb, &pb, nullptr) == CL_SUCCESS) {
        if (FILE* f = fopen(cachePath.c_str(), "wb")) {
          uint32_t nameLen = (uint32_t)c.deviceName.size();
          uint32_t lws32 = (uint32_t)c.lws;
          fwrite(&CACHE_MAGIC, 4, 1, f);
          fwrite(&nameLen, 4, 1, f);
          fwrite(c.deviceName.data(), 1, nameLen, f);
          fwrite(&lws32, 4, 1, f);
          fwrite(bin.data(), 1, bin.size(), f);
          fclose(f);
        }
      }
    }
  }
  // 诊断:ZK_KINFO=1 时打印 kernel 资源占用(private=spill 字节,wgs 反映占用率上限)
  if (getenv("ZK_KINFO")) {
    for (int t = 0; t < 2; t++) {
      cl_kernel kk = t ? c.kDict : c.kMask;
      const char* nm = t ? "dict" : "mask";
      size_t wgs = 0; cl_ulong lm = 0, pm = 0;
      p_clGetKernelWorkGroupInfo(kk, c.dev, 0x11B0, sizeof wgs, &wgs, nullptr);
      p_clGetKernelWorkGroupInfo(kk, c.dev, 0x11B2, 8, &lm, nullptr);
      p_clGetKernelWorkGroupInfo(kk, c.dev, 0x11B4, 8, &pm, nullptr);
      fprintf(stderr, "[kinfo] %s: wgs=%zu local=%lluB private=%lluB\n",
              nm, wgs, (unsigned long long)lm, (unsigned long long)pm);
    }
    fprintf(stderr, "[kinfo] lws=%zu(0=驱动自选)\n", c.lws);
  }
  c.ready = true;
  return c;
}

GpuProbe gpuProbe() {
  OclCtx& c = ocl();
  GpuProbe r;
  r.ok = c.ready;
  r.deviceName = c.deviceName;
  r.error = c.error;
  return r;
}

bool gpuWarm() {
  return g_peek && g_peek->ready;
}

/** 冒烟测试:跑一个只写常量的 kernel,验证 OpenCL 基础链路 */
int gpuSmokeTest(std::string& err) {
  OclCtx& c = ocl();
  if (!c.ready) { err = c.error; return -1; }
  cl_int e = CL_SUCCESS;
  cl_kernel k = p_clCreateKernel(c.prog, "probe_ok", &e);
  if (!k) { err = "创建 probe kernel 失败"; return -1; }
  cl_mem found = p_clCreateBuffer(c.ctx, CL_MEM_READ_WRITE, 8, nullptr, &e);
  if (!found) { err = "创建缓冲区失败"; return -1; }
  int64_t neg = -1;
  p_clEnqueueWriteBuffer(c.q, found, CL_TRUE, 0, 8, &neg, 0, nullptr, nullptr);
  p_clSetKernelArg(k, 0, sizeof(cl_mem), &found);
  size_t one = 1, zero = 0;
  e = p_clEnqueueNDRangeKernel(c.q, k, 1, &zero, &one, nullptr, 0, nullptr, nullptr);
  if (e != CL_SUCCESS) { err = "enqueue 失败"; return -1; }
  p_clFinish(c.q);
  int64_t v = -1;
  p_clEnqueueReadBuffer(c.q, found, CL_TRUE, 0, 8, &v, 0, nullptr, nullptr);
  p_clReleaseMemObject(found);
  p_clReleaseKernel(k);
  if (v != 12345) { err = "probe 结果异常"; return 1; }
  return 0;
}

// 每次 enqueue 的候选规模基准:16.7M(全速 ~23ms),远低于 TDR 2s 上限,
// 块间同步开销摊薄到 <0.5%,也保留命中早退与取消的粒度
#define CHUNK_CAND (1ULL << 24)

/** 公共调度:分块 enqueue,块间读 found 早退;total 越界保护由 kernel 负责。
 *  hybrid 非空时改为混合调度:从 ctl.head 升序领块,块间查 ctl.stop(CPU 侧命中)。
 *  rawMap 非空(字典)时块号是原字典序号空间,二分映射到 packed 子区间再 enqueue。 */
static int runChunks(OclCtx& c, cl_kernel k, cl_mem foundBuf, uint64_t total, int baseArgIdx,
                     int totalArgIdx, uint64_t& foundIdx, std::string& err,
                     HybridCtl* hyb = nullptr, const std::vector<size_t>* rawMap = nullptr,
                     uint64_t* attemptsOut = nullptr) {
  cl_int e = p_clSetKernelArg(k, totalArgIdx, sizeof(uint64_t), &total);
  if (e != CL_SUCCESS) { err = "设置 total 参数失败"; return -1; }
  using clk = std::chrono::steady_clock;
  auto t0 = clk::now();
  auto lastPrint = t0;

  if (hyb) {
    // ---- 混合调度:与 CPU 对向推进;越界进入 CPU 认领区即止(重叠≤1 块,重复验无害) ----
    uint64_t attempted = 0;
    while (!hyb->stop.load(std::memory_order_relaxed)) {
      uint64_t base = hyb->head.fetch_add(CHUNK_CAND, std::memory_order_relaxed);
      if (base >= total) break;
      if (base >= hyb->tail.load(std::memory_order_relaxed)) break; // 剩余归 CPU
      uint64_t end = base + CHUNK_CAND < total ? base + CHUNK_CAND : total;
      attempted += end - base;
      uint64_t pLo = base, pHi = end; // packed 子区间(掩码:与 raw 同空间)
      if (rawMap) {
        pLo = (uint64_t)(std::lower_bound(rawMap->begin(), rawMap->end(), (size_t)base) - rawMap->begin());
        pHi = (uint64_t)(std::lower_bound(rawMap->begin(), rawMap->end(), (size_t)end) - rawMap->begin());
      }
      if (pHi > pLo) { // 整块都是超长词(dict)时只计数不 enqueue
        uint64_t pbase = pLo, ptotal = pHi;
        p_clSetKernelArg(k, baseArgIdx, sizeof(uint64_t), &pbase);
        p_clSetKernelArg(k, totalArgIdx, sizeof(uint64_t), &ptotal);
        size_t cnt = (size_t)(pHi - pLo);
        size_t offset = 0, gws = cnt, lws = c.lws, *plws = nullptr;
        if (lws) { gws = (cnt + lws - 1) / lws * lws; plws = &lws; }
        e = p_clEnqueueNDRangeKernel(c.q, k, 1, &offset, &gws, plws, 0, nullptr, nullptr);
        if (e != CL_SUCCESS) {
          hyb->stop.store(true, std::memory_order_relaxed);
          if (attemptsOut) *attemptsOut = attempted;
          err = "enqueue 失败";
          return -1;
        }
        p_clFinish(c.q);
        auto now = clk::now();
        if (now - lastPrint >= std::chrono::seconds(10)) {
          double el = std::chrono::duration<double>(now - t0).count();
          fprintf(stderr, "[~] 进度 %llu/%llu(%.1f%%),%.0fM/s\n",
                  (unsigned long long)attempted, (unsigned long long)total,
                  attempted * 100.0 / total, (el > 0 ? attempted / el : 0) / 1e6);
          lastPrint = now;
        }
        if (g_crackAbort.load(std::memory_order_relaxed)) {
          hyb->stop.store(true, std::memory_order_relaxed);
          if (attemptsOut) *attemptsOut = attempted;
          return 1;
        }
        int64_t found = -1;
        p_clEnqueueReadBuffer(c.q, foundBuf, CL_TRUE, 0, sizeof found, &found, 0, nullptr, nullptr);
        if (found >= 0) {
          foundIdx = rawMap ? (uint64_t)(*rawMap)[(size_t)found] : (uint64_t)found;
          hyb->stop.store(true, std::memory_order_relaxed);
          if (attemptsOut) *attemptsOut = attempted;
          return 0;
        }
      }
    }
    if (attemptsOut) *attemptsOut = attempted;
    return 1; // GPU 侧完毕(跑完/被 CPU 命中叫停/进入 CPU 区),未命中
  }

  uint64_t done = 0;
  for (uint64_t base = 0; base < total; base += CHUNK_CAND) {
    size_t cand = (size_t)(total - base < CHUNK_CAND ? total - base : CHUNK_CAND);
    e = p_clSetKernelArg(k, baseArgIdx, sizeof(uint64_t), &base);
    if (e != CL_SUCCESS) { err = "设置 base 参数失败"; return -1; }
    size_t offset = 0;
    size_t gws = cand, lws = c.lws, *plws = nullptr;
    if (lws) { // 显式 local size:global 向上取整,kernel 内 total 边界检查兜底
      gws = (cand + lws - 1) / lws * lws;
      plws = &lws;
    }
    e = p_clEnqueueNDRangeKernel(c.q, k, 1, &offset, &gws, plws, 0, nullptr, nullptr);
    if (e != CL_SUCCESS) { err = "enqueue 失败"; return -1; }
    p_clFinish(c.q);
    done += cand;
    auto now = clk::now();
    if (now - lastPrint >= std::chrono::seconds(10)) { // 长任务进度(10s 一报)
      double el = std::chrono::duration<double>(now - t0).count();
      fprintf(stderr, "[~] 进度 %llu/%llu(%.1f%%),%.0fM/s\n",
              (unsigned long long)done, (unsigned long long)total,
              done * 100.0 / total, (el > 0 ? done / el : 0) / 1e6);
      lastPrint = now;
    }
    if (g_crackAbort.load(std::memory_order_relaxed)) return 1;
    int64_t found = -1;
    p_clEnqueueReadBuffer(c.q, foundBuf, CL_TRUE, 0, sizeof found, &found, 0, nullptr, nullptr);
    if (found >= 0) {
      foundIdx = (uint64_t)found;
      return 0;
    }
  }
  return 1;
}

int gpuCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos, uint64_t total,
                 uint64_t& foundIdx, std::string& err, HybridCtl* hybrid, uint64_t* attemptsOut) {
  OclCtx& c = ocl();
  if (!c.ready) { err = c.error; return -1; }
  if (p.vlen > 512 || p.slen > 32 || pos.size() > 24) {
    err = "GPU 参数超限(value ≤ 512B,salt ≤ 32B,掩码 ≤ 24 位)";
    return -1;
  }
  // HMAC 预计算:salt/value 都是固定消息,主机端拼好尾块(衔接 ipad 块后)
  HmacFixedMsg saltPc, valuePc;
  saltPc.init(p.salt, p.slen);
  valuePc.init(p.value, p.vlen);
  // 字符集打包:csbuf + 偏移/长度表 + 每位除法魔数
  std::vector<uint8_t> csbuf;
  std::vector<uint32_t> csoff, cslen, csflg;
  std::vector<uint64_t> csmag;
  for (const auto& cs : pos) {
    csoff.push_back((uint32_t)csbuf.size());
    cslen.push_back((uint32_t)cs.size());
    DivMagic dm = divMagicFor((uint32_t)cs.size());
    csmag.push_back(dm.m);
    csflg.push_back(dm.flag);
    csbuf.insert(csbuf.end(), cs.begin(), cs.end());
  }
  cl_int e = CL_SUCCESS;
  BufGuard bSaltTail, bValueTail, bCsbuf, bCsoff, bCslen, bCsmag, bCsflg, bFound;
  bSaltTail.m = makeRoBuf(c.ctx, saltPc.tailw.data(), saltPc.tailw.size() * 4, &e);
  bValueTail.m = makeRoBuf(c.ctx, valuePc.tailw.data(), valuePc.tailw.size() * 4, &e);
  bCsbuf.m = makeRoBuf(c.ctx, csbuf.data(), csbuf.size(), &e);
  bCsoff.m = makeRoBuf(c.ctx, csoff.data(), csoff.size() * 4, &e);
  bCslen.m = makeRoBuf(c.ctx, cslen.data(), cslen.size() * 4, &e);
  bCsmag.m = makeRoBuf(c.ctx, csmag.data(), csmag.size() * 8, &e);
  bCsflg.m = makeRoBuf(c.ctx, csflg.data(), csflg.size() * 4, &e);
  bFound.m = p_clCreateBuffer(c.ctx, CL_MEM_READ_WRITE, 8, nullptr, &e);
  if (!bSaltTail.m || !bValueTail.m || !bCsbuf.m || !bCsoff.m || !bCslen.m ||
      !bCsmag.m || !bCsflg.m || !bFound.m) {
    err = "创建缓冲区失败";
    return -1;
  }
  int64_t neg = -1;
  p_clEnqueueWriteBuffer(c.q, bFound.m, CL_TRUE, 0, 8, &neg, 0, nullptr, nullptr);

  cl_kernel k = c.kMask;
  uint32_t saltBlocks = (uint32_t)saltPc.tailBlocks();
  uint32_t valueBlocks = (uint32_t)valuePc.tailBlocks();
  uint32_t npos = (uint32_t)pos.size();
  uint32_t ew[5];
  beWords20(p.expect, ew);
  p_clSetKernelArg(k, 0, sizeof(cl_mem), &bSaltTail.m);
  p_clSetKernelArg(k, 1, 4, &saltBlocks);
  p_clSetKernelArg(k, 2, sizeof(cl_mem), &bValueTail.m);
  p_clSetKernelArg(k, 3, 4, &valueBlocks);
  for (int i = 0; i < 5; i++) p_clSetKernelArg(k, 4 + i, 4, &ew[i]);
  p_clSetKernelArg(k, 9, sizeof(cl_mem), &bCsbuf.m);
  p_clSetKernelArg(k, 10, sizeof(cl_mem), &bCsoff.m);
  p_clSetKernelArg(k, 11, sizeof(cl_mem), &bCslen.m);
  p_clSetKernelArg(k, 12, sizeof(cl_mem), &bCsmag.m);
  p_clSetKernelArg(k, 13, sizeof(cl_mem), &bCsflg.m);
  p_clSetKernelArg(k, 14, 4, &npos);
  p_clSetKernelArg(k, 17, sizeof(cl_mem), &bFound.m);
  return runChunks(c, k, bFound.m, total, 15, 16, foundIdx, err, hybrid, nullptr, attemptsOut);
}

int gpuCrackDict(const GpuCrackParams& p, const uint8_t* words, size_t stride, uint64_t count,
                 uint64_t& foundIdx, std::string& err, HybridCtl* hybrid,
                 const std::vector<size_t>* rawMap, uint64_t* attemptsOut) {
  OclCtx& c = ocl();
  if (!c.ready) { err = c.error; return -1; }
  if (p.vlen > 512 || p.slen > 32) {
    err = "GPU 参数超限(value ≤ 512B,salt ≤ 32B)";
    return -1;
  }
  // HMAC 预计算:salt/value 都是固定消息,主机端拼好尾块(衔接 ipad 块后)
  HmacFixedMsg saltPc, valuePc;
  saltPc.init(p.salt, p.slen);
  valuePc.init(p.value, p.vlen);
  cl_int e = CL_SUCCESS;
  BufGuard bSaltTail, bValueTail, bWords, bFound;
  bSaltTail.m = makeRoBuf(c.ctx, saltPc.tailw.data(), saltPc.tailw.size() * 4, &e);
  bValueTail.m = makeRoBuf(c.ctx, valuePc.tailw.data(), valuePc.tailw.size() * 4, &e);
  bWords.m = makeRoBuf(c.ctx, words, stride * count, &e);
  bFound.m = p_clCreateBuffer(c.ctx, CL_MEM_READ_WRITE, 8, nullptr, &e);
  if (!bSaltTail.m || !bValueTail.m || !bWords.m || !bFound.m) {
    err = "创建缓冲区失败(字典过大?)";
    return -1;
  }
  int64_t neg = -1;
  p_clEnqueueWriteBuffer(c.q, bFound.m, CL_TRUE, 0, 8, &neg, 0, nullptr, nullptr);

  cl_kernel k = c.kDict;
  uint32_t saltBlocks = (uint32_t)saltPc.tailBlocks();
  uint32_t valueBlocks = (uint32_t)valuePc.tailBlocks();
  uint32_t ustride = (uint32_t)stride;
  uint32_t ew[5];
  beWords20(p.expect, ew);
  p_clSetKernelArg(k, 0, sizeof(cl_mem), &bSaltTail.m);
  p_clSetKernelArg(k, 1, 4, &saltBlocks);
  p_clSetKernelArg(k, 2, sizeof(cl_mem), &bValueTail.m);
  p_clSetKernelArg(k, 3, 4, &valueBlocks);
  for (int i = 0; i < 5; i++) p_clSetKernelArg(k, 4 + i, 4, &ew[i]);
  p_clSetKernelArg(k, 9, sizeof(cl_mem), &bWords.m);
  p_clSetKernelArg(k, 10, 4, &ustride);
  p_clSetKernelArg(k, 13, sizeof(cl_mem), &bFound.m);
  return runChunks(c, k, bFound.m, count, 11, 12, foundIdx, err, hybrid, rawMap, attemptsOut);
}
