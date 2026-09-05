/**
 * nvrtc.cpp:CUDA 后端(NVRTC 编译 + Driver API 发射)。
 * 自声明 API 子集,LoadLibrary("nvcuda.dll") + LoadLibrary("nvrtc64_*.dll")
 * 运行时解析,与 ocl.cpp 同款零依赖套路;kernel 源码与 OpenCL 后端共用
 * (kernel_cl.h 的 __CUDACC__ shim 分支)。
 */
#include "nvrtc.h"
#include "kernel_cl.h"
#include "divmagic.h"
#include "../crack_cpu.h"
#include "../sha1.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
using LibHandle = HMODULE;
#else
#include <dlfcn.h>
#include <unistd.h>
using LibHandle = void*;
#endif

/* ---------- CUDA Driver API / NVRTC API 子集声明 ---------- */
using CUresult = int;
using CUdevice = int;
using CUdeviceptr = uint64_t;
using CUcontext = struct _CUctx*;
using CUmodule = struct _CUmod*;
using CUfunction = struct _CUfunc*;
using nvrtcProgram = struct _nvrtcProgram*;

#define CUDA_SUCCESS 0
#define NVRTC_SUCCESS 0
#define CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR 75
#define CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR 76

#define CU_FN(ret, name, args) typedef ret (*PFN_##name) args; static PFN_##name p_##name = nullptr
CU_FN(CUresult, cuInit, (unsigned int));
CU_FN(CUresult, cuDeviceGet, (CUdevice*, int));
CU_FN(CUresult, cuDeviceGetName, (char*, int, CUdevice));
CU_FN(CUresult, cuDeviceGetAttribute, (int*, int, CUdevice));
CU_FN(CUresult, cuDevicePrimaryCtxRetain, (CUcontext*, CUdevice));
CU_FN(CUresult, cuCtxCreate, (CUcontext*, unsigned, CUdevice));
CU_FN(CUresult, cuCtxSetCurrent, (CUcontext));
CU_FN(CUresult, cuMemAlloc, (CUdeviceptr*, size_t));
CU_FN(CUresult, cuMemFree, (CUdeviceptr));
CU_FN(CUresult, cuMemAllocHost, (void**, size_t));
CU_FN(CUresult, cuMemFreeHost, (void*));
CU_FN(CUresult, cuMemcpyHtoD, (CUdeviceptr, const void*, size_t));
CU_FN(CUresult, cuMemcpyDtoH, (void*, CUdeviceptr, size_t));
CU_FN(CUresult, cuModuleLoadData, (CUmodule*, const void*));
CU_FN(CUresult, cuModuleGetFunction, (CUfunction*, CUmodule, const char*));
CU_FN(CUresult, cuLaunchKernel, (CUfunction, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned,
                                 unsigned, void*, void**, void**));
CU_FN(CUresult, cuFuncGetAttribute, (int*, int, CUfunction));
CU_FN(CUresult, cuCtxSynchronize, ());
CU_FN(CUresult, cuGetErrorString, (CUresult, const char**));

CU_FN(int, nvrtcCreateProgram, (nvrtcProgram*, const char*, const char*, int, const char**, const char**));
CU_FN(int, nvrtcCompileProgram, (nvrtcProgram, int, const char**));
CU_FN(int, nvrtcGetProgramLogSize, (nvrtcProgram, size_t*));
CU_FN(int, nvrtcGetProgramLog, (nvrtcProgram, char*));
CU_FN(int, nvrtcGetCUBINSize, (nvrtcProgram, size_t*));
CU_FN(int, nvrtcGetCUBIN, (nvrtcProgram, char*));
CU_FN(int, nvrtcDestroyProgram, (nvrtcProgram*));
#undef CU_FN

/* ---------- 运行时上下文(进程内单例) ---------- */
struct CudaCtx {
  bool ready = false;
  std::string deviceName;
  std::string error;
  CUdevice dev = 0;
  CUcontext ctx = nullptr;
  CUmodule mod = nullptr;
  CUfunction kMask = nullptr;
  CUfunction kDict = nullptr;
};

static LibHandle loadNvrtc() {
#ifdef _WIN32
  // NVRTC 的 DLL 名带 CUDA 大版本号,逐一尝试;PATH 找不到时退到 CUDA_PATH
  static const char* names[] = {
    "nvrtc64_130_0.dll", "nvrtc64_120_0.dll", "nvrtc64_110_0.dll", "nvrtc64.dll", nullptr
  };
  for (int i = 0; names[i]; i++) {
    if (HMODULE h = LoadLibraryA(names[i])) return h;
  }
  if (const char* cp = getenv("CUDA_PATH")) {
    for (int i = 0; names[i]; i++) {
      std::string p1 = std::string(cp) + "\\bin\\x64\\" + names[i];
      if (HMODULE h = LoadLibraryA(p1.c_str())) return h;
      std::string p2 = std::string(cp) + "\\bin\\" + names[i];
      if (HMODULE h = LoadLibraryA(p2.c_str())) return h;
    }
  }
  return nullptr;
#else
  static const char* names[] = {
    "libnvrtc.so", "libnvrtc.so.12", "libnvrtc.so.11", nullptr
  };
  for (int i = 0; names[i]; i++) {
    if (LibHandle h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL)) return h;
  }
  if (const char* cp = getenv("CUDA_PATH")) {
    for (int i = 0; names[i]; i++) {
      std::string p = std::string(cp) + "/lib64/" + names[i];
      if (LibHandle h = dlopen(p.c_str(), RTLD_NOW | RTLD_LOCAL)) return h;
    }
  }
  return nullptr;
#endif
}

static bool loadApis(std::string& err) {
#ifdef _WIN32
  static LibHandle cudaDll = [] { return LoadLibraryA("nvcuda.dll"); }();
#else
  static LibHandle cudaDll = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
#endif
  static LibHandle rtcDll = loadNvrtc();
  if (!cudaDll) {
#ifdef _WIN32
    err = "nvcuda.dll 加载失败(无 NVIDIA 驱动?)";
#else
    err = "libcuda.so.1 加载失败(无 NVIDIA 驱动?)";
#endif
    return false;
  }
  if (!rtcDll) { err = "NVRTC 未找到(未安装 CUDA Toolkit)"; return false; }
  bool ok = true;
#ifdef _WIN32
#define RESOLVE(dll, name) \
  if (!p_##name) { p_##name = (PFN_##name)(void*)GetProcAddress(dll, #name); ok = ok && p_##name; }
#else
#define RESOLVE(dll, name) \
  if (!p_##name) { p_##name = (PFN_##name)dlsym(dll, #name); ok = ok && p_##name; }
#endif
  RESOLVE(cudaDll, cuInit) RESOLVE(cudaDll, cuDeviceGet) RESOLVE(cudaDll, cuDeviceGetName)
  RESOLVE(cudaDll, cuDeviceGetAttribute) RESOLVE(cudaDll, cuDevicePrimaryCtxRetain)
  RESOLVE(cudaDll, cuCtxCreate)
  RESOLVE(cudaDll, cuCtxSetCurrent) RESOLVE(cudaDll, cuMemAlloc) RESOLVE(cudaDll, cuMemFree)
  RESOLVE(cudaDll, cuMemAllocHost) RESOLVE(cudaDll, cuMemFreeHost)
  RESOLVE(cudaDll, cuMemcpyHtoD) RESOLVE(cudaDll, cuMemcpyDtoH) RESOLVE(cudaDll, cuModuleLoadData)
  RESOLVE(cudaDll, cuModuleGetFunction) RESOLVE(cudaDll, cuLaunchKernel) RESOLVE(cudaDll, cuCtxSynchronize)
  RESOLVE(cudaDll, cuFuncGetAttribute)
  RESOLVE(cudaDll, cuGetErrorString)
  RESOLVE(rtcDll, nvrtcCreateProgram) RESOLVE(rtcDll, nvrtcCompileProgram)
  RESOLVE(rtcDll, nvrtcGetProgramLogSize) RESOLVE(rtcDll, nvrtcGetProgramLog)
  RESOLVE(rtcDll, nvrtcGetCUBINSize) RESOLVE(rtcDll, nvrtcGetCUBIN) RESOLVE(rtcDll, nvrtcDestroyProgram)
#undef RESOLVE
  if (!ok) err = "CUDA/NVRTC 导出函数不完整";
  return ok;
}

static const char* cuErr(CUresult r) {
  const char* s = nullptr;
  if (p_cuGetErrorString && p_cuGetErrorString(r, &s) == CUDA_SUCCESS && s) return s;
  return "unknown";
}

static CudaCtx& cuda() {
  static CudaCtx c;
  static bool inited = false;
  if (inited) return c;
  inited = true;

  if (!loadApis(c.error)) return c;
  if (p_cuInit(0) != CUDA_SUCCESS) { c.error = "cuInit 失败"; return c; }
  if (p_cuDeviceGet(&c.dev, 0) != CUDA_SUCCESS) { c.error = "无 CUDA 设备"; return c; }
  char name[256] = {0};
  p_cuDeviceGetName(name, sizeof name, c.dev);
  c.deviceName = name;
  int major = 0, minor = 0;
  p_cuDeviceGetAttribute(&major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, c.dev);
  p_cuDeviceGetAttribute(&minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, c.dev);
#ifdef _WIN32
  if (p_cuDevicePrimaryCtxRetain(&c.ctx, c.dev) != CUDA_SUCCESS || !c.ctx) {
    c.error = "获取 primary context 失败";
    return c;
  }
#else
  // Linux 新版驱动上 primary context 可能被容器/持久化服务占用，直接创建独立 context。
  if (p_cuCtxCreate(&c.ctx, 0, c.dev) != CUDA_SUCCESS || !c.ctx) {
    c.error = "创建 CUDA context 失败";
    return c;
  }
#endif
  {
    CUresult cr = p_cuCtxSetCurrent(c.ctx);
    // 自检:context 当前化后立刻试分配 8 字节,失败则改用自建 context
    CUdeviceptr probe = 0;
    CUresult ar = cr == CUDA_SUCCESS ? p_cuMemAlloc(&probe, 8) : cr;
    if (ar == CUDA_SUCCESS) {
      p_cuMemFree(probe);
    } else {
      // primary ctx 失效(实测 CUDA 13 驱动组合下出现过),退到 cuCtxCreate
      c.ctx = nullptr;
      CUresult cc = p_cuCtxCreate(&c.ctx, 0, c.dev);
      if (cc != CUDA_SUCCESS || !c.ctx) {
        c.error = std::string("创建 context 失败: ") + cuErr(cc);
        return c;
      }
      CUresult ar2 = p_cuMemAlloc(&probe, 8);
      if (ar2 != CUDA_SUCCESS) {
        c.error = std::string("context 自检分配失败: ") + cuErr(ar2);
        return c;
      }
      p_cuMemFree(probe);
      if (getenv("ZK_KINFO"))
        fprintf(stderr, "[kinfo] primary ctx 分配失败(%s),已改用 cuCtxCreate\n", cuErr(ar));
    }
  }
  char arch[16];
  snprintf(arch, sizeof arch, "sm_%d%d", major, minor);
  if (getenv("ZK_KINFO"))
    fprintf(stderr, "[kinfo] cuda init: dev=%d sm_%d%d ctx=%p setcur=%d\n",
            c.dev, major, minor, (void*)c.ctx, (int)p_cuCtxSetCurrent(c.ctx));

  // ---- cubin 缓存:NVRTC 全量编译要秒级,落盘后启动 <10ms ----
  // 文件格式:[u32 magic][u32 keyLen][key(devName|arch)][cubin]
  const uint32_t CACHE_MAGIC = 0x5A4B4305; // "ZKC" v5(v4 免展开压缩实测慢 16x 已回退;v3 掩码 key 打包特化)
  std::string key = c.deviceName + "|" + arch;
  std::string cachePath;
#ifdef _WIN32
  char exePath[MAX_PATH] = {0};
  GetModuleFileNameA(nullptr, exePath, MAX_PATH);
  cachePath = exePath;
  size_t slash = cachePath.find_last_of("\\/");
  cachePath = (slash == std::string::npos ? "." : cachePath.substr(0, slash)) + "\\flask_crack_nvrtc.bin";
#else
  char exePath[4096] = {0};
  ssize_t n = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
  cachePath.assign(n > 0 ? exePath : ".");
  size_t slash = cachePath.find_last_of('/');
  cachePath = (slash == std::string::npos ? "." : cachePath.substr(0, slash)) + "/flask_crack_nvrtc.bin";
#endif

  std::vector<uint8_t> cubin;
  if (FILE* f = fopen(cachePath.c_str(), "rb")) {
    uint32_t magic = 0, keyLen = 0;
    if (fread(&magic, 4, 1, f) == 1 && magic == CACHE_MAGIC &&
        fread(&keyLen, 4, 1, f) == 1 && keyLen < 512) {
      char k[512] = {0};
      if (fread(k, 1, keyLen, f) == keyLen && key == k) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f) - 8 - (long)keyLen;
        fseek(f, 8 + (long)keyLen, SEEK_SET);
        if (sz > 0) {
          cubin.resize((size_t)sz);
          if (fread(cubin.data(), 1, cubin.size(), f) != cubin.size()) cubin.clear();
        }
      }
    }
    fclose(f);
  }

  if (cubin.empty()) {
    nvrtcProgram prog = nullptr;
    const char* src = FLASK_CRACK_CL;
    if (p_nvrtcCreateProgram(&prog, src, "flask_crack.cu", 0, nullptr, nullptr) != NVRTC_SUCCESS) {
      c.error = "nvrtcCreateProgram 失败";
      return c;
    }
    char opt[40];
    snprintf(opt, sizeof opt, "--gpu-architecture=%s", arch);
    // -default-device:源码里 OpenCL 风格的裸 inline 函数在 CUDA 侧视为 __device__
    const char* opts[] = { opt, "-default-device" };
    int rc = p_nvrtcCompileProgram(prog, 2, opts);
    if (rc != NVRTC_SUCCESS) {
      size_t logSize = 0;
      p_nvrtcGetProgramLogSize(prog, &logSize);
      std::string log(logSize, '\0');
      if (logSize > 1) p_nvrtcGetProgramLog(prog, log.data());
      p_nvrtcDestroyProgram(&prog);
      c.error = "NVRTC 编译失败: " + log;
      return c;
    }
    size_t sz = 0;
    p_nvrtcGetCUBINSize(prog, &sz);
    cubin.resize(sz);
    p_nvrtcGetCUBIN(prog, (char*)cubin.data());
    p_nvrtcDestroyProgram(&prog);
    if (cubin.empty()) { c.error = "NVRTC 未产出 cubin"; return c; }
    if (FILE* f = fopen(cachePath.c_str(), "wb")) {
      uint32_t keyLen = (uint32_t)key.size();
      fwrite(&CACHE_MAGIC, 4, 1, f);
      fwrite(&keyLen, 4, 1, f);
      fwrite(key.data(), 1, keyLen, f);
      fwrite(cubin.data(), 1, cubin.size(), f);
      fclose(f);
    }
  }

  if (p_cuModuleLoadData(&c.mod, cubin.data()) != CUDA_SUCCESS) {
    c.error = "cuModuleLoadData 失败";
    return c;
  }
  if (p_cuModuleGetFunction(&c.kMask, c.mod, "crack_mask") != CUDA_SUCCESS) {
    c.error = "取 crack_mask 函数失败";
    return c;
  }
  if (p_cuModuleGetFunction(&c.kDict, c.mod, "crack_dict") != CUDA_SUCCESS) {
    c.error = "取 crack_dict 函数失败";
    return c;
  }
  if (getenv("ZK_KINFO")) { // CU_FUNC_ATTRIBUTE: LOCAL_SIZE_BYTES=3, NUM_REGS=4, MAX_THREADS=0
    int regs = 0, local = 0, maxThr = 0;
    p_cuFuncGetAttribute(&regs, 4, c.kMask);
    p_cuFuncGetAttribute(&local, 3, c.kMask);
    p_cuFuncGetAttribute(&maxThr, 0, c.kMask);
    fprintf(stderr, "[kinfo] cuda crack_mask: regs=%d local=%dB maxThreads=%d\n", regs, local, maxThr);
  }
  c.ready = true;
  return c;
}

GpuProbe cudaProbe() {
  CudaCtx& c = cuda();
  GpuProbe r;
  r.ok = c.ready;
  r.deviceName = c.deviceName;
  r.error = c.error;
  return r;
}

/* ---------- 缓冲区助手 ---------- */
struct CuBuf {
  CUdeviceptr p = 0;
  ~CuBuf() { if (p) p_cuMemFree(p); }
};

static CUdeviceptr cuAlloc(const void* data, size_t n, CUresult* rc) {
  CUdeviceptr d = 0;
  *rc = p_cuMemAlloc(&d, n);
  if (*rc != CUDA_SUCCESS) return 0;
  if (data && n) {
    CUresult r2 = p_cuMemcpyHtoD(d, data, n);
    if (r2 != CUDA_SUCCESS) { *rc = r2; p_cuMemFree(d); return 0; }
  }
  return d;
}

CudaHostBuf cudaHostAlloc(size_t bytes) {
  CudaHostBuf r;
  if (bytes == 0) return r;
  CudaCtx& c = cuda();
  if (!c.ready) return r;
  void* p = nullptr;
  if (p_cuMemAllocHost(&p, bytes) != CUDA_SUCCESS || !p) return r;
  r.ptr = p;
  r.size = bytes;
  return r;
}

void cudaHostFree(CudaHostBuf& b) {
  if (b.ptr) p_cuMemFreeHost(b.ptr);
  b = CudaHostBuf();
}

#define CHUNK_CAND (1ULL << 24) // 与 OpenCL 后端同基准

int cudaCrackMask(const GpuCrackParams& p, const std::vector<std::string>& pos, uint64_t total,
                  uint64_t& foundIdx, std::string& err) {
  CudaCtx& c = cuda();
  if (!c.ready) { err = c.error; return -1; }
  if (p.vlen > 512 || p.slen > 32 || pos.size() > 24) {
    err = "GPU 参数超限(value ≤ 512B,salt ≤ 32B,掩码 ≤ 24 位)";
    return -1;
  }
  p_cuCtxSetCurrent(c.ctx);
  if (getenv("ZK_KINFO")) {
    CUresult sr = p_cuCtxSetCurrent(c.ctx);
    fprintf(stderr, "[kinfo] crack setcur=%d ctx=%p\n", (int)sr, (void*)c.ctx);
  }
  // HMAC 预计算 + 字符集打包 + 每位除法魔数(与 ocl.cpp 相同)
  HmacFixedMsg saltPc, valuePc;
  saltPc.init(p.salt, p.slen);
  valuePc.init(p.value, p.vlen);
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
  CuBuf dSalt, dValue, dCsbuf, dCsoff, dCslen, dCsmag, dCsflg, dFound;
  CUresult arc = CUDA_SUCCESS;
  dSalt.p = cuAlloc(saltPc.tailw.data(), saltPc.tailw.size() * 4, &arc);
  dValue.p = cuAlloc(valuePc.tailw.data(), valuePc.tailw.size() * 4, &arc);
  dCsbuf.p = cuAlloc(csbuf.data(), csbuf.size(), &arc);
  dCsoff.p = cuAlloc(csoff.data(), csoff.size() * 4, &arc);
  dCslen.p = cuAlloc(cslen.data(), cslen.size() * 4, &arc);
  dCsmag.p = cuAlloc(csmag.data(), csmag.size() * 8, &arc);
  dCsflg.p = cuAlloc(csflg.data(), csflg.size() * 4, &arc);
  dFound.p = cuAlloc(nullptr, 8, &arc);
  if (!dSalt.p || !dValue.p || !dCsbuf.p || !dCsoff.p || !dCslen.p ||
      !dCsmag.p || !dCsflg.p || !dFound.p) {
    err = std::string("设备内存分配失败: ") + cuErr(arc);
    return -1;
  }
  int64_t neg = -1;
  p_cuMemcpyHtoD(dFound.p, &neg, 8);

  uint32_t saltBlocks = (uint32_t)saltPc.tailBlocks();
  uint32_t valueBlocks = (uint32_t)valuePc.tailBlocks();
  uint32_t npos = (uint32_t)pos.size();
  uint32_t ew[5];
  beWords20(p.expect, ew);
  uint64_t base = 0, totalArg = total;
  void* params[] = { &dSalt.p, &saltBlocks, &dValue.p, &valueBlocks,
                     &ew[0], &ew[1], &ew[2], &ew[3], &ew[4],
                     &dCsbuf.p, &dCsoff.p, &dCslen.p, &dCsmag.p, &dCsflg.p,
                     &npos, &base, &totalArg, &dFound.p };
  const unsigned BLOCK = [] { // ZK_CB=<n> 探测用覆盖块大小,默认 256
    const char* v = getenv("ZK_CB");
    int n = v ? atoi(v) : 0;
    return n > 0 ? (unsigned)n : 256u;
  }();
  for (base = 0; base < total; base += CHUNK_CAND) {
    size_t cand = (size_t)(total - base < CHUNK_CAND ? total - base : CHUNK_CAND);
    unsigned grid = (unsigned)((cand + BLOCK - 1) / BLOCK);
    CUresult r = p_cuLaunchKernel(c.kMask, grid, 1, 1, BLOCK, 1, 1, 0, nullptr, params, nullptr);
    if (r != CUDA_SUCCESS) { err = std::string("cuLaunchKernel 失败: ") + cuErr(r); return -1; }
    p_cuCtxSynchronize();
    if (g_crackAbort.load(std::memory_order_relaxed)) return 1;
    int64_t found = -1;
    p_cuMemcpyDtoH(&found, dFound.p, 8);
    if (found >= 0) {
      foundIdx = (uint64_t)found;
      return 0;
    }
  }
  return 1;
}

int cudaCrackDict(const GpuCrackParams& p, const uint8_t* words, size_t stride, uint64_t count,
                  uint64_t& foundIdx, std::string& err, CudaHostBuf* pinned) {
  size_t wordBytes = stride * (size_t)count;
  bool usePinned = pinned && pinned->ptr == words && pinned->size >= wordBytes;
  struct PinnedGuard {
    CudaHostBuf* b;
    ~PinnedGuard() { if (b) cudaHostFree(*b); }
  } pinnedGuard{usePinned ? pinned : nullptr};
  CudaCtx& c = cuda();
  if (!c.ready) { err = c.error; return -1; }
  if (p.vlen > 512 || p.slen > 32) {
    err = "GPU 参数超限(value ≤ 512B,salt ≤ 32B)";
    return -1;
  }
  p_cuCtxSetCurrent(c.ctx);
  // HMAC 预计算(与 ocl.cpp 的 gpuCrackDict 相同)
  HmacFixedMsg saltPc, valuePc;
  saltPc.init(p.salt, p.slen);
  valuePc.init(p.value, p.vlen);
  CuBuf dSalt, dValue, dWords, dFound;
  CUresult arc = CUDA_SUCCESS;
  dSalt.p = cuAlloc(saltPc.tailw.data(), saltPc.tailw.size() * 4, &arc);
  dValue.p = cuAlloc(valuePc.tailw.data(), valuePc.tailw.size() * 4, &arc);
  dWords.p = cuAlloc(usePinned ? pinned->ptr : words, wordBytes, &arc);
  dFound.p = cuAlloc(nullptr, 8, &arc);
  if (!dSalt.p || !dValue.p || !dWords.p || !dFound.p) {
    err = std::string("设备内存分配失败(字典过大?): ") + cuErr(arc);
    return -1;
  }
  int64_t neg = -1;
  p_cuMemcpyHtoD(dFound.p, &neg, 8);

  uint32_t saltBlocks = (uint32_t)saltPc.tailBlocks();
  uint32_t valueBlocks = (uint32_t)valuePc.tailBlocks();
  uint32_t ustride = (uint32_t)stride;
  uint32_t ew[5];
  beWords20(p.expect, ew);
  uint64_t base = 0, totalArg = count;
  void* params[] = { &dSalt.p, &saltBlocks, &dValue.p, &valueBlocks,
                     &ew[0], &ew[1], &ew[2], &ew[3], &ew[4],
                     &dWords.p, &ustride, &base, &totalArg, &dFound.p };
  const unsigned BLOCK = 256;
  for (base = 0; base < count; base += CHUNK_CAND) {
    size_t cand = (size_t)(count - base < CHUNK_CAND ? count - base : CHUNK_CAND);
    unsigned grid = (unsigned)((cand + BLOCK - 1) / BLOCK);
    CUresult r = p_cuLaunchKernel(c.kDict, grid, 1, 1, BLOCK, 1, 1, 0, nullptr, params, nullptr);
    if (r != CUDA_SUCCESS) { err = std::string("cuLaunchKernel 失败: ") + cuErr(r); return -1; }
    p_cuCtxSynchronize();
    if (g_crackAbort.load(std::memory_order_relaxed)) return 1;
    int64_t found = -1;
    p_cuMemcpyDtoH(&found, dFound.p, 8);
    if (found >= 0) {
      foundIdx = (uint64_t)found;
      return 0;
    }
  }
  return 1;
}
