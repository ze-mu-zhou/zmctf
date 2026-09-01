#include "gpu_opencl.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

// Minimal OpenCL 1.2 dynamic binding: no SDK or import library needed, the
// ICD (OpenCL.dll / libOpenCL.so) ships with the GPU driver.
using cl_int = int;
using cl_uint = unsigned;
using cl_ulong = unsigned long long;
using cl_bool = cl_uint;
using cl_bitfield = cl_ulong;
using cl_device_type = cl_bitfield;
using cl_platform_id = void *;
using cl_device_id = void *;
using cl_context = void *;
using cl_command_queue = void *;
using cl_program = void *;
using cl_kernel = void *;
using cl_mem = void *;

constexpr cl_int CL_SUCCESS = 0;
constexpr cl_device_type CL_DEVICE_TYPE_GPU = 1ull << 2;
constexpr cl_uint CL_DEVICE_MAX_COMPUTE_UNITS = 0x1002;
constexpr cl_uint CL_PROGRAM_BUILD_LOG = 0x1183;
constexpr cl_bitfield CL_MEM_READ_WRITE = 1;
constexpr cl_bitfield CL_MEM_READ_ONLY = 1 << 2;
constexpr cl_bitfield CL_MEM_COPY_HOST_PTR = 1 << 5;
constexpr cl_bool CL_TRUE = 1;

struct Cl {
  void *lib = nullptr;
  cl_int (*GetPlatformIDs)(cl_uint, cl_platform_id *, cl_uint *){};
  cl_int (*GetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *){};
  cl_int (*GetDeviceInfo)(cl_device_id, cl_uint, size_t, void *, size_t *){};
  cl_context (*CreateContext)(const void *, cl_uint, const cl_device_id *, void *, void *, cl_int *){};
  cl_command_queue (*CreateCommandQueue)(cl_context, cl_device_id, cl_bitfield, cl_int *){};
  cl_program (*CreateProgramWithSource)(cl_context, cl_uint, const char **, const size_t *, cl_int *){};
  cl_int (*BuildProgram)(cl_program, cl_uint, const cl_device_id *, const char *, void *, void *){};
  cl_int (*GetProgramBuildInfo)(cl_program, cl_device_id, cl_uint, size_t, void *, size_t *){};
  cl_kernel (*CreateKernel)(cl_program, const char *, cl_int *){};
  cl_mem (*CreateBuffer)(cl_context, cl_bitfield, size_t, void *, cl_int *){};
  cl_int (*EnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void *, cl_uint, const void *, void *){};
  cl_int (*SetKernelArg)(cl_kernel, cl_uint, size_t, const void *){};
  cl_int (*EnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const void *, const size_t *, const size_t *, cl_uint, const void *, void *){};
  cl_int (*EnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void *, cl_uint, const void *, void *){};
  cl_int (*Finish)(cl_command_queue){};
  cl_int (*ReleaseMemObject)(cl_mem){};
  cl_int (*ReleaseKernel)(cl_kernel){};
  cl_int (*ReleaseProgram)(cl_program){};
  cl_int (*ReleaseCommandQueue)(cl_command_queue){};
  cl_int (*ReleaseContext)(cl_context){};
};

void *cl_sym(void *lib, const char *name) {
#ifdef _WIN32
  return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(lib), name));
#else
  return dlsym(lib, name);
#endif
}

const Cl &cl_api() {
  static const Cl cl = [] {
    Cl c{};
#ifdef _WIN32
    c.lib = LoadLibraryA("OpenCL.dll");
#else
    c.lib = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!c.lib) c.lib = dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
#endif
    if (!c.lib) return c;
    const std::pair<const char *, void **> entries[] = {
        {"clGetPlatformIDs", reinterpret_cast<void **>(&c.GetPlatformIDs)},
        {"clGetDeviceIDs", reinterpret_cast<void **>(&c.GetDeviceIDs)},
        {"clGetDeviceInfo", reinterpret_cast<void **>(&c.GetDeviceInfo)},
        {"clCreateContext", reinterpret_cast<void **>(&c.CreateContext)},
        {"clCreateCommandQueue", reinterpret_cast<void **>(&c.CreateCommandQueue)},
        {"clCreateProgramWithSource", reinterpret_cast<void **>(&c.CreateProgramWithSource)},
        {"clBuildProgram", reinterpret_cast<void **>(&c.BuildProgram)},
        {"clGetProgramBuildInfo", reinterpret_cast<void **>(&c.GetProgramBuildInfo)},
        {"clCreateKernel", reinterpret_cast<void **>(&c.CreateKernel)},
        {"clCreateBuffer", reinterpret_cast<void **>(&c.CreateBuffer)},
        {"clEnqueueWriteBuffer", reinterpret_cast<void **>(&c.EnqueueWriteBuffer)},
        {"clSetKernelArg", reinterpret_cast<void **>(&c.SetKernelArg)},
        {"clEnqueueNDRangeKernel", reinterpret_cast<void **>(&c.EnqueueNDRangeKernel)},
        {"clEnqueueReadBuffer", reinterpret_cast<void **>(&c.EnqueueReadBuffer)},
        {"clFinish", reinterpret_cast<void **>(&c.Finish)},
        {"clReleaseMemObject", reinterpret_cast<void **>(&c.ReleaseMemObject)},
        {"clReleaseKernel", reinterpret_cast<void **>(&c.ReleaseKernel)},
        {"clReleaseProgram", reinterpret_cast<void **>(&c.ReleaseProgram)},
        {"clReleaseCommandQueue", reinterpret_cast<void **>(&c.ReleaseCommandQueue)},
        {"clReleaseContext", reinterpret_cast<void **>(&c.ReleaseContext)},
    };
    for (const auto &[name, slot] : entries) {
      *slot = cl_sym(c.lib, name);
      if (!*slot) { c = Cl{}; return c; }
    }
    return c;
  }();
  return cl;
}

cl_device_id find_gpu(cl_platform_id *platform_out = nullptr) {
  const Cl &cl = cl_api();
  cl_uint nplatforms = 0;
  if (cl.GetPlatformIDs(0, nullptr, &nplatforms) != CL_SUCCESS || !nplatforms) return nullptr;
  std::vector<cl_platform_id> platforms(nplatforms);
  cl.GetPlatformIDs(nplatforms, platforms.data(), nullptr);
  cl_device_id best = nullptr;
  cl_platform_id best_platform = nullptr;
  cl_uint best_units = 0;
  for (const auto platform : platforms) {
    cl_uint ndev = 0;
    if (cl.GetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &ndev) != CL_SUCCESS || !ndev) continue;
    std::vector<cl_device_id> devices(ndev);
    cl.GetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, ndev, devices.data(), nullptr);
    for (const auto device : devices) {
      cl_uint units = 0;
      cl.GetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(units), &units, nullptr);
      if (units > best_units) { best = device; best_platform = platform; best_units = units; }
    }
  }
  if (platform_out) *platform_out = best_platform;
  return best;
}

void cl_check(cl_int err, const char *what) {
  if (err != CL_SUCCESS) throw std::runtime_error(std::string("OpenCL ") + what + " 失败，错误码 " + std::to_string(err));
}

constexpr std::array<std::uint32_t, 64> MD5_K = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

constexpr std::array<unsigned, 64> MD5_S = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// Message word index consumed by step i.
constexpr unsigned md5_word(unsigned i) {
  const unsigned round = i / 16;
  return round == 0 ? i
       : round == 1 ? (5 * i + 1) % 16
       : round == 2 ? (3 * i + 5) % 16
                    : (7 * i) % 16;
}

// Vector width of the generated kernel (candidates per thread iteration).
// hashcat tunes Vec:8 for MD5 on this GPU class.
constexpr unsigned VEC = 8;

struct alignas(16) RootWord4 {
  std::uint32_t v[4];
};

struct alignas(32) VecWords {
  std::uint32_t v[VEC];
};

const char *KERNEL_HEAD = R"OPENCL(

typedef unsigned int u32;
typedef unsigned long u64;

inline uvec zm_rotl(const uvec x, const u32 s) { return (x << s) | (x >> (32 - s)); }
inline u32 zm_rotr32(const u32 x, const u32 s) { return (x >> s) | (x << (32 - s)); }
inline uvec zm_splat(const u32 x) { return (uvec) (SPLAT_ARGS); }

#define ZM_F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define ZM_G(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))
#define ZM_H(x,y,z) ((x) ^ (y) ^ (z))
#define ZM_I(x,y,z) ((y) ^ ((x) | ~(z)))

__kernel void zm_md5_match(
    const u64 launch_base, const u64 roots_this,
    const u64 inner_count, const u64 stride,
    const u32 v0, const u32 v1, const u32 v2, const u32 v3,
    const u32 m0, const u32 m1, const u32 m2, const u32 m3,
    __global const uint4 *root_words,
    __global const uvec *inner_tab,
    const u32 max_hits, __global u32 *hit_count,
    __global u64 *hit_index, __global uint4 *hit_digest)
{
  const u64 gid = (u64) get_global_id(0);
  if (gid >= roots_this) return;
  __global const uint4 *rw = root_words + gid * 4u;
  const uint4 r0 = rw[0];
  const uint4 r1 = rw[1];
  const uint4 r2 = rw[2];
  const uint4 r3 = rw[3];

  const u64 root_index = launch_base + gid;
  const u32 ic32 = (u32) inner_count;
  const u32 nvec = (ic32 + (VEC - 1u)) / VEC;

)OPENCL";

// The kernel body is generated per launch shape, following hashcat's
// m00000_a3-optimized (m00000s) single-target kernel:
//  - the inner loop varies only message word 0 (leading candidate bytes), via
//    a host-precomputed OR table, VEC candidates per thread (u32x8 ILP);
//  - every fixed message word is folded into a per-step constant K+w (the
//    F_w1c01 = w[1] + MD5C01 trick), so steps are add+fn+rotl+add only;
//  - for exact 128-bit targets, round 4 (steps 63..49) is reversed from the
//    target once per thread, and the forward loop stops after step 45: the
//    reversed d-component (d45) is a w0-independent exact constant, so the
//    early reject costs one vector compare (~28% less work per candidate);
//    survivors recompute the tail and take a full masked compare.
//  - masked (pattern) targets cannot be reversed, so they run all 64 steps.
std::string build_kernel_source(std::size_t length, bool exact) {
  std::array<bool, 16> zero{};
  for (std::size_t z = length / 4 + 1; z < 14; ++z) zero[z] = true;
  zero[15] = true;  // high length word: always 0 for length <= 55
  zero[0] = false;  // loop word

  // Scalar message words needed for constant folding / reversal.
  std::array<bool, 16> need{};
  for (unsigned i = 0; i != 64; ++i) {
    const unsigned g = md5_word(i);
    if (g != 0 && !zero[g]) need[g] = true;
  }
  need[14] = true;
  need[0] = true;

  const std::string vec_t = "uint" + std::to_string(VEC);
  const std::string int_t = "int" + std::to_string(VEC);
  std::string s = KERNEL_HEAD;
  const auto replace_all = [](std::string &text, const std::string &from, const std::string &to) {
    for (std::size_t p = 0; (p = text.find(from, p)) != std::string::npos; p += to.size()) text.replace(p, from.size(), to);
  };
  replace_all(s, "uvec", vec_t);
  replace_all(s, "VEC", std::to_string(VEC));
  std::string splat_args;
  for (unsigned i = 0; i != VEC; ++i) splat_args += (i ? ", x" : "x");
  replace_all(s, "SPLAT_ARGS", splat_args);

  char line[224];
  const char *comp = "xyzw";
  for (unsigned i = 0; i != 16; ++i) {
    if (!need[i]) continue;
    std::snprintf(line, sizeof(line), "  const u32 w%u_s = r%u.%c;\n", i, i / 4, comp[i % 4]);
    s += line;
  }

  // Folded per-step constants for fixed words (K + w_g), zero words inline K.
  for (unsigned i = 0; i != 64; ++i) {
    const unsigned g = md5_word(i);
    if (g == 0 || zero[g]) continue;
    std::snprintf(line, sizeof(line), "  const u32 kc%02u = 0x%08xu + w%u_s;\n", i, MD5_K[i], g);
    s += line;
  }

  const char *vars[4] = {"a", "b", "c", "d"};
  const auto fn_of = [](unsigned i) {
    return i < 16 ? "ZM_F" : i < 32 ? "ZM_G" : i < 48 ? "ZM_H" : "ZM_I";
  };

  if (exact) {
    // Reverse steps 63..49 from (target - IV). All use fixed words, so the
    // reversed state is exact per-thread constants. Step 48 (uses w0) is
    // undone in the loop with a single vector subtract.
    s += "\n  u32 ra = v0 - 0x67452301u, rb = v1 - 0xefcdab89u;\n";
    s += "  u32 rc = v2 - 0x98badcfeu, rd = v3 - 0x10325476u;\n";
    const char *rvars[4] = {"ra", "rb", "rc", "rd"};
    for (unsigned i = 63; i >= 49; --i) {
      const unsigned t = (4 - (i % 4)) % 4;
      const unsigned g = md5_word(i);
      std::string term;
      if (!zero[g]) term = " - w" + std::to_string(g) + "_s";
      std::snprintf(line, sizeof(line), "  %s = zm_rotr32(%s - %s, %uu) - ZM_I(%s, %s, %s)%s - 0x%08xu;\n",
                    rvars[t], rvars[t], rvars[(t + 1) % 4], MD5_S[i],
                    rvars[(t + 1) % 4], rvars[(t + 2) % 4], rvars[(t + 3) % 4], term.c_str(), MD5_K[i]);
      s += line;
    }
    // After undoing steps 63..49 the reversed state is exact: its d-component
    // (rd = d45) lets the forward loop bail right after step 45, before the
    // w0-dependent step 48 makes deeper static reversal impossible.
  }

  s += "\n  const " + vec_t + " save_w0 = zm_splat(w0_s);\n";
  s += "  for (u32 it = 0; it < nvec; ++it) {\n";
  s += "    const u32 base_i = it * " + std::to_string(VEC) + "u;\n";
  s += "    const " + vec_t + " w0v = save_w0 | inner_tab[it];\n";
  s += "    " + vec_t + " a = zm_splat(0x67452301u), b = zm_splat(0xefcdab89u);\n";
  s += "    " + vec_t + " c = zm_splat(0x98badcfeu), d = zm_splat(0x10325476u);\n";

  const unsigned forward_end = exact ? 46 : 64;
  const auto emit_step = [&](unsigned i) {
    const unsigned t = (4 - (i % 4)) % 4;
    const unsigned g = md5_word(i);
    std::string kterm;
    if (g == 0)
      std::snprintf(line, sizeof(line), "0x%08xu + w0v", MD5_K[i]);
    else if (zero[g])
      std::snprintf(line, sizeof(line), "0x%08xu", MD5_K[i]);
    else
      std::snprintf(line, sizeof(line), "kc%02u", i);
    kterm = line;
    std::snprintf(line, sizeof(line), "    %s += %s + %s(%s, %s, %s); %s = zm_rotl(%s, %uu); %s += %s;\n",
                  vars[t], kterm.c_str(), fn_of(i), vars[(t + 1) % 4], vars[(t + 2) % 4], vars[(t + 3) % 4],
                  vars[t], vars[t], MD5_S[i], vars[t], vars[(t + 1) % 4]);
    s += line;
  };
  for (unsigned i = 0; i != forward_end; ++i) emit_step(i);

  const char *lanes4[4] = {"x", "y", "z", "w"};
  const auto lane_acc = [&](unsigned lane) { return VEC == 4 ? lanes4[lane] : ("s" + std::to_string(lane)); };
  const auto emit_report = [&](const std::string &cond) {
    for (unsigned lane = 0; lane != VEC; ++lane) {
      const std::string acc = lane_acc(lane);
      s += "      if (" + cond + "." + acc + " && base_i + " + std::to_string(lane) + "u < ic32) {\n";
      s += "        const u32 slot = atomic_add(hit_count, 1u);\n";
      s += "        if (slot < max_hits) {\n";
      s += "          hit_index[slot] = (u64) (base_i + " + std::to_string(lane) + "u) * stride + root_index;\n";
      s += "          hit_digest[slot] = (uint4) (a." + acc + ", b." + acc + ", c." + acc + ", d." + acc + ");\n";
      s += "        }\n      }\n";
    }
  };

  if (exact) {
    // Early reject: after step 45, the d-component must equal the reversed d45.
    s += "    const " + int_t + " early = (d == zm_splat(rd));\n";
    s += "    if (any(early)) {\n";
    for (unsigned i = 46; i != 64; ++i) {
      // Continuation steps, indented one level deeper.
      const unsigned t = (4 - (i % 4)) % 4;
      const unsigned g = md5_word(i);
      std::string kterm;
      if (g == 0)
        std::snprintf(line, sizeof(line), "0x%08xu + w0v", MD5_K[i]);
      else if (zero[g])
        std::snprintf(line, sizeof(line), "0x%08xu", MD5_K[i]);
      else
        std::snprintf(line, sizeof(line), "kc%02u", i);
      kterm = line;
      std::snprintf(line, sizeof(line), "      %s += %s + %s(%s, %s, %s); %s = zm_rotl(%s, %uu); %s += %s;\n",
                    vars[t], kterm.c_str(), fn_of(i), vars[(t + 1) % 4], vars[(t + 2) % 4], vars[(t + 3) % 4],
                    vars[t], vars[t], MD5_S[i], vars[t], vars[(t + 1) % 4]);
      s += line;
    }
    s += "      a += zm_splat(0x67452301u); b += zm_splat(0xefcdab89u);\n";
    s += "      c += zm_splat(0x98badcfeu); d += zm_splat(0x10325476u);\n";
    // Full masked re-check per lane (exact mode has full masks).
    s += "      const " + int_t + " hitv = ((a & m0v) == (v0v & m0v)) & ((b & m1v) == (v1v & m1v)) &\n";
    s += "                        ((c & m2v) == (v2v & m2v)) & ((d & m3v) == (v3v & m3v));\n";
    s += "      const " + int_t + " fire = hitv & early;\n";
    emit_report("fire");
    s += "    }\n";
  } else {
    s += "    a += zm_splat(0x67452301u); b += zm_splat(0xefcdab89u);\n";
    s += "    c += zm_splat(0x98badcfeu); d += zm_splat(0x10325476u);\n";
    s += "    const " + int_t + " hitv = ((a & m0v) == (v0v & m0v)) & ((b & m1v) == (v1v & m1v)) &\n";
    s += "                      ((c & m2v) == (v2v & m2v)) & ((d & m3v) == (v3v & m3v));\n";
    s += "    if (any(hitv)) {\n";
    emit_report("hitv");
    s += "    }\n";
  }
  s += "  }\n}\n";

  if (exact) {
    // Masked compare constants referenced by the exact path's re-check.
    std::string inject = "  const " + vec_t + " v0v = zm_splat(v0), v1v = zm_splat(v1), v2v = zm_splat(v2), v3v = zm_splat(v3);\n";
    inject += "  const " + vec_t + " m0v = zm_splat(m0), m1v = zm_splat(m1), m2v = zm_splat(m2), m3v = zm_splat(m3);\n";
    const std::string anchor = "\n  const " + vec_t + " save_w0";
    const auto pos = s.find(anchor);
    s.insert(pos, "\n" + inject);
  } else {
    std::string inject = "  const " + vec_t + " v0v = zm_splat(v0), v1v = zm_splat(v1), v2v = zm_splat(v2), v3v = zm_splat(v3);\n";
    inject += "  const " + vec_t + " m0v = zm_splat(m0), m1v = zm_splat(m1), m2v = zm_splat(m2), m3v = zm_splat(m3);\n";
    const std::string anchor = "\n  const " + vec_t + " save_w0";
    const auto pos = s.find(anchor);
    s.insert(pos, "\n" + inject);
  }
  return s;
}

struct ClMem {
  const Cl *cl;
  cl_mem mem = nullptr;
  ~ClMem() { if (mem) cl->ReleaseMemObject(mem); }
  ClMem(const ClMem &) = delete;
  ClMem &operator=(const ClMem &) = delete;
  ClMem(const Cl *c) : cl(c) {}
};

} // namespace

bool gpu_available() noexcept {
  static const bool ok = [] {
    const Cl &cl = cl_api();
    if (!cl.GetPlatformIDs) return false;
    return find_gpu() != nullptr;
  }();
  return ok;
}

GpuMatchResult gpu_match(const GpuMatchParams &params) {
  const Cl &cl = cl_api();
  if (!cl.GetPlatformIDs) throw std::runtime_error("OpenCL 不可用");
  cl_platform_id platform = nullptr;
  cl_device_id device = find_gpu(&platform);
  if (!device) throw std::runtime_error("未找到 GPU 设备");

  const auto L = static_cast<std::size_t>(params.length);

  // Inner loop = leading candidate bytes (all inside message word 0, at most 4
  // positions, product capped), so the kernel can fold every other message
  // word into per-step constants and reverse round 4 for exact targets.
  std::size_t n_inner = 0;
  std::uint64_t inner_count = 1;
  while (n_inner < L && n_inner < 4 && inner_count <= 65536 / params.radix[n_inner]) {
    inner_count *= params.radix[n_inner];
    ++n_inner;
  }
  if (n_inner == 0 && L > 0) throw std::runtime_error("GPU 路径要求每个位置基数 ≤ 65536");

  // Outer (trailing) positions [n_inner, L): root cursor range and hit-index
  // stride. Overflow guard: hit indices must stay representable.
  std::uint64_t stride = 1;
  for (std::size_t q = n_inner; q < L; ++q) {
    if (stride > std::numeric_limits<std::uint64_t>::max() / params.radix[q] / inner_count)
      throw std::runtime_error("候选空间过大，GPU 路径不支持");
    stride *= params.radix[q];
  }
  const bool exact = params.mask[0] == 0xffffffffu && params.mask[1] == 0xffffffffu &&
                     params.mask[2] == 0xffffffffu && params.mask[3] == 0xffffffffu;

  // Inner table: entries iterate leading positions with position n_inner-1
  // fastest, consistent with the global enumeration index (it * stride + root).
  const std::uint64_t inner_vec = (inner_count + VEC - 1) / VEC;
  std::vector<VecWords> inner_tab(inner_vec);
  for (std::uint64_t it = 0; it < inner_count; ++it) {
    std::uint64_t v = it;
    std::uint32_t w0 = 0;
    for (std::size_t q = n_inner; q-- > 0;) {
      const auto rd = params.radix[q];
      const auto dig = static_cast<std::uint32_t>(v % rd);
      v /= rd;
      w0 |= static_cast<std::uint32_t>(params.chars[params.offsets[q] + dig]) << ((q & 3) * 8);
    }
    inner_tab[it / VEC].v[it % VEC] = w0;
  }

  const std::uint64_t roots_total =
      std::min(stride, (params.limit + inner_count - 1) / inner_count);
  const std::uint32_t max_hits = static_cast<std::uint32_t>(std::min<std::uint64_t>(params.max_hits, 65536));
  // Fill the GPU: a launch should span several waves of threads (tens of
  // thousands) or the SMs starve. Cap the root staging at 16 MiB.
  const std::uint64_t roots_per_launch =
      std::clamp<std::uint64_t>((std::uint64_t{1} << 30) / inner_count, 1, 262144);

  const std::string source = build_kernel_source(L, exact);

  cl_int err = CL_SUCCESS;
  cl_context context = cl.CreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
  cl_check(err, "clCreateContext");
  cl_command_queue queue = cl.CreateCommandQueue(context, device, 0, &err);
  cl_check(err, "clCreateCommandQueue");

  GpuMatchResult result;
  cl_program program = nullptr;
  cl_kernel kernel = nullptr;
  ClMem roots_mem(&cl), tab_mem(&cl);
  ClMem count_mem(&cl), index_mem(&cl), digest_mem(&cl);
  try {
    const char *source_cstr = source.c_str();
    const size_t source_len = source.size();
    program = cl.CreateProgramWithSource(context, 1, &source_cstr, &source_len, &err);
    cl_check(err, "clCreateProgramWithSource");
    err = cl.BuildProgram(program, 1, &device, nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS) {
      size_t log_size = 0;
      cl.GetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
      std::string log(log_size, '\0');
      cl.GetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log.size(), log.data(), nullptr);
      throw std::runtime_error("OpenCL 内核编译失败：" + log);
    }
    kernel = cl.CreateKernel(program, "zm_md5_match", &err);
    cl_check(err, "clCreateKernel");

    auto make_ro = [&](const void *data, size_t size) {
      cl_int e = CL_SUCCESS;
      const std::uint8_t dummy = 0;
      if (size == 0) { data = &dummy; size = 1; }
      cl_mem m = cl.CreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, size, const_cast<void *>(data), &e);
      cl_check(e, "clCreateBuffer");
      return m;
    };
    roots_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_ONLY, sizeof(RootWord4) * 4 * roots_per_launch, nullptr, &err);
    cl_check(err, "clCreateBuffer root_words");
    tab_mem.mem = make_ro(inner_tab.data(), inner_tab.size() * sizeof(VecWords));
    const std::uint32_t zero = 0;
    count_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(zero), const_cast<std::uint32_t *>(&zero), &err);
    cl_check(err, "clCreateBuffer hit_count");
    index_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_WRITE, sizeof(std::uint64_t) * max_hits, nullptr, &err);
    cl_check(err, "clCreateBuffer hit_index");
    digest_mem.mem = cl.CreateBuffer(context, CL_MEM_READ_WRITE, 16 * max_hits, nullptr, &err);
    cl_check(err, "clCreateBuffer hit_digest");

    auto set_u32 = [&](cl_uint n, std::uint32_t v) { cl_check(cl.SetKernelArg(kernel, n, sizeof(v), &v), "clSetKernelArg"); };
    auto set_u64 = [&](cl_uint n, std::uint64_t v) { cl_check(cl.SetKernelArg(kernel, n, sizeof(v), &v), "clSetKernelArg"); };
    auto set_mem = [&](cl_uint n, cl_mem m) { cl_check(cl.SetKernelArg(kernel, n, sizeof(m), &m), "clSetKernelArg"); };
    set_u64(2, inner_count);
    set_u64(3, stride);
    for (cl_uint i = 0; i != 4; ++i) {
      set_u32(4 + i, params.value[i]);
      set_u32(8 + i, params.mask[i]);
    }
    set_mem(12, roots_mem.mem);
    set_mem(13, tab_mem.mem);
    set_u32(14, max_hits);
    set_mem(15, count_mem.mem);
    set_mem(16, index_mem.mem);
    set_mem(17, digest_mem.mem);

    const size_t local_size = 256;
    std::vector<RootWord4> staging(4 * roots_per_launch);
    std::vector<std::uint32_t> digits(L);

    const auto start = std::chrono::steady_clock::now();
    std::uint64_t roots_done = 0;
    while (roots_done < roots_total) {
      const std::uint64_t roots_this = std::min(roots_per_launch, roots_total - roots_done);

      // Host-side root decode over the trailing positions [n_inner, L):
      // seek the mixed-radix digit cursor to the first root of this chunk,
      // then repack 16 message words per root (padding and length preset),
      // advancing the cursor with carry per root.
      std::uint64_t r = roots_done;
      for (std::size_t q = L; q-- > n_inner;) {
        digits[q] = static_cast<std::uint32_t>(r % params.radix[q]);
        r /= params.radix[q];
      }
      for (std::uint64_t root = 0; root < roots_this; ++root) {
        std::uint32_t w[16] = {};
        for (std::size_t q = n_inner; q < L; ++q)
          w[q >> 2] |= static_cast<std::uint32_t>(params.chars[params.offsets[q] + digits[q]]) << ((q & 3) * 8);
        w[L >> 2] |= 0x80u << ((L & 3) * 8);
        w[14] = static_cast<std::uint32_t>(L * 8);
        auto *dst = &staging[4 * root];
        for (unsigned i = 0; i != 4; ++i)
          for (unsigned j = 0; j != 4; ++j) dst[i].v[j] = w[4 * i + j];
        for (std::size_t q = L; q-- > n_inner;) {
          if (++digits[q] < params.radix[q]) break;
          digits[q] = 0;
        }
      }
      cl_check(cl.EnqueueWriteBuffer(queue, roots_mem.mem, CL_TRUE, 0,
                                     sizeof(RootWord4) * 4 * roots_this, staging.data(),
                                     0, nullptr, nullptr),
               "clEnqueueWriteBuffer roots");

      set_u64(0, roots_done);
      set_u64(1, roots_this);
      const size_t global_size = static_cast<size_t>((roots_this + local_size - 1) / local_size) * local_size;
      cl_check(cl.EnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global_size, &local_size, 0, nullptr, nullptr),
               "clEnqueueNDRangeKernel");
      cl_check(cl.Finish(queue), "clFinish");
      roots_done += roots_this;
      std::uint32_t hits = 0;
      cl_check(cl.EnqueueReadBuffer(queue, count_mem.mem, CL_TRUE, 0, sizeof(hits), &hits, 0, nullptr, nullptr),
               "clEnqueueReadBuffer");
      result.hit_total = hits;
      if (params.interrupted && params.interrupted->load(std::memory_order_relaxed)) break;
      if (hits >= max_hits) break;
    }
    result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    result.processed = std::min(params.limit, roots_done * inner_count);

    const std::uint32_t stored = static_cast<std::uint32_t>(std::min<std::uint64_t>(result.hit_total, max_hits));
    if (stored) {
      std::vector<std::uint64_t> indices(stored);
      std::vector<std::array<std::uint32_t, 4>> digests(stored);
      cl_check(cl.EnqueueReadBuffer(queue, index_mem.mem, CL_TRUE, 0, stored * sizeof(std::uint64_t), indices.data(), 0, nullptr, nullptr),
               "clEnqueueReadBuffer hits");
      cl_check(cl.EnqueueReadBuffer(queue, digest_mem.mem, CL_TRUE, 0, stored * 16, digests.data(), 0, nullptr, nullptr),
               "clEnqueueReadBuffer digests");
      result.hits.resize(stored);
      for (std::uint32_t i = 0; i != stored; ++i) result.hits[i] = GpuMatchHit{indices[i], digests[i]};
    }
  } catch (...) {
    if (kernel) cl.ReleaseKernel(kernel);
    if (program) cl.ReleaseProgram(program);
    cl.ReleaseCommandQueue(queue);
    cl.ReleaseContext(context);
    throw;
  }
  cl.ReleaseKernel(kernel);
  cl.ReleaseProgram(program);
  cl.ReleaseCommandQueue(queue);
  cl.ReleaseContext(context);
  return result;
}
