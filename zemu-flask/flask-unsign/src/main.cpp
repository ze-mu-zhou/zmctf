/**
 * zemu-flask:密码/爆破工具集 CLI。
 *
 * 用法:
 *   zemu-flask flask decode --cookie <c>
 *   zemu-flask flask verify --cookie <c> --secret <s> [--salt <salt>]
 *   zemu-flask flask sign   --secret <s> --json <j> [--salt <salt>] [--legacy]
 *   zemu-flask flask crack  --cookie <c> (--wordlist <f> | --mask <?l?l?d?d>)
 *                            [--salt <salt>] [--threads N] [--engine auto|gpu|cuda|cpu]
 *   zemu-flask selftest     # SHA-NI 与便携实现对拍
 *   zemu-flask gpuinfo      # OpenCL GPU 探测
 *   zemu-flask gputest      # OpenCL 冒烟测试
 *   zemu-flask serve        # stdin 服务模式(进程常驻,GPU 上下文复用)
 *   zemu-flask interactive  # 交互模式:菜单选操作,逐项提问(无参数且 stdin 是终端时自动进入)
 *   zemu-flask help         # 彩色中文帮助(掩码规则详解)
 *
 * crack 结果(secret)与 sign/decode 输出走 stdout,统计、进度与交互提示走 stderr。
 * 帮助彩色输出:终端为 tty 时自动启用;ZK_COLOR=1 可强制开启(管道调试用)。
 * 构建:仅支持 MSYS2 UCRT64 的 MinGW g++(见 build.sh);MSVC 不适用——
 * 源码依赖 GNU __attribute__((target)) 与直接 #include <windows.h>。
 */
#include "flask.h"
#include "gpu/ocl.h"
#include "json_mini.h"
#include "sha1.h"

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

/** SHA-NI 对拍自测:len 0..256 随机输入,便携实现 vs SHA-NI 全比对 */
static int cmdSelftest() {
  if (!hasShaNi()) {
    std::cout << "SHA-NI 不可用,当前走便携实现" << std::endl;
    return 0;
  }
  std::mt19937 rng(12345); // 固定种子,对拍序列可复现
  std::uniform_int_distribution<int> dist(0, 255);
  for (int len = 0; len <= 256; len++) {
    std::vector<uint8_t> data((size_t)len);
    for (auto& b : data) b = (uint8_t)dist(rng);
    uint8_t d1[20], d2[20];
    g_forceImpl = 1;
    { Sha1 h; h.update(data.data(), data.size()); h.final(d1); }
    g_forceImpl = 2;
    { Sha1 h; h.update(data.data(), data.size()); h.final(d2); }
    if (memcmp(d1, d2, 20) != 0) {
      std::cerr << "[!] SHA-NI 与便携实现不一致(len=" << len << ")" << std::endl;
      g_forceImpl = 0;
      return 1;
    }
  }
  g_forceImpl = 0;
  std::cout << "SHA-NI selftest OK(len 0..256 与便携实现全一致)" << std::endl;
  return 0;
}

/** Windows 控制台默认关 ANSI;开启虚拟终端处理后才认彩色转义序列 */
static void enableVtColors() {
#ifdef _WIN32
  auto fix = [](DWORD stdHandle) {
    HANDLE h = GetStdHandle(stdHandle);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
      SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  };
  fix(STD_OUTPUT_HANDLE);
  fix(STD_ERROR_HANDLE);
#endif
}

/** tty 自动彩色;ZK_COLOR=1 强制彩色(输出被管道接走时用) */
static bool wantColor(FILE* f) {
  if (std::getenv("ZK_COLOR")) return true;
#ifdef _WIN32
  return _isatty(_fileno(f)) != 0;
#else
  return isatty(fileno(f)) != 0;
#endif
}

static void usage(std::ostream& os, bool color) {
  const char *B = "", *CY = "", *YE = "", *GN = "", *DIM = "", *R = "";
  if (color) { // 粗体 / 青(命令) / 黄(参数) / 绿(掩码占位符) / 暗(备注)
    B = "\033[1m"; CY = "\033[36m"; YE = "\033[33m";
    GN = "\033[32m"; DIM = "\033[2m"; R = "\033[0m";
  }
  os << B << "用法:" << R << "\n"
     << "  " << CY << "zemu-flask" << R << "                 " << DIM << "# 无参数:进入交互模式(一问一答)" << R << "\n"
     << "  " << CY << "zemu-flask" << R << " <命令> [参数]\n\n"

     << B << "命令:" << R << "\n"
     << "  " << CY << "flask decode" << R << "  " << YE << "--cookie <c>" << R
     << "  解析 cookie,输出其中的 JSON\n"
     << "  " << CY << "flask verify" << R << "  " << YE << "--cookie <c> --secret <s>" << R
     << " [" << YE << "--salt <s>" << R << "]  验证 cookie 签名\n"
     << "  " << CY << "flask sign" << R << "    " << YE << "--secret <s> --json <j>" << R
     << " [" << YE << "--salt <s>" << R << "] [" << YE << "--legacy" << R
     << "]  用密钥签出新 cookie\n"
     << "  " << CY << "flask crack" << R << "   " << YE << "--cookie <c>" << R
     << " (" << YE << "--wordlist <f>" << R << " | " << YE << "--mask <掩码>" << R << ")\n"
     << "               [" << YE << "--salt <s>" << R << "] [" << YE << "--threads N" << R
     << "] [" << YE << "--engine auto|gpu|cuda|cpu" << R << "]  爆破密钥\n"
     << "  " << CY << "selftest" << R << "        SHA-NI 与便携实现全量对拍\n"
     << "  " << CY << "gpuinfo" << R << "         探测 OpenCL GPU\n"
     << "  " << CY << "gputest" << R << "         GPU 冒烟测试\n"
     << "  " << CY << "serve" << R << "           stdin 常驻服务(JSON 行协议)\n"
     << "  " << CY << "interactive" << R << "     进入交互模式(与无参数运行相同)\n"
     << "  " << CY << "help" << R << "            显示本帮助\n\n"

     << B << "掩码(" << YE << "--mask" << R << B << "):" << R << "\n"
     << "  逐位描述密钥每个字符的取值范围,工具穷举所有组合。\n"
     << "  占位符(每个占一位):\n"
     << "    " << GN << "?l" << R << "  小写字母 a-z              (26 种/位)\n"
     << "    " << GN << "?u" << R << "  大写字母 A-Z              (26 种/位)\n"
     << "    " << GN << "?d" << R << "  数字 0-9                  (10 种/位)\n"
     << "    " << GN << "?s" << R << "  特殊字符(含空格)         (33 种/位)\n"
     << "    " << GN << "?a" << R << "  以上全部 = 95 个可打印字符 (95 种/位)\n"
     << "    " << GN << "??" << R << "  字面问号 \"?\" 本身\n"
     << "  其余字符原样照写,表示该位置固定不变。\n"
     << "  总组合数 = 每位种数相乘,例如:\n"
     << "    " << GN << "?l?l?d?d" << R << "       26×26×10×10 = 67,600 种\n"
     << "    " << GN << "admin?d?d?d?d" << R << "  10×10×10×10   = 10,000 种(前 5 位固定)\n"
     << "  " << DIM << "注意:组合数越大耗时越长;GPU 模式掩码最多 24 位,超出请加 "
     << YE << "--engine cpu" << R << DIM << "。" << R << "\n\n"

     << B << "引擎(" << YE << "--engine" << R << B << "):" << R << "\n"
     << "  " << GN << "auto" << R << "  默认。大任务 GPU 与 CPU 同时对向吃块,小任务纯 CPU\n"
     << "  " << GN << "gpu" << R << "    仅 OpenCL GPU;失败即报错,不回退\n"
     << "  " << GN << "cuda" << R << "   仅 CUDA 后端(需 CUDA Toolkit 的 NVRTC)\n"
     << "  " << GN << "cpu" << R << "    仅 CPU(" << YE << "--threads" << R << " 控线程数)\n\n"

     << B << "示例:" << R << "\n"
     << "  " << CY << "zemu-flask" << R << " flask crack --cookie <c> --wordlist rockyou.txt\n"
     << "  " << CY << "zemu-flask" << R << " flask crack --cookie <c> --mask \""
     << GN << "?u?l?l?l?l?d?d" << R << "\"\n"
     << "  " << CY << "zemu-flask" << R << " flask crack --cookie <c> --mask \""
     << GN << "admin?d?d?d?d" << R << "\" --engine cpu --threads 8\n\n"

     << DIM << "不带 --salt 时使用 Flask 默认盐 \"cookie-session\"。\n"
     << "结果数据走 stdout,进度与统计走 stderr。" << R << "\n";
}

/** 单条命令分发(argv[1] 为子命令);main 与 serve 共用 */
static int runCommand(int argc, char** argv) {
  std::string cmd = argv[1];

  if (cmd == "selftest") return cmdSelftest();
  if (cmd == "gpuinfo") {
    GpuProbe p = gpuProbe();
    if (p.ok) {
      std::cout << "GPU 可用: " << p.deviceName << std::endl;
      return 0;
    }
    std::cout << "GPU 不可用: " << p.error << std::endl;
    return 1;
  }
  if (cmd == "gputest") {
    std::string err;
    int rc = gpuSmokeTest(err);
    if (rc == 0) {
      std::cout << "OpenCL 基础链路 OK" << std::endl;
      return 0;
    }
    std::cout << "OpenCL 冒烟测试失败: " << err << std::endl;
    return 1;
  }

  if (cmd == "flask") {
    if (argc < 3) { usage(std::cerr, wantColor(stderr)); return 2; }
    std::string action = argv[2];
    std::string cookie, secret, jsonText, salt, wordlist, mask, engine = "auto";
    int threads = 0;
    bool legacy = false;
    for (int i = 3; i < argc; i++) {
      std::string a = argv[i];
      auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
      if (a == "--cookie") cookie = next();
      else if (a == "--secret") secret = next();
      else if (a == "--json") jsonText = next();
      else if (a == "--salt") salt = next();
      else if (a == "--wordlist") wordlist = next();
      else if (a == "--mask") mask = next();
      else if (a == "--threads") {
        std::string v = next();
        std::from_chars(v.data(), v.data() + v.size(), threads); // 非法输入保持 0=自动
      }
      else if (a == "--engine") engine = next();
      else if (a == "--legacy") legacy = true;
      else { std::cerr << "[!] 未知参数: " << a << std::endl; usage(std::cerr, wantColor(stderr)); return 2; }
    }
    if (engine != "auto" && engine != "gpu" && engine != "cpu" && engine != "cuda") {
      std::cerr << "[!] --engine 只支持 auto|gpu|cpu|cuda,收到: " << engine << std::endl;
      return 2;
    }
    if (action == "decode" && !cookie.empty()) return flaskDecode(cookie);
    if (action == "verify" && !cookie.empty() && !secret.empty())
      return flaskVerify(cookie, secret, salt);
    if (action == "sign" && !secret.empty() && !jsonText.empty())
      return flaskSign(secret, jsonText, salt, legacy);
    if (action == "crack" && !cookie.empty())
      return flaskCrack(cookie, wordlist, mask, salt, threads, engine);
  }
  usage(std::cerr, wantColor(stderr));
  return 2;
}

/**
 * stdin 服务模式:每行一个 JSON 字符串数组(即 argv,不含程序名),
 * stdout/stderr 合流,每条命令以 <<<zk-rc=N>>> 哨兵行结束。
 * 进程常驻:GPU 上下文初始化一次,后续 crack 不再付 ~110ms 初始化与进程创建开销。
 */
static int cmdServe() {
  std::cerr.rdbuf(std::cout.rdbuf()); // 合流:GUI 只需读 stdout
  std::string line;
  while (std::getline(std::cin, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    Json j;
    JsonParser parser(line);
    std::vector<std::string> args;
    bool ok = parser.parse(j) && j.type == Json::ARR;
    if (ok) {
      for (const auto& v : j.arr) {
        if (v.type != Json::STR) { ok = false; break; }
        args.push_back(v.str);
      }
    }
    int rc = 2;
    if (ok && !args.empty()) {
      std::vector<char*> argv;
      argv.reserve(args.size() + 1);
      argv.push_back((char*)"zemu-flask");
      for (auto& a : args) argv.push_back(a.data());
      rc = runCommand((int)argv.size(), argv.data());
    } else {
      std::cout << "[!] serve:命令须为非空 JSON 字符串数组" << std::endl;
    }
    std::cout << "<<<zk-rc=" << rc << ">>>" << std::endl;
  }
  return 0;
}

/** stdin 是否为终端:是则无参数时进交互模式;管道则保持打印用法(脚本友好)。
 * 注意 Windows 上 _isatty 对 NUL 这类字符设备也返回真,须用 GetConsoleMode 判定 */
static bool stdinIsTty() {
#ifdef _WIN32
  DWORD mode;
  return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
  return isatty(fileno(stdin)) != 0;
#endif
}

/** 交互提问(提示语走 stderr,stdout 只留结果);读到 EOF 置 eof=true */
static std::string ask(const std::string& prompt, bool& eof) {
  std::cerr << prompt;
  std::cerr.flush();
  std::string line;
  if (!std::getline(std::cin, line)) eof = true;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  return line;
}

/** 交互模式:菜单选操作,逐项问参数,拼成 argv 仍走 runCommand 执行,完成后回到菜单 */
static int cmdInteractive() {
  const bool color = wantColor(stderr);
  const char *B = "", *CY = "", *GN = "", *R = "";
  if (color) { B = "\033[1m"; CY = "\033[36m"; GN = "\033[32m"; R = "\033[0m"; }
  bool eof = false;
  for (;;) {
    std::cerr << "\n" << B << "===== zemu-flask 交互模式 =====" << R << "\n"
              << "  " << CY << "1" << R << ") flask decode  解析 cookie\n"
              << "  " << CY << "2" << R << ") flask verify  验证 cookie 签名\n"
              << "  " << CY << "3" << R << ") flask sign    用密钥签新 cookie\n"
              << "  " << CY << "4" << R << ") flask crack   爆破密钥(字典/掩码)\n"
              << "  " << CY << "0" << R << ") 退出\n";
    std::string c = ask("请选择 [0-4]: ", eof);
    if (eof || c == "0" || c == "q" || c == "Q") break;
    std::vector<std::string> args;
    if (c == "1") {
      args = {"flask", "decode", "--cookie", ask("cookie: ", eof)};
    } else if (c == "2") {
      args = {"flask", "verify",
              "--cookie", ask("cookie: ", eof),
              "--secret", ask("secret: ", eof)};
      std::string salt = ask("salt(留空=cookie-session): ", eof);
      if (!salt.empty()) { args.push_back("--salt"); args.push_back(salt); }
    } else if (c == "3") {
      args = {"flask", "sign",
              "--secret", ask("secret: ", eof),
              "--json", ask("JSON(单行,如 {\"a\":1}): ", eof)};
      std::string salt = ask("salt(留空=cookie-session): ", eof);
      if (!salt.empty()) { args.push_back("--salt"); args.push_back(salt); }
      std::string leg = ask("legacy 模式?[y/N]: ", eof);
      if (leg == "y" || leg == "Y") args.push_back("--legacy");
    } else if (c == "4") {
      args = {"flask", "crack", "--cookie", ask("cookie: ", eof)};
      std::string mode = ask("模式 [1=字典 2=掩码]: ", eof);
      if (mode == "1") {
        args.push_back("--wordlist");
        args.push_back(ask("wordlist 路径: ", eof));
      } else if (mode == "2") {
        args.push_back("--mask");
        args.push_back(ask(std::string("掩码(") + GN + "?l" + R + "=小写 " + GN + "?u" + R +
                           "=大写 " + GN + "?d" + R + "=数字 " + GN + "?s" + R + "=特殊 " +
                           GN + "?a" + R + "=全部 " + GN + "??" + R + "=字面?): ", eof));
      } else {
        std::cerr << "[!] 无效选择" << std::endl;
        continue;
      }
      std::string salt = ask("salt(留空=cookie-session): ", eof);
      if (!salt.empty()) { args.push_back("--salt"); args.push_back(salt); }
      std::string engine = ask("engine [auto/gpu/cpu](留空=auto): ", eof);
      if (!engine.empty()) { args.push_back("--engine"); args.push_back(engine); }
      std::string threads = ask("threads(留空=自动): ", eof);
      if (!threads.empty()) { args.push_back("--threads"); args.push_back(threads); }
    } else {
      std::cerr << "[!] 无效选择,请重新输入" << std::endl;
      continue;
    }
    if (eof) break;
    std::vector<char*> argv; // 与 cmdServe 相同的 argv 拼装手法
    argv.reserve(args.size() + 1);
    argv.push_back((char*)"zemu-flask");
    for (auto& a : args) argv.push_back(a.data());
    runCommand((int)argv.size(), argv.data());
  }
  return 0;
}

/** 实际入口(UTF-8 argv 已就绪),平台差异在下方薄壳层消化 */
static int runMain(int argc, char** argv) {
  enableVtColors();
  if (argc >= 2 && std::string(argv[1]) == "serve") return cmdServe();
  if (argc >= 2) {
    std::string a1 = argv[1];
    if (a1 == "interactive" || a1 == "-i") return cmdInteractive();
    if (a1 == "help" || a1 == "--help" || a1 == "-h") { // 打印到 stdout,退出码 0
      usage(std::cout, wantColor(stdout));
      return 0;
    }
  }
  if (argc < 2) { // 终端无参数 → 交互模式;管道无参数 → 打印用法
    if (stdinIsTty()) return cmdInteractive();
    usage(std::cerr, wantColor(stderr));
    return 2;
  }
  return runCommand(argc, argv);
}

#ifdef _WIN32

/** UTF-16 → UTF-8(wmain 的 argv 是宽字符;窄字符 main 拿到的是 ANSI 码页字节,
 *  中文系统下非 ASCII 参数会被 GBK 化,HMAC 密钥/JSON/salt 全部失配) */
static std::string utf8FromWide(const wchar_t* ws) {
  int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
  std::string s((size_t)(n > 0 ? n : 0), '\0');
  if (n > 0) {
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, s.data(), n, nullptr, nullptr);
    s.resize((size_t)n - 1); // 去掉 WideCharToMultiByte 写入的结尾 NUL
  }
  return s;
}

int wmain(int argc, wchar_t** argv) {
  // 控制台切 UTF-8:交互模式键入与彩色中文提示在真实控制台不再乱码;
  // 输出重定向到管道时无影响(管道本就按原始字节收发)
  SetConsoleCP(CP_UTF8);
  SetConsoleOutputCP(CP_UTF8);
  std::vector<std::string> args((size_t)argc);
  for (int i = 0; i < argc; i++) args[(size_t)i] = utf8FromWide(argv[i]);
  std::vector<char*> argp((size_t)argc);
  for (int i = 0; i < argc; i++) argp[(size_t)i] = args[(size_t)i].data();
  return runMain(argc, argp.data());
}

#else

int main(int argc, char** argv) { return runMain(argc, argv); }

#endif
