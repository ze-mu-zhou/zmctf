/**
 * zemu-autodan:统一 LLM 越狱红队 CLI(C++26)。
 * 无参数运行 → 交互式 shell(set 配置,template/autodan/adaptive/chat 直接跑);
 * 带参数运行 → 传统 CLI 单次执行。
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "attacks/adaptive.h"
#include "attacks/autodan.h"
#include "attacks/template.h"
#include "target.h"

using namespace zemu;

// ============================================================ 配置

struct Cli {
  std::string backend, baseUrl, model, key, corpus, filter, behavior, behaviors;
  std::string suffix, targetToken, learnedOut;
  std::string aBackend, aBaseUrl, aModel, aKey;
  bool verbose = false, noVerify = false, llmJudge = false;
  int iterations = 50, restarts = 1, epochs = 5, topK = 5;
  double breakScore = 8.5;
};

static void usage(std::ostream& os) {
  os << "用法:\n"
     << "  zemu-autodan              进入交互式 shell\n"
     << "  zemu-autodan <攻击> [参数]  单次执行\n\n"
     << "攻击:\n"
     << "  template  批量发送 Spiritual 语料模板\n"
     << "  autodan   AutoDAN-Turbo 模式:attacker/scorer/summarizer 三智能体终身学习\n"
     << "  adaptive  logprobs 随机搜索 + Claude prefill/迁移\n"
     << "  chat      交互式对话 REPL(/quit 退出,/clear 清历史,/system <s> 设系统提示)\n\n"
     << "通用参数:\n"
     << "  --backend openai|anthropic|gemini|manual   后端类型(manual=人工中转)\n"
     << "  --base-url <u>   API 地址(openai 默认 https://api.openai.com/v1;\n"
     << "                   vllm 本地: http://127.0.0.1:8000/v1)\n"
     << "  --model <m>      模型名\n"
     << "  --key <k>        API key(也可用环境变量 ZEMU_KEY)\n"
     << "  --no-verify      关闭 TLS 证书校验(本地 http 自动关闭)\n"
     << "  --judge-llm      用 LLM 判定而非本地拒绝词\n"
     << "  -v               显示完整 prompt/响应(template)\n\n"
     << "autodan 专有:\n"
     << "  --behavior <b> / --behaviors <f>   目标行为(单个/文件每行一个)\n"
     << "  --corpus <json>        种子策略语料\n"
     << "  --epochs <n>           每行为探索轮数(默认 5)\n"
     << "  --break-score <f>      成功分数线(默认 8.5)\n"
     << "  --top-k <n>            每轮检索策略数(默认 5)\n"
     << "  --learned-out <f>      学到策略写回文件(默认 <corpus目录>/learned_strategies.json)\n"
     << "  --attacker-backend/--attacker-base-url/--attacker-model/--attacker-key\n"
     << "                         红队 LLM 配置(缺省=目标同配置)\n\n"
     << "adaptive 专有:\n"
     << "  --iterations <n>   每次重启的搜索轮数(默认 50)\n"
     << "  --restarts <n>     随机重启次数(默认 1)\n"
     << "  --suffix <s>       手工初始 suffix(Claude 迁移攻击用)\n"
     << "  --target-token <t> 目标 token(默认按模型名自动)\n\n"
     << "template 专有:\n"
     << "  --corpus <json>  语料 JSON\n"
     << "  --filter <族>     只跑匹配的模型族(如 Claude)\n"
     << "  --behavior <b>    替换模板中的 {{behavior}}\n";
}

/** 解析参数token(不含程序名/子命令)到 Cli;err 输出错误。 */
static bool parseInto(Cli& c, const std::vector<std::string>& args, std::string& err) {
  for (std::size_t i = 0; i < args.size(); i++) {
    const std::string& a = args[i];
    auto next = [&]() -> std::string { return i + 1 < args.size() ? args[++i] : ""; };
    if (a == "--backend") c.backend = next();
    else if (a == "--base-url") c.baseUrl = next();
    else if (a == "--model") c.model = next();
    else if (a == "--key") c.key = next();
    else if (a == "--corpus") c.corpus = next();
    else if (a == "--filter") c.filter = next();
    else if (a == "--behavior") c.behavior = next();
    else if (a == "--behaviors") c.behaviors = next();
    else if (a == "--iterations") c.iterations = std::atoi(next().c_str());
    else if (a == "--restarts") c.restarts = std::atoi(next().c_str());
    else if (a == "--epochs") c.epochs = std::atoi(next().c_str());
    else if (a == "--top-k") c.topK = std::atoi(next().c_str());
    else if (a == "--break-score") c.breakScore = std::atof(next().c_str());
    else if (a == "--suffix") c.suffix = next();
    else if (a == "--target-token") c.targetToken = next();
    else if (a == "--learned-out") c.learnedOut = next();
    else if (a == "--attacker-backend") c.aBackend = next();
    else if (a == "--attacker-base-url") c.aBaseUrl = next();
    else if (a == "--attacker-model") c.aModel = next();
    else if (a == "--attacker-key") c.aKey = next();
    else if (a == "--judge-llm") c.llmJudge = true;
    else if (a == "--no-verify") c.noVerify = true;
    else if (a == "-v") c.verbose = true;
    else if (a == "--rounds") c.epochs = std::atoi(next().c_str());  // 旧参数兼容
    else { err = "未知参数: " + a; return false; }
  }
  return true;
}

static target::TargetConfig makeCfg(const std::string& backend, const std::string& baseUrl,
                                    const std::string& model, const std::string& key,
                                    bool noVerify) {
  target::TargetConfig cfg;
  if (backend == "manual") {
    cfg.backend = target::Backend::MANUAL;
    cfg.model = "human-in-the-loop";
    cfg.baseUrl.clear();
    cfg.verifyTls = false;
    return cfg;
  }
  if (backend == "anthropic") {
    cfg.backend = target::Backend::ANTHROPIC;
    cfg.baseUrl = baseUrl.empty() ? "https://api.anthropic.com" : baseUrl;
    cfg.model = model.empty() ? "claude-3-5-sonnet-20241022" : model;
  } else if (backend == "gemini") {
    cfg.backend = target::Backend::GEMINI;
    cfg.baseUrl = baseUrl.empty() ? "https://generativelanguage.googleapis.com" : baseUrl;
    cfg.model = model.empty() ? "gemini-1.5-pro" : model;
  } else {
    cfg.backend = target::Backend::OPENAI;
    cfg.baseUrl = baseUrl.empty() ? "https://api.openai.com/v1" : baseUrl;
    cfg.model = model.empty() ? "gpt-4o" : model;
  }
  cfg.apiKey = key;
  cfg.verifyTls = !noVerify;
  return cfg;
}

static void loadEnvKey(Cli& c) {
  if (c.key.empty()) {
    const char* ek = std::getenv("ZEMU_KEY");
    if (ek) c.key = ek;
  }
}

/** exe 所在目录(默认语料按 exe 位置定位,任意 cwd 都能跑) */
static std::string exeDir() {
#ifdef _WIN32
  char buf[MAX_PATH];
  DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
  if (n == 0) return ".";
  std::string p(buf, n);
#else
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
  if (n <= 0) return ".";
  buf[n] = 0;
  std::string p(buf);
#endif
  auto s = p.find_last_of("/\\");
  return s == std::string::npos ? "." : p.substr(0, s);
}

/** 默认语料:exe 在 bin/ 下,语料在 ../src/resources/corpus.json;找不到再试 cwd 相对路径 */
static std::string defaultCorpus() {
  std::string p = exeDir() + "/../src/resources/corpus.json";
  if (std::ifstream(p).good()) return p;
  if (std::ifstream("src/resources/corpus.json").good()) return "src/resources/corpus.json";
  return "";
}

static void ensureDefaults(Cli& c) {
  loadEnvKey(c);
  if (c.corpus.empty()) c.corpus = defaultCorpus();
}

// ============================================================ 子命令

static int runChat(const Cli& c) {
  target::Target tgt(makeCfg(c.backend, c.baseUrl, c.model, c.key, c.noVerify));
  std::vector<target::Msg> history;
  std::cout << "== 交互对话(" << tgt.backendName() << "/" << tgt.model()
            << "):/quit 退出,/clear 清历史,/system <s> 设系统提示 ==" << std::endl;
  std::string line;
  while (true) {
    std::cout << "\n> " << std::flush;
    if (!std::getline(std::cin, line) || line == "/quit") break;
    if (line == "/clear") { history.clear(); std::cout << "(历史已清空)" << std::endl; continue; }
    if (line.rfind("/system ", 0) == 0) {
      if (!history.empty() && history[0].role == "system") history.erase(history.begin());
      history.insert(history.begin(), {"system", line.substr(8)});
      std::cout << "(系统提示已设置)" << std::endl;
      continue;
    }
    if (line.empty()) continue;
    history.push_back({"user", line});
    target::GenOptions go;
    go.temperature = 0.7;
    auto res = tgt.complete(history, go);
    if (!res.ok) {
      std::cerr << "[!] " << res.error << std::endl;
      history.pop_back();
      continue;
    }
    std::cout << res.text << std::endl;
    history.push_back({"assistant", res.text});
  }
  return 0;
}

static int dispatch(const std::string& cmd, Cli c) {
  ensureDefaults(c);
  if (cmd == "chat") return runChat(c);
  if (cmd == "template") {
    if (c.corpus.empty()) { std::cerr << "[!] 需要 --corpus(或 set corpus ...)" << std::endl; return 2; }
    target::Target tgt(makeCfg(c.backend, c.baseUrl, c.model, c.key, c.noVerify));
    return zemu::attack::runTemplate(tgt, c.corpus, c.filter, c.behavior, c.verbose);
  }
  if (cmd == "adaptive") {
    if (c.behavior.empty() && c.behaviors.empty()) {
      std::cerr << "[!] 需要 --behavior 或 --behaviors" << std::endl; return 2;
    }
    target::Target tgt(makeCfg(c.backend, c.baseUrl, c.model, c.key, c.noVerify));
    zemu::attack::AdaptiveOptions ao{
        .behaviors = c.behaviors, .behavior = c.behavior, .iterations = c.iterations,
        .topLogprobs = 5, .maxTokens = 512, .llmJudge = c.llmJudge,
        .restarts = c.restarts, .suffix = c.suffix, .targetToken = c.targetToken};
    return zemu::attack::runAdaptive(tgt, ao);
  }
  if (cmd == "autodan") {
    if (c.corpus.empty() || (c.behavior.empty() && c.behaviors.empty())) {
      std::cerr << "[!] 需要 --corpus 和 --behavior/--behaviors" << std::endl; return 2;
    }
    target::Target tgt(makeCfg(c.backend, c.baseUrl, c.model, c.key, c.noVerify));
    if (c.aKey.empty()) c.aKey = c.key;
    auto aCfg = (c.aBackend.empty() && c.aBaseUrl.empty())
                    ? makeCfg(c.backend, c.baseUrl, c.aModel.empty() ? c.model : c.aModel,
                              c.aKey, c.noVerify)
                    : makeCfg(c.aBackend, c.aBaseUrl, c.aModel, c.aKey, c.noVerify);
    target::Target attacker(aCfg);
    std::cerr << "[i] attacker LLM: " << attacker.backendName() << "/" << attacker.model()
              << std::endl;
    zemu::attack::AutodanOptions ao{
        .corpus = c.corpus, .behavior = c.behavior, .behaviors = c.behaviors,
        .epochs = c.epochs, .breakScore = c.breakScore, .topK = c.topK,
        .maxTokens = 512, .llmJudge = c.llmJudge, .learnedOut = c.learnedOut};
    return zemu::attack::runAutodan(tgt, attacker, ao);
  }
  if (cmd == "help") { usage(std::cout); return 0; }
  std::cerr << "[!] 未知命令: " << cmd << std::endl;
  return 2;
}

// ============================================================ 交互式 shell(菜单式)

/** 按空白切分,支持双引号包裹含空格的参数 */
static std::vector<std::string> splitLine(const std::string& line) {
  std::vector<std::string> out;
  std::string cur;
  bool inQ = false;
  for (char ch : line) {
    if (ch == '"') { inQ = !inQ; continue; }
    if (!inQ && (ch == ' ' || ch == '\t')) {
      if (!cur.empty()) { out.push_back(cur); cur.clear(); }
    } else {
      cur += ch;
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

static std::string maskKey(const std::string& k) {
  if (k.empty()) return "(未设置,可用 ZEMU_KEY)";
  if (k.size() <= 6) return "******";
  return "******" + k.substr(k.size() - 4);
}

static std::string ask(const std::string& prompt) {
  std::cout << prompt << std::flush;
  std::string s;
  if (!std::getline(std::cin, s)) return "";
  if (!s.empty() && s.back() == '\r') s.pop_back();
  return s;
}

static void showCfg(const Cli& c) {
  auto show = [](const char* k, const std::string& v) {
    if (!v.empty()) std::cout << "  " << k << " = " << v << "\n";
  };
  std::cout << "当前配置:\n";
  show("backend", c.backend); show("base-url", c.baseUrl); show("model", c.model);
  std::cout << "  key = " << maskKey(c.key) << "\n";
  show("corpus", c.corpus); show("filter", c.filter);
  show("behavior", c.behavior); show("behaviors", c.behaviors);
  show("suffix", c.suffix); show("target-token", c.targetToken);
  show("learned-out", c.learnedOut);
  show("attacker-backend", c.aBackend); show("attacker-base-url", c.aBaseUrl);
  show("attacker-model", c.aModel);
  if (!c.aKey.empty()) std::cout << "  attacker-key = " << maskKey(c.aKey) << "\n";
  std::cout << "  iterations=" << c.iterations << " restarts=" << c.restarts
            << " epochs=" << c.epochs << " top-k=" << c.topK
            << " break-score=" << c.breakScore << "\n"
            << "  judge-llm=" << (c.llmJudge ? "on" : "off")
            << " no-verify=" << (c.noVerify ? "on" : "off")
            << " verbose=" << (c.verbose ? "on" : "off") << std::endl;
}

static void menuBackend(Cli& base) {
  std::cout << "选择后端:\n"
            << "  [1] openai(含 vllm/ollama 等兼容接口)\n"
            << "  [2] anthropic\n"
            << "  [3] gemini\n"
            << "  [4] manual(人工中转:目标只有网页接口时选这个)\n"
            << "  [0] 取消\n";
  std::string s = ask("> ");
  if (s == "1") base.backend = "openai";
  else if (s == "2") base.backend = "anthropic";
  else if (s == "3") base.backend = "gemini";
  else if (s == "4") base.backend = "manual";
  else return;
  std::cout << "ok: backend = " << base.backend << std::endl;
  if (base.backend != "manual" && base.baseUrl.empty()) {
    std::string u = ask("base-url(回车=默认官方接口;本地 vllm/ollama 填 http://127.0.0.1:端口/v1): ");
    if (!u.empty()) base.baseUrl = u;
  }
}

static void menuConfig(Cli& base) {
  for (;;) {
    std::cout << "\n---- 配置 ----\n"
              << "  [1] backend       (当前: " << (base.backend.empty() ? "openai" : base.backend) << ")\n"
              << "  [2] base-url      (当前: " << (base.baseUrl.empty() ? "默认" : base.baseUrl) << ")\n"
              << "  [3] model         (当前: " << (base.model.empty() ? "默认" : base.model) << ")\n"
              << "  [4] key           (当前: " << maskKey(base.key) << ")\n"
              << "  [5] behavior      (当前: " << (base.behavior.empty() ? "(未设)" : base.behavior) << ")\n"
              << "  [6] attacker 配置 (autodan 用;当前: "
              << (base.aModel.empty() ? "同目标" : base.aModel) << ")\n"
              << "  [7] judge-llm 开关(当前: " << (base.llmJudge ? "on" : "off") << ")\n"
              << "  [8] no-verify 开关(当前: " << (base.noVerify ? "on" : "off") << ")\n"
              << "  [9] epochs/iterations(当前: " << base.epochs << "/" << base.iterations << ")\n"
              << "  [0] 返回\n";
    std::string s = ask("选择> ");
    if (s.empty() || s == "0") return;
    if (s == "1") menuBackend(base);
    else if (s == "2") { base.baseUrl = ask("base-url: "); }
    else if (s == "3") { base.model = ask("model: "); }
    else if (s == "4") { base.key = ask("key: "); }
    else if (s == "5") { base.behavior = ask("目标行为: "); }
    else if (s == "6") {
      std::string m = ask("attacker-model(回车=同目标模型): ");
      if (!m.empty()) base.aModel = m;
      std::string u = ask("attacker-base-url(回车=同目标;本地 ollama 填 http://127.0.0.1:11434/v1): ");
      if (!u.empty()) { base.aBaseUrl = u; base.aBackend = "openai"; }
      std::string k = ask("attacker-key(回车=同目标 key;本地随便填): ");
      if (!k.empty()) base.aKey = k;
    }
    else if (s == "7") { base.llmJudge = !base.llmJudge; std::cout << "judge-llm = " << (base.llmJudge ? "on" : "off") << std::endl; }
    else if (s == "8") { base.noVerify = !base.noVerify; std::cout << "no-verify = " << (base.noVerify ? "on" : "off") << std::endl; }
    else if (s == "9") {
      std::string e = ask("epochs(autodan 每行为轮数): ");
      if (!e.empty()) base.epochs = std::atoi(e.c_str());
      std::string it = ask("iterations(adaptive 搜索轮数): ");
      if (!it.empty()) base.iterations = std::atoi(it.c_str());
    }
    else std::cerr << "[!] 无效选择" << std::endl;
  }
}

/** 缺行为时引导输入 */
static void ensureBehavior(Cli& c) {
  if (c.behavior.empty() && c.behaviors.empty())
    c.behavior = ask("目标行为(如: print(open('/flag').read()) 的输出): ");
}

/** set 命令:把 "k v" 翻译成 "--k v" 复用 parseInto */
static bool shellSet(Cli& base, const std::vector<std::string>& tok) {
  if (tok.size() < 3) { std::cerr << "[!] 用法: set <项> <值>" << std::endl; return false; }
  const std::string& k = tok[1];
  if (k == "judge-llm" || k == "no-verify" || k == "verbose") {
    bool on = tok[2] == "on" || tok[2] == "true" || tok[2] == "1";
    if (k == "judge-llm") base.llmJudge = on;
    else if (k == "no-verify") base.noVerify = on;
    else base.verbose = on;
    return true;
  }
  std::string err;
  std::vector<std::string> args = {"--" + k, tok[2]};
  if (!parseInto(base, args, err)) { std::cerr << "[!] " << err << std::endl; return false; }
  return true;
}

static void printMenu(const Cli& base) {
  std::cout << "\n====== zemu-autodan ======\n"
            << "  模式: " << (base.backend.empty() ? "openai" : base.backend)
            << " | 模型: " << (base.model.empty() ? "默认" : base.model)
            << " | 行为: " << (base.behavior.empty() ? "(未设)" : base.behavior.substr(0, 40)) << "\n"
            << "  [1] template   语料批量攻击(109 条现成手法)\n"
            << "  [2] autodan    AutoDAN-Turbo 三智能体终身学习\n"
            << "  [3] adaptive   logprobs 随机搜索 / Claude prefill\n"
            << "  [4] chat       手动对话探测\n"
            << "  [5] 配置设置\n"
            << "  [6] 查看当前配置\n"
            << "  [0] 退出\n";
}

static int shell() {
  Cli base;
  ensureDefaults(base);
  std::cout << "zemu-autodan(选编号操作;也可直接输命令,help 查看)\n";
  if (!base.corpus.empty()) std::cout << "语料: " << base.corpus << "\n";
  std::string line;
  while (true) {
    printMenu(base);
    line = ask("选择> ");
    if (line.empty()) continue;
    // 数字 → 菜单动作
    if (line == "0" || line == "q" || line == "quit" || line == "exit") break;
    if (line == "1") { dispatch("template", base); continue; }
    if (line == "2") { Cli c = base; ensureBehavior(c); if (!c.behavior.empty() || !c.behaviors.empty()) dispatch("autodan", c); continue; }
    if (line == "3") { Cli c = base; ensureBehavior(c); if (!c.behavior.empty() || !c.behaviors.empty()) dispatch("adaptive", c); continue; }
    if (line == "4") { dispatch("chat", base); continue; }
    if (line == "5") { menuConfig(base); continue; }
    if (line == "6") { showCfg(base); continue; }
    // 非数字 → 按命令解析(set/show/template ... 均可用)
    auto tok = splitLine(line);
    const std::string& cmd = tok[0];
    if (cmd == "help" || cmd == "?") {
      std::cout << "命令: set <项> <值> / show / template / autodan / adaptive / chat / quit\n"
                   "提示: 目标只有网页接口时,配置里 backend 选 manual\n";
      continue;
    }
    if (cmd == "show") { showCfg(base); continue; }
    if (cmd == "set") {
      if (shellSet(base, tok)) std::cout << "ok" << std::endl;
      continue;
    }
    if (cmd == "template" || cmd == "adaptive" || cmd == "autodan" || cmd == "chat") {
      Cli c = base;
      std::string err;
      std::vector<std::string> rest(tok.begin() + 1, tok.end());
      if (!parseInto(c, rest, err)) { std::cerr << "[!] " << err << std::endl; continue; }
      dispatch(cmd, c);
      continue;
    }
    std::cerr << "[!] 无效选择: " << cmd << std::endl;
  }
  return 0;
}

// ============================================================ main

int main(int argc, char** argv) {
  if (argc < 2) return shell();  // 无参数 → 交互式
  std::string cmd = argv[1];
  if (cmd == "help" || cmd == "--help" || cmd == "-h") { usage(std::cout); return 0; }
  if (cmd == "shell") return shell();

  Cli c;
  std::string err;
  std::vector<std::string> args(argv + 2, argv + argc);
  if (!parseInto(c, args, err)) {
    std::cerr << "[!] " << err << std::endl;
    return 2;
  }
  return dispatch(cmd, c);
}
