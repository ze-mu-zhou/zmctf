/** target.h — 统一 LLM 目标接口。
 * 四类后端:OpenAI 兼容(openai/gpt 系列 + vllm/llama.cpp 本地服务)、
 * Anthropic、Gemini。统一抽象:对话补全(可带 system/温度/logprobs/prefill)。
 */
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace zemu::target {

enum class Backend { OPENAI, ANTHROPIC, GEMINI, MANUAL, UNKNOWN };

struct Msg {
  std::string role;   // system / user / assistant
  std::string content;
};

struct GenOptions {
  double temperature = 0.0;
  int maxTokens = 1024;
  int topLogprobs = 0;           // >0 请求 logprobs(OpenAI/vllm)
  std::string stop;              // 停止串(可选)
  std::string prefill;           // Anthropic 前缀填充
  std::string model;             // 覆盖默认模型
};

struct GenResult {
  bool ok = false;
  std::string text;              // 补全文本
  std::vector<std::pair<std::string, double>> logprobs;  // topLogprobs>0 时的候选
  std::string error;
  int status = 0;
};

struct TargetConfig {
  Backend backend = Backend::OPENAI;
  std::string baseUrl = "https://api.openai.com/v1";  // vllm: http://127.0.0.1:8000/v1
  std::string apiKey;
  std::string model = "gpt-4o";
  int timeoutMs = 120000;
  bool verifyTls = true;
};

class Target {
 public:
  explicit Target(TargetConfig cfg);

  /** 单轮补全(messages 最后一条追加并请求回复) */
  GenResult complete(const std::vector<Msg>& msgs, const GenOptions& opt = {}) const;

  /** 便捷:单 user 消息 */
  GenResult ask(const std::string& user, const GenOptions& opt = {}) const;

  /** 手动模式:打印 prompt,等用户粘贴响应(单独一行 <<< 结束) */
  static GenResult manualExchange(const std::vector<Msg>& msgs);

  const std::string& model() const { return cfg_.model; }
  const std::string& backendName() const { return backendName_; }

 private:
  TargetConfig cfg_;
  std::string backendName_;
  std::string chatPath(const std::vector<Msg>& msgs, const GenOptions& opt,
                       bool withLogprobs, std::string& jsonBody, std::string& err) const;
};

}  // namespace zemu::target
