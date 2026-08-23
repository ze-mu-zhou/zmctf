/** adaptive.h — adaptive 攻击(llm-adaptive-attacks 完整移植)。
 * OpenAI/vllm:refined_best 对抗模板 + suffix 随机搜索最大化目标 token logprob,
 *   支持多次重启、目标 token 缺失早停、模型专属初始 suffix、self-transfer
 *  (一个行为搜到的 suffix 作为后续行为的初始值——论文中高 ASR 的关键);
 * Anthropic:prefill 前缀填充,或用 --suffix 做迁移攻击(GPT 搜到的 suffix 直接打 Claude)。
 */
#pragma once

#include <string>

#include "../target.h"

namespace zemu::attack {

struct AdaptiveOptions {
  std::string behaviors;    // 行为文件(每行一个)或直接用 --behavior
  std::string behavior;     // 单个行为
  int iterations = 50;      // 每行为搜索轮数(每次重启)
  int topLogprobs = 5;      // 请求的 top logprobs 数
  int maxTokens = 512;
  bool llmJudge = false;    // 用 LLM 判定而非本地拒绝词
  int restarts = 1;         // 随机重启次数(上游 n_restarts)
  std::string suffix;       // 手工指定初始 suffix(Claude 迁移攻击用)
  std::string targetToken;  // 目标 token(空=按模型名自动:llama3/phi3→"<",否则 "Sure")
};

int runAdaptive(const target::Target& tgt, const AdaptiveOptions& opt);

}  // namespace zemu::attack
