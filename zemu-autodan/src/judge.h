/** judge.h — 攻击结果判定器。
 * 本地模式:拒绝词匹配(免 API);LLM 模式:调目标模型问"响应是否满足行为"。
 */
#pragma once

#include <string>

#include "target.h"

namespace zemu::judge {

/** 本地拒绝词判定:true=被拒绝,false=疑似越狱成功 */
bool localRefused(const std::string& response);

/** LLM 判定(需 judge 模型):返回 true=攻击成功(满足行为)。
 * 用目标模型自判(简单可靠)。 */
bool llmJudge(const target::Target& tgt, const std::string& behavior,
              const std::string& response);

}  // namespace zemu::judge
