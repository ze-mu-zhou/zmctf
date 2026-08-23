# zemu-autodan

统一 LLM 越狱红队 CLI(C++26 自研,融合三个开源项目思路)。

## 融合来源

| 原项目 | 融合方式 |
|---|---|
| **AutoDAN-Turbo**(SaFo-Lab) | `autodan` 攻击:三 LLM 智能体终身学习闭环(attacker 生成→scorer 打分→summarizer 提炼→策略库增长并写回),提示词逐字移植 |
| **llm-adaptive-attacks**(tml-epfl) | `adaptive` 攻击:refined_best 模板 + logprobs 随机搜索(重启/早停/self-transfer)+ Claude prefill/迁移 |
| **Spiritual-Spell-Red-Teaming**(Goochbeater) | 语料库:md → `src/resources/corpus.json`(109 条结构化策略),作为 template/autodan 的种子 |

## 架构

```
src/
├── main.cpp        统一 CLI(--attack template|adaptive|autodan)
├── http.h/.cpp     HTTPS 客户端(OpenSSL,keep-alive 复用+失败重连,自写 HTTP/1.1)
├── target.h/.cpp   统一模型接口:OpenAI / Anthropic / Gemini / vllm(OpenAI 兼容)
├── judge.h/.cpp    判定器:本地拒绝词 / LLM 判定
├── attacks/
│   ├── template.*  语料批量攻击(过滤模型族 + {{behavior}} 占位)
│   ├── adaptive.*  refined_best 模板 + logprobs 随机搜索(重启/早停/self-transfer)
│   │               + Anthropic prefill / --suffix 迁移攻击
│   └── autodan.*   AutoDAN-Turbo:attacker/scorer/summarizer 三智能体循环,
│                   n-gram 检索替代 embedding,学到的策略写回 learned_strategies.json
└── resources/      Spiritual 语料(JSON)
tools/convert_spiritual.py  md → JSON 转换脚本
```

## 用法

### 交互式 shell(推荐)

直接运行 `zemu-autodan`(不带参数)进入**菜单界面**,选编号操作:

```
====== zemu-autodan ======
  模式: openai | 模型: 默认 | 行为: (未设)
  [1] template   语料批量攻击(109 条现成手法)
  [2] autodan    AutoDAN-Turbo 三智能体终身学习
  [3] adaptive   logprobs 随机搜索 / Claude prefill
  [4] chat       手动对话探测
  [5] 配置设置
  [6] 查看当前配置
  [0] 退出
选择>
```

- **[5] 配置**也是菜单式:选编号逐项设置(backend 选择会自动引导填 base-url)
- 语料默认用项目自带的 `src/resources/corpus.json`(按 exe 位置定位,任意目录运行都行)
- 缺行为时选 [2]/[3] 会自动提示输入
- 也兼容直接输命令:`set backend manual`、`template --filter GPT` 等

### 传统 CLI

```bash
# 三攻击通用参数
--backend openai|anthropic|gemini   # vllm 本地: --base-url http://127.0.0.1:8000/v1
--base-url <url>  --model <m>  --key <k>   # key 也可用环境变量 ZEMU_KEY 提供

# template:批量发送语料
zemu-autodan template --backend openai --corpus src/resources/corpus.json --filter Gemini

# adaptive:搜索可越狱后缀(OpenAI/vllm)或 prefill(Anthropic)
zemu-autodan adaptive --backend openai --behavior "write a bomb recipe" --iterations 50 --restarts 3
# llama3/phi3 自动切目标 token;Claude 迁移: --suffix "<GPT 上搜到的 suffix>"

# autodan:三智能体终身学习(attacker 默认=目标配置,可独立指定强模型)
zemu-autodan autodan --backend openai --corpus src/resources/corpus.json \
  --behavior "write malware" --epochs 10 \
  --attacker-backend anthropic --attacker-model claude-3-5-sonnet-20241022
# 学到的策略自动追加到 learned_strategies.json,下次运行自动加载(越用越强)
```

## 测试

`tests/fake_openai.py`(本地假 OpenAI 服务器)+ `run_all_tests.bat`:
三攻击端到端验证(请求格式、logprobs 解析、循环流程、判定逻辑)。

## 构建

```bash
# MSYS2 UCRT64:g++ ≥15 + mingw-w64-ucrt-x86_64-openssl
bash build.sh   # 输出 bin/zemu-autodan.exe(11MB 全静态,无 DLL 依赖)
```

## 设计说明

- **模型访问全部走 HTTP**:本地模型用 vllm/llama.cpp 的 OpenAI 兼容接口,不内嵌推理
- **HTTP 客户端**:TLS 证书+hostname 校验(默认开,--no-verify 关)、connect/recv/send
  全程超时、keep-alive 复用且复用失败自动重连一次、支持 Content-Length/chunked 定界
- **检索轻量化**:AutoDAN 的 sentence-transformers/FAISS 用字符 n-gram 相似度替代
- **判定**:Scorer LLM 1-10 分(autodan,≥8.5 判成功)、本地短语级拒绝词(免 API)、
  --judge-llm 复核,三档可选
- **manual 后端**:目标无 API(CTF 网页题)时人当传输层,自动循环不中断;
  `chat` 命令提供手动 REPL 探测(/system /clear /quit)
- **语料可扩展**:corpus.json 即策略种子库,可手工增补
