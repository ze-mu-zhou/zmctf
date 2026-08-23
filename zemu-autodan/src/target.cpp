/** target.cpp — OpenAI/Anthropic/Gemini 适配器实现。
 * 请求体用 json_mini.h 构造(紧凑序列化),响应用 JsonParser 解析。
 */
#include "target.h"

#include <algorithm>
#include <iostream>
#include <sstream>

#include "http.h"
#include "json_mini.h"

namespace zemu::target {

namespace {

/** Json 字符串构造 */
Json jstr(const std::string& s) {
  Json j;
  j.type = Json::STR;
  j.str = s;
  return j;
}
Json jnum(const std::string& s) {
  Json j;
  j.type = Json::NUM;
  j.num = s;
  return j;
}

/** 从 JSON 对象中找字符串字段 */
bool getStr(const Json& j, const char* name, std::string& out) {
  if (j.type != Json::OBJ) return false;
  for (auto& [k, v] : j.obj)
    if (k == name && v.type == Json::STR) { out = v.str; return true; }
  return false;
}

/** 从 messages 数组里取 content(OpenAI 响应) */
bool extractOpenAiText(const Json& root, std::string& out) {
  for (auto& [k, v] : root.obj) {
    if (k == "choices" && v.type == Json::ARR && !v.arr.empty()) {
      const Json& c = v.arr[0];
      if (c.type != Json::OBJ) continue;
      for (auto& [k2, v2] : c.obj) {
        if (k2 == "message" && v2.type == Json::OBJ) {
          std::string t;
          if (getStr(v2, "content", t)) { out = t; return true; }
        }
        if (k2 == "text" && v2.type == Json::STR) { out = v2.str; return true; }
      }
    }
  }
  return false;
}

bool extractAnthropicText(const Json& root, std::string& out) {
  for (auto& [k, v] : root.obj) {
    if (k == "content" && v.type == Json::ARR) {
      for (auto& block : v.arr) {
        if (block.type == Json::OBJ) {
          std::string t;
          if (getStr(block, "text", t)) { out += t; }
        }
      }
      return !out.empty();
    }
  }
  return false;
}

bool extractGeminiText(const Json& root, std::string& out) {
  for (auto& [k, v] : root.obj) {
    if (k == "candidates" && v.type == Json::ARR && !v.arr.empty()) {
      const Json& c = v.arr[0];
      for (auto& [k2, v2] : c.obj) {
        if (k2 == "content" && v2.type == Json::OBJ) {
          for (auto& [k3, v3] : v2.obj) {
            if (k3 == "parts" && v3.type == Json::ARR && !v3.arr.empty() && v3.arr[0].type == Json::OBJ) {
              std::string t;
              if (getStr(v3.arr[0], "text", t)) { out = t; return true; }
            }
          }
        }
      }
    }
  }
  return false;
}

}  // namespace

Target::Target(TargetConfig cfg) : cfg_(std::move(cfg)) {
  switch (cfg_.backend) {
    case Backend::OPENAI: backendName_ = "openai"; break;
    case Backend::ANTHROPIC: backendName_ = "anthropic"; break;
    case Backend::GEMINI: backendName_ = "gemini"; break;
    case Backend::MANUAL: backendName_ = "manual"; break;
    default: backendName_ = "unknown"; break;
  }
  if (cfg_.model.empty()) cfg_.model = "gpt-4o";
}

GenResult Target::manualExchange(const std::vector<Msg>& msgs) {
  GenResult res;
  std::cout << "\n========== 把下面 prompt 发给目标(网页等),粘贴响应回来 ==========\n";
  for (auto& m : msgs)
    if (m.role != "system") std::cout << m.content << "\n";
  std::cout << "========== 在此粘贴目标响应,单独一行 <<< 结束 ==========" << std::endl;
  std::string line, text;
  while (std::getline(std::cin, line)) {
    if (line == "<<<") break;
    text += line;
    text += '\n';
  }
  if (!text.empty() && text.back() == '\n') text.pop_back();
  if (text.empty()) { res.error = "用户未提供响应(EOF/空)"; return res; }
  res.text = text;
  res.status = 200;
  res.ok = true;
  return res;
}

GenResult Target::complete(const std::vector<Msg>& msgs, const GenOptions& opt) const {
  if (cfg_.backend == Backend::MANUAL) return manualExchange(msgs);
  GenResult res;
  std::string body, err;
  std::string path = chatPath(msgs, opt, opt.topLogprobs > 0, body, err);
  if (path.empty()) { res.error = err; return res; }

  http::Request req;
  req.method = "POST";
  req.body = body;
  req.timeoutMs = cfg_.timeoutMs;
  req.headers["Content-Type"] = "application/json";

  switch (cfg_.backend) {
    case Backend::OPENAI:
      req.url = cfg_.baseUrl + path;
      if (!cfg_.apiKey.empty()) req.headers["Authorization"] = "Bearer " + cfg_.apiKey;
      break;
    case Backend::ANTHROPIC:
      req.url = cfg_.baseUrl + path;
      req.headers["x-api-key"] = cfg_.apiKey;
      req.headers["anthropic-version"] = "2023-06-01";
      break;
    case Backend::GEMINI:
      req.url = cfg_.baseUrl + path;
      // key 走 header,避免出现在 URL/日志里
      if (!cfg_.apiKey.empty()) req.headers["x-goog-api-key"] = cfg_.apiKey;
      break;
    default:
      res.error = "未知后端";
      return res;
  }

  auto resp = http::send(req);
  res.status = resp.status;
  if (!resp.error.empty()) {
    res.error = "网络错误: " + resp.error;
    return res;
  }
  if (resp.status != 200) {
    res.error = "HTTP " + std::to_string(resp.status) + ": " + resp.body.substr(0, 300);
    return res;
  }

  Json root;
  JsonParser parser(resp.body);
  if (!parser.parse(root)) {
    res.error = "响应 JSON 解析失败: " + resp.body.substr(0, 200);
    return res;
  }

  bool got = false;
  switch (cfg_.backend) {
    case Backend::OPENAI: got = extractOpenAiText(root, res.text); break;
    case Backend::ANTHROPIC: got = extractAnthropicText(root, res.text); break;
    case Backend::GEMINI: got = extractGeminiText(root, res.text); break;
    default: break;
  }
  // logprobs 提取(OpenAI chat.completions:choices[0].logprobs.content[].top_logprobs)
  if (opt.topLogprobs > 0 && cfg_.backend == Backend::OPENAI) {
    for (auto& [k, v] : root.obj) {
      if (k == "choices" && v.type == Json::ARR && !v.arr.empty() && v.arr[0].type == Json::OBJ) {
        for (auto& [k2, v2] : v.arr[0].obj) {
          if (k2 == "logprobs" && v2.type == Json::OBJ) {
            for (auto& [k3, v3] : v2.obj) {
              if (k3 == "content" && v3.type == Json::ARR) {
                for (auto& tok : v3.arr) {
                  if (tok.type != Json::OBJ) continue;
                  for (auto& [k4, v4] : tok.obj) {
                    if (k4 == "top_logprobs" && v4.type == Json::ARR) {
                      for (auto& cand : v4.arr) {
                        if (cand.type != Json::OBJ) continue;
                        std::string t;
                        double lp = 0;
                        for (auto& [k5, v5] : cand.obj) {
                          if (k5 == "token" && v5.type == Json::STR) t = v5.str;
                          if (k5 == "logprob" && v5.type == Json::NUM) lp = std::atof(v5.num.c_str());
                        }
                        if (!t.empty()) res.logprobs.emplace_back(t, lp);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  if (!got && res.text.empty()) {
    res.error = "响应无文本内容";
    return res;
  }
  res.ok = true;
  return res;
}

GenResult Target::ask(const std::string& user, const GenOptions& opt) const {
  return complete({{"user", user}}, opt);
}

std::string Target::chatPath(const std::vector<Msg>& msgs, const GenOptions& opt,
                             bool withLogprobs, std::string& jsonBody, std::string& err) const {
  std::string model = opt.model.empty() ? cfg_.model : opt.model;
  switch (cfg_.backend) {
    case Backend::OPENAI: {
      Json root;
      root.type = Json::OBJ;
      root.obj.push_back({"model", jstr(model)});
      Json ms;
      ms.type = Json::ARR;
      for (auto& m : msgs) {
        Json mm;
        mm.type = Json::OBJ;
        mm.obj.push_back({"role", jstr(m.role)});
        mm.obj.push_back({"content", jstr(m.content)});
        ms.arr.push_back(mm);
      }
      root.obj.push_back({"messages", ms});
      root.obj.push_back({"temperature", jnum(std::to_string(opt.temperature))});
      root.obj.push_back({"max_tokens", jnum(std::to_string(opt.maxTokens))});
      if (withLogprobs) {
        Json lp;
        lp.type = Json::BOOL;
        lp.b = true;
        root.obj.push_back({"logprobs", lp});
        root.obj.push_back({"top_logprobs", jnum(std::to_string(opt.topLogprobs))});
      }
      if (!opt.stop.empty()) root.obj.push_back({"stop", jstr(opt.stop)});
      jsonCanonical(root, jsonBody);
      return "/chat/completions";
    }
    case Backend::ANTHROPIC: {
      Json root;
      root.type = Json::OBJ;
      root.obj.push_back({"model", jstr(model)});
      root.obj.push_back({"max_tokens", jnum(std::to_string(opt.maxTokens))});
      root.obj.push_back({"temperature", jnum(std::to_string(opt.temperature))});
      // 最后一条 user 消息拆为 system + messages
      std::vector<Msg> ms = msgs;
      std::string sys;
      if (!ms.empty() && ms[0].role == "system") {
        sys = ms[0].content;
        ms.erase(ms.begin());
      }
      if (!sys.empty()) root.obj.push_back({"system", jstr(sys)});
      Json msj;
      msj.type = Json::ARR;
      for (auto& m : ms) {
        Json mm;
        mm.type = Json::OBJ;
        std::string role = m.role == "assistant" ? "assistant" : "user";
        mm.obj.push_back({"role", jstr(role)});
        mm.obj.push_back({"content", jstr(m.content)});
        msj.arr.push_back(mm);
      }
      // prefill:Anthropic 无顶层 prefill 字段,正确做法是末尾追加 assistant 消息
      if (!opt.prefill.empty()) {
        Json pre;
        pre.type = Json::OBJ;
        pre.obj.push_back({"role", jstr("assistant")});
        pre.obj.push_back({"content", jstr(opt.prefill)});
        msj.arr.push_back(pre);
      }
      root.obj.push_back({"messages", msj});
      jsonCanonical(root, jsonBody);
      return "/v1/messages";
    }
    case Backend::GEMINI: {
      Json root;
      root.type = Json::OBJ;
      Json contents;
      contents.type = Json::ARR;
      // 合并 role 序列:system → user
      for (auto& m : msgs) {
        if (m.role == "system") continue;
        Json c;
        c.type = Json::OBJ;
        c.obj.push_back({"role", jstr(m.role == "assistant" ? "model" : "user")});
        Json parts;
        parts.type = Json::ARR;
        Json part;
        part.type = Json::OBJ;
        part.obj.push_back({"text", jstr(m.content)});
        parts.arr.push_back(part);
        c.obj.push_back({"parts", parts});
        contents.arr.push_back(c);
      }
      root.obj.push_back({"contents", contents});
      Json gen;
      gen.type = Json::OBJ;
      gen.obj.push_back({"temperature", jnum(std::to_string(opt.temperature))});
      gen.obj.push_back({"maxOutputTokens", jnum(std::to_string(opt.maxTokens))});
      root.obj.push_back({"generationConfig", gen});
      jsonCanonical(root, jsonBody);
      return "/v1beta/models/" + model + ":generateContent";
    }
    default:
      err = "未知后端";
      return {};
  }
}

}  // namespace zemu::target
