/** http.h — 极简 HTTPS 客户端(OpenSSL 3.x,复用 json_mini.h / b64.h)。
 * 支持 GET/POST/JSON body、自定义头、超时;响应返回状态码 + body 字符串。
 * 仅做 OpenAI/Anthropic/Gemini/vllm 这类 JSON API 所需的最小集合。
 */
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace zemu::http {

struct Response {
  int status = 0;
  std::map<std::string, std::string> headers;  // 键小写
  std::string body;
  std::string error;  // 网络/握手错误时非空
};

struct Request {
  std::string method = "POST";
  std::string url;                    // https://host:port/path
  std::map<std::string, std::string> headers;  // 自定义头
  std::string body;                   // 原始 body(JSON 自行序列化)
  int timeoutMs = 60000;
  bool verifyTls = true;              // 本地 http:// 时自动 false
};

/** 发送请求并等待完整响应。失败时 resp.error 非空。 */
Response send(const Request& req);

/** 便捷:URL 解析后的连接参数 */
struct Url {
  std::string scheme, host, path;
  int port = 0;
  bool parse(const std::string& url);
};

}  // namespace zemu::http
