/** http.cpp — HTTPS 客户端实现(OpenSSL 3.x + 自写 HTTP/1.1)。
 * - TLS 校验:verifyTls=true 时启用 SSL_VERIFY_PEER + hostname 校验(SSL_set1_host)。
 * - 超时:connect / send / recv 全程受 req.timeoutMs 约束(非阻塞 connect + select,
 *   SO_RCVTIMEO/SO_SNDTIMEO)。
 * - 连接复用:同 host:port 的 keep-alive 空闲连接复用;复用连接若已被服务端关闭,
 *   自动新建连接重试一次。
 * - 响应定界:支持 Content-Length 与 Transfer-Encoding: chunked;keep-alive 连接
 *   仅在响应自界定且完整读满时归还,否则关闭。
 */
#include "http.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#define INVALID_SOCKET (-1)
#define closesocket close
typedef int SOCKET;
#endif

namespace zemu::http {

namespace {

constexpr std::size_t MAX_RESPONSE = 32u << 20;  // 响应总大小上限 32MB,防恶意/异常服务端打爆内存

struct CtxDeleter {
  void operator()(SSL_CTX* c) const { if (c) SSL_CTX_free(c); }
};
using CtxPtr = std::unique_ptr<SSL_CTX, CtxDeleter>;

/** 全局 SSL 上下文(进程内懒初始化) */
SSL_CTX* sslCtx() {
  static CtxPtr ctx = [] {
    SSL_library_init();
    SSL_load_error_strings();
    auto* c = SSL_CTX_new(TLS_client_method());
    if (c) SSL_CTX_set_default_verify_paths(c);  // 只加载 CA 目录,校验开关在 per-SSL 上设置
    return CtxPtr(c);
  }();
  return ctx.get();
}

/** Winsock 初始化(首次连接时;Windows 下必须) */
void ensureWsa() {
#ifdef _WIN32
  static bool done = [] {
    WSADATA wsa{};
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  }();
  (void)done;
#endif
}

std::string lower(std::string s) {
  for (auto& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

void closeConn(SOCKET fd, SSL* ssl) {
  if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
  if (fd != INVALID_SOCKET) closesocket(fd);
}

/** 连接缓存:host:port → 已建立的 fd(keep-alive 复用) */
struct ConnCache {
  struct Entry {
    SOCKET fd = INVALID_SOCKET;
    SSL* ssl = nullptr;
  };
  std::mutex m;
  std::map<std::string, Entry> pool;

  Entry take(const std::string& key) {
    std::lock_guard<std::mutex> lk(m);
    auto it = pool.find(key);
    if (it == pool.end()) return {};
    Entry e = it->second;
    pool.erase(it);
    return e;
  }
  void put(const std::string& key, Entry e) {
    std::lock_guard<std::mutex> lk(m);
    if (pool.size() >= 8) {  // 上限,超出直接关闭,不能泄漏 fd/SSL
      closeConn(e.fd, e.ssl);
      return;
    }
    pool[key] = e;
  }
};
ConnCache& conns() {
  static ConnCache c;
  return c;
}

void setBlocking(SOCKET fd, bool blocking) {
#ifdef _WIN32
  u_long nb = blocking ? 0 : 1;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return;
  fcntl(fd, F_SETFL, blocking ? (fl & ~O_NONBLOCK) : (fl | O_NONBLOCK));
#endif
}

void setSockTimeouts(SOCKET fd, int ms) {
#ifdef _WIN32
  DWORD tv = (DWORD)ms;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
#else
  struct timeval tv { ms / 1000, (ms % 1000) * 1000 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
}

/** TCP 连接,带超时(非阻塞 connect + select) */
SOCKET connectTcp(const std::string& host, int port, int timeoutMs, std::string& err) {
  ensureWsa();
  struct addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = nullptr;
  std::string sport = std::to_string(port);
  int rc = getaddrinfo(host.c_str(), sport.c_str(), &hints, &res);
  if (rc != 0 || !res) {
    err = "getaddrinfo: " + std::string(gai_strerror(rc));
    return INVALID_SOCKET;
  }
  SOCKET fd = INVALID_SOCKET;
  for (auto* p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd == INVALID_SOCKET) continue;
    setBlocking(fd, false);
    rc = connect(fd, p->ai_addr, (int)p->ai_addrlen);
    if (rc != 0) {
#ifdef _WIN32
      if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(fd); fd = INVALID_SOCKET; continue; }
#else
      if (errno != EINPROGRESS) { closesocket(fd); fd = INVALID_SOCKET; continue; }
#endif
      fd_set wfds;
      FD_ZERO(&wfds);
      FD_SET(fd, &wfds);
      struct timeval tv { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
      if (select((int)fd + 1, nullptr, &wfds, nullptr, &tv) <= 0) {
        closesocket(fd); fd = INVALID_SOCKET; continue;  // 超时或 select 错误
      }
      int soerr = 0;
      socklen_t sl = sizeof soerr;
      getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&soerr, &sl);
      if (soerr != 0) { closesocket(fd); fd = INVALID_SOCKET; continue; }
    }
    setBlocking(fd, true);
    setSockTimeouts(fd, timeoutMs);
    break;
  }
  freeaddrinfo(res);
  if (fd == INVALID_SOCKET) err = "connect 失败或超时";
  return fd;
}

/** 写满为止(SSL_write 默认模式已是全写语义;裸 send 可能部分写) */
bool sendAll(SOCKET fd, SSL* ssl, const std::string& out) {
  std::size_t sent = 0;
  while (sent < out.size()) {
    int n = ssl ? SSL_write(ssl, out.data() + sent, (int)(out.size() - sent))
                : ::send(fd, out.data() + sent, (int)(out.size() - sent), 0);
    if (n <= 0) return false;
    sent += (std::size_t)n;
  }
  return true;
}

struct HeadInfo {
  bool hasCL = false;
  bool chunked = false;
  std::size_t clen = 0;
};

/** 解析响应头(不含结尾空行),提取 Content-Length / Transfer-Encoding */
HeadInfo parseHead(std::string head) {
  for (auto& c : head) c = (char)std::tolower((unsigned char)c);
  HeadInfo hi;
  std::istringstream is(head);
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.rfind("content-length:", 0) == 0) {
      hi.hasCL = true;
      hi.clen = (std::size_t)std::strtoull(line.c_str() + 15, nullptr, 10);
    } else if (line.rfind("transfer-encoding:", 0) == 0 &&
               line.find("chunked", 18) != std::string::npos) {
      hi.chunked = true;
    }
  }
  return hi;
}

/** 尝试解码 chunked body(从 bodyStart 起)。
 * 返回 1=完整(body 写入 out),0=数据不全需继续读,-1=格式错误。 */
int tryDecodeChunked(const std::string& raw, std::size_t bodyStart, std::string& out) {
  std::size_t p = bodyStart;
  out.clear();
  for (;;) {
    auto eol = raw.find("\r\n", p);
    if (eol == std::string::npos) return 0;
    std::size_t sz = 0;
    bool any = false;
    for (std::size_t i = p; i < eol; i++) {
      char c = raw[i];
      if (c == ';') break;  // chunk 扩展,忽略
      int d;
      if (c >= '0' && c <= '9') d = c - '0';
      else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
      else if (c == ' ' || c == '\t') continue;
      else return -1;
      sz = sz * 16 + (std::size_t)d;
      any = true;
      if (sz > MAX_RESPONSE) return -1;
    }
    if (!any) return -1;
    std::size_t dataStart = eol + 2;
    if (sz == 0) {
      // 末块 "0\r\n" + 可选 trailer + 空行;两种形态都含 "\r\n\r\n"(从块长行起查)
      return raw.find("\r\n\r\n", eol) != std::string::npos ? 1 : 0;
    }
    if (raw.size() < dataStart + sz + 2) return 0;
    if (raw.compare(dataStart + sz, 2, "\r\n") != 0) return -1;
    out.append(raw, dataStart, sz);
    p = dataStart + sz + 2;
  }
}

/** 解析响应头为 Response(body 已由读循环定界好) */
Response parseResponse(const std::string& head, std::string body) {
  Response r;
  r.body = std::move(body);
  std::istringstream is(head);
  std::string proto;
  is >> proto >> r.status;
  std::string line;
  std::getline(is, line);  // 吃掉状态行剩余
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string k = lower(line.substr(0, colon));
    std::string v = line.substr(colon + 1);
    while (!v.empty() && v.front() == ' ') v.erase(v.begin());
    r.headers[k] = v;
  }
  return r;
}

/** 单次尝试:取/建连接 → 发请求 → 读完整响应。reused 输出是否用了缓存连接。 */
Response sendOnce(const Request& req, const Url& u, bool& reused) {
  Response resp;
  bool https = u.scheme == "https";
  std::string key = u.host + ":" + std::to_string(u.port);
  auto conn = conns().take(key);
  reused = conn.fd != INVALID_SOCKET;

  if (!reused) {
    std::string err;
    SOCKET fd = connectTcp(u.host, u.port, req.timeoutMs < 30000 ? req.timeoutMs : 30000, err);
    if (fd == INVALID_SOCKET) {
      resp.error = err;
      return resp;
    }
    conn.fd = fd;
    if (https) {
      conn.ssl = SSL_new(sslCtx());
      if (!conn.ssl) {
        resp.error = "SSL_new 失败";
        closesocket(conn.fd);
        return resp;
      }
      SSL_set_fd(conn.ssl, conn.fd);
      SSL_set_tlsext_host_name(conn.ssl, u.host.c_str());
      // 默认 SSL_VERIFY_NONE!必须显式开 PEER 校验,否则 verifyTls=true 形同虚设
      SSL_set_verify(conn.ssl, req.verifyTls ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
      if (req.verifyTls) SSL_set1_host(conn.ssl, u.host.c_str());  // hostname 校验
      if (SSL_connect(conn.ssl) != 1) {
        unsigned long e = ERR_get_error();
        char ebuf[256];
        resp.error = "TLS 握手失败: ";
        resp.error += e ? ERR_error_string(e, ebuf) : "对端关闭连接";
        closeConn(conn.fd, conn.ssl);
        return resp;
      }
    }
  }

  // 组装请求
  std::ostringstream oss;
  oss << req.method << " " << u.path << " HTTP/1.1\r\n";
  oss << "Host: " << u.host;
  if ((https && u.port != 443) || (!https && u.port != 80)) oss << ":" << u.port;
  oss << "\r\n";
  oss << "User-Agent: zemu-autodan/0.1\r\n";
  oss << "Accept: application/json\r\n";
  oss << "Connection: keep-alive\r\n";
  if (!req.body.empty()) oss << "Content-Length: " << req.body.size() << "\r\n";
  for (auto& [k, v] : req.headers) oss << k << ": " << v << "\r\n";
  oss << "\r\n";
  oss << req.body;

  if (!sendAll(conn.fd, conn.ssl, oss.str())) {
    resp.error = "发送失败(超时或对端关闭)";
    closeConn(conn.fd, conn.ssl);
    return resp;
  }

  // 读响应:先读头,再按 Content-Length / chunked 定界;两者都无则读到 EOF
  std::string raw;
  char buf[16384];
  std::size_t hdrEnd = std::string::npos;
  HeadInfo hi;
  std::string body;
  bool complete = false, readErr = false;
  for (;;) {
    int n = https ? SSL_read(conn.ssl, buf, (int)sizeof buf)
                  : recv(conn.fd, buf, (int)sizeof buf, 0);
    if (n > 0) {
      raw.append(buf, (std::size_t)n);
      if (raw.size() > MAX_RESPONSE) {
        resp.error = "响应超过 32MB 上限";
        closeConn(conn.fd, conn.ssl);
        return resp;
      }
      if (hdrEnd == std::string::npos) {
        hdrEnd = raw.find("\r\n\r\n");
        if (hdrEnd != std::string::npos) hi = parseHead(raw.substr(0, hdrEnd));
      }
      if (hdrEnd != std::string::npos) {
        if (hi.chunked) {
          int rc = tryDecodeChunked(raw, hdrEnd + 4, body);
          if (rc < 0) {
            resp.error = "chunked 响应格式错误";
            closeConn(conn.fd, conn.ssl);
            return resp;
          }
          if (rc > 0) { complete = true; break; }
        } else if (hi.hasCL && raw.size() >= hdrEnd + 4 + hi.clen) {
          body = raw.substr(hdrEnd + 4, hi.clen);
          complete = true;
          break;
        }
      }
    } else if (n == 0) {
      break;  // EOF(对端关闭)
    } else {
      readErr = true;  // 超时或连接错误(SO_RCVTIMEO 已设,recv 不会无限阻塞)
      break;
    }
  }

  if (readErr) {
    resp.error = "读取响应失败(超时或对端中断)";
    closeConn(conn.fd, conn.ssl);
    return resp;
  }
  if (hdrEnd == std::string::npos) {
    resp.error = "响应无完整头";
    closeConn(conn.fd, conn.ssl);
    return resp;
  }
  if (!complete) {
    if (hi.chunked) {
      resp.error = "chunked 响应不完整";
      closeConn(conn.fd, conn.ssl);
      return resp;
    }
    if (hi.hasCL) {
      resp.error = "响应 body 不完整(Content-Length 未读满)";
      closeConn(conn.fd, conn.ssl);
      return resp;
    }
    body = raw.substr(hdrEnd + 4);  // 无 CL 非 chunked:EOF 定界
  }

  auto parsed = parseResponse(raw.substr(0, hdrEnd), std::move(body));
  // keep-alive:仅当响应自界定且完整(CL/chunked),且服务端未要求关闭
  bool keepAlive = complete;
  auto ce = parsed.headers.find("connection");
  if (ce != parsed.headers.end() && lower(ce->second) == "close") keepAlive = false;
  if (keepAlive) conns().put(key, conn);
  else closeConn(conn.fd, conn.ssl);
  return parsed;
}

}  // namespace

bool Url::parse(const std::string& url) {
  auto schemeEnd = url.find("://");
  if (schemeEnd == std::string::npos) return false;
  scheme = url.substr(0, schemeEnd);
  std::size_t p = schemeEnd + 3;
  auto pathStart = url.find('/', p);
  std::string hostPort = (pathStart == std::string::npos) ? url.substr(p) : url.substr(p, pathStart - p);
  path = (pathStart == std::string::npos) ? "/" : url.substr(pathStart);
  port = (scheme == "https") ? 443 : 80;
  auto colon = hostPort.rfind(':');
  if (colon != std::string::npos && hostPort.find(']') == std::string::npos) {
    host = hostPort.substr(0, colon);
    port = std::atoi(hostPort.substr(colon + 1).c_str());
  } else {
    host = hostPort;
  }
  if (host.empty()) return false;
  return true;
}

Response send(const Request& req) {
  Url u;
  if (!u.parse(req.url)) {
    Response resp;
    resp.error = "URL 解析失败: " + req.url;
    return resp;
  }
  for (int attempt = 0; attempt < 2; attempt++) {
    bool reused = false;
    Response r = sendOnce(req, u, reused);
    // 复用的空闲连接可能已被服务端关闭:网络层失败时新建连接重试一次
    if (attempt == 0 && reused && r.status == 0 && !r.error.empty()) continue;
    return r;
  }
  Response resp;  // 不可达
  resp.error = "内部错误";
  return resp;
}

}  // namespace zemu::http
