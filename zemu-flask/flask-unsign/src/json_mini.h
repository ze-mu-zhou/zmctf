/**
 * json_mini.h:最小 JSON 解析 + TaggedJSON 规范化输出
 * (sort_keys + 紧凑分隔符 + ensure_ascii 转义,与 Flask TaggedJSONSerializer 对齐;
 * sign 命令用)。数字保留原文本(极端浮点格式可能与 Python repr 有出入)。
 */
#pragma once

#include <algorithm>
#include <cstring>
#include <format>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

struct Json {
  enum Type { NIL, BOOL, NUM, STR, ARR, OBJ } type = NIL;
  bool b = false;
  std::string num;                 // 原样保留数字文本
  std::string str;                 // UTF-8
  std::vector<Json> arr;
  std::vector<std::pair<std::string, Json>> obj;
};

struct JsonParser {
  const char* p;
  int depth = 0;
  explicit JsonParser(const std::string& s) : p(s.c_str()) {}

  // 嵌套深度上限,防极端输入递归爆栈
  struct DepthGuard {
    int& d; bool ok;
    explicit DepthGuard(int& d) : d(d), ok(++d <= 200) {}
    ~DepthGuard() { d--; }
  };

  void ws() { while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++; }

  bool expect(char c) { ws(); return *p == c ? (p++, true) : false; }

  bool literal(const char* w) {
    size_t n = strlen(w);
    if (strncmp(p, w, n) == 0) { p += n; return true; }
    return false;
  }

  static int hex4(const char* s, uint32_t& out) {
    out = 0;
    for (int i = 0; i < 4; i++) {
      char c = s[i];
      out <<= 4;
      if (c >= '0' && c <= '9') out |= (uint32_t)(c - '0');
      else if (c >= 'a' && c <= 'f') out |= (uint32_t)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') out |= (uint32_t)(c - 'A' + 10);
      else return -1;
    }
    return 0;
  }

  static void utf8Enc(uint32_t cp, std::string& out) {
    if (cp < 0x80) out += (char)cp;
    else if (cp < 0x800) { out += (char)(0xC0 | cp >> 6); out += (char)(0x80 | (cp & 63)); }
    else if (cp < 0x10000) {
      out += (char)(0xE0 | cp >> 12); out += (char)(0x80 | (cp >> 6 & 63)); out += (char)(0x80 | (cp & 63));
    } else {
      out += (char)(0xF0 | cp >> 18); out += (char)(0x80 | (cp >> 12 & 63));
      out += (char)(0x80 | (cp >> 6 & 63)); out += (char)(0x80 | (cp & 63));
    }
  }

  bool parseStr(std::string& out) {
    ws();
    if (*p != '"') return false;
    p++;
    while (*p && *p != '"') {
      if (*p == '\\') {
        p++;
        switch (*p) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            // 截断检查:c_str() 仅保证 1 个 NUL,p[1..4] 任一为空即拒绝,防 hex4 越界读
            if (!p[1] || !p[2] || !p[3] || !p[4]) return false;
            uint32_t cp;
            if (hex4(p + 1, cp) < 0) return false;
            p += 4;
            // 代理对:\uD83D\uDE00(同样先查 p[3..6] 非空再 hex4)
            if (cp >= 0xD800 && cp <= 0xDBFF && p[1] == '\\' && p[2] == 'u' &&
                p[3] && p[4] && p[5] && p[6]) {
              uint32_t lo;
              if (hex4(p + 3, lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                p += 6;
              }
            }
            utf8Enc(cp, out);
            break;
          }
          default: return false;
        }
        p++;
      } else {
        if ((uint8_t)*p < 0x20) return false;
        out += *p++;
      }
    }
    return *p == '"' ? (p++, true) : false;
  }

  bool parse(Json& j) {
    DepthGuard dg(depth);
    if (!dg.ok) return false;
    ws();
    if (*p == '{') {
      p++;
      j.type = Json::OBJ;
      ws();
      if (*p == '}') { p++; return true; }
      while (true) {
        std::string k;
        if (!parseStr(k) || !expect(':')) return false;
        Json v;
        if (!parse(v)) return false;
        // Python json.loads:重复 key 后者覆盖前者
        bool dup = false;
        for (auto& kv : j.obj) {
          if (kv.first == k) { kv.second = std::move(v); dup = true; break; }
        }
        if (!dup) j.obj.emplace_back(k, std::move(v));
        if (expect(',')) continue;
        return expect('}');
      }
    }
    if (*p == '[') {
      p++;
      j.type = Json::ARR;
      ws();
      if (*p == ']') { p++; return true; }
      while (true) {
        Json v;
        if (!parse(v)) return false;
        j.arr.push_back(std::move(v));
        if (expect(',')) continue;
        return expect(']');
      }
    }
    if (*p == '"') {
      j.type = Json::STR;
      return parseStr(j.str);
    }
    if (literal("true")) { j.type = Json::BOOL; j.b = true; return true; }
    if (literal("false")) { j.type = Json::BOOL; j.b = false; return true; }
    if (literal("null")) { j.type = Json::NIL; return true; }
    // 数字:原样保留文本
    const char* start = p;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else if (*p >= '1' && *p <= '9') while (*p >= '0' && *p <= '9') p++;
    else return false;
    if (*p == '.') { p++; if (!(*p >= '0' && *p <= '9')) return false; while (*p >= '0' && *p <= '9') p++; }
    if (*p == 'e' || *p == 'E') {
      p++;
      if (*p == '+' || *p == '-') p++;
      if (!(*p >= '0' && *p <= '9')) return false;
      while (*p >= '0' && *p <= '9') p++;
    }
    j.type = Json::NUM;
    j.num.assign(start, p - start);
    return true;
  }
};

/**
 * UTF-8 单字符解码并强校验:续字节格式、过长编码(overlong)、代理区码点、
 * >U+10FFFF、截断序列全部拒绝;非法返回 false(与 Python 对非法输入抛错对齐)。
 */
inline bool utf8DecodeStrict(const std::string& s, size_t i, uint32_t& cp, size_t& adv) {
  uint8_t c = (uint8_t)s[i];
  if (c < 0x80) { cp = c; adv = 1; return true; }
  uint32_t minv;
  if ((c & 0xE0) == 0xC0) { adv = 2; cp = c & 0x1F; minv = 0x80; }
  else if ((c & 0xF0) == 0xE0) { adv = 3; cp = c & 0x0F; minv = 0x800; }
  else if ((c & 0xF8) == 0xF0) { adv = 4; cp = c & 0x07; minv = 0x10000; }
  else return false; // 孤立续字节或 0xF8+(非法起始字节)
  if (i + adv > s.size()) return false; // 序列截断
  for (size_t k = 1; k < adv; k++) {
    uint8_t t = (uint8_t)s[i + k];
    if ((t & 0xC0) != 0x80) return false; // 续字节须为 10xxxxxx
    cp = (cp << 6) | (t & 0x3F);
  }
  if (cp < minv || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
  return true;
}

/** Python json.dumps 字符串转义(ensure_ascii=True):非 ASCII → \uXXXX(代理对)。
 *  含非法 UTF-8 时返回 false,调用方应拒绝签名。 */
inline bool jsonEscape(const std::string& s, std::string& out) {
  out += '"';
  for (size_t i = 0; i < s.size();) {
    uint8_t c = (uint8_t)s[i];
    if (c >= 0x20 && c < 0x7F && c != '"' && c != '\\') { out += (char)c; i++; continue; }
    uint32_t cp;
    size_t adv;
    if (!utf8DecodeStrict(s, i, cp, adv)) return false;
    i += adv;
    if (cp < 0x80) {
      switch (cp) {
        case '"': out += "\\\""; continue;
        case '\\': out += "\\\\"; continue;
        case '\b': out += "\\b"; continue;
        case '\f': out += "\\f"; continue;
        case '\n': out += "\\n"; continue;
        case '\r': out += "\\r"; continue;
        case '\t': out += "\\t"; continue;
        default: std::format_to(std::back_inserter(out), "\\u{:04x}", cp); continue;
      }
    }
    if (cp < 0x10000) {
      std::format_to(std::back_inserter(out), "\\u{:04x}", cp);
    } else { // 代理对
      cp -= 0x10000;
      std::format_to(std::back_inserter(out), "\\u{:04x}\\u{:04x}",
                     0xD800 | (cp >> 10), 0xDC00 | (cp & 0x3FF));
    }
  }
  out += '"';
  return true;
}

/** TaggedJSON 规范化:sort_keys + 紧凑分隔符。非法 UTF-8 时返回 false。 */
inline bool jsonCanonical(const Json& j, std::string& out) {
  switch (j.type) {
    case Json::NIL: out += "null"; break;
    case Json::BOOL: out += j.b ? "true" : "false"; break;
    case Json::NUM: out += j.num; break;
    case Json::STR: if (!jsonEscape(j.str, out)) return false; break;
    case Json::ARR:
      out += '[';
      for (size_t i = 0; i < j.arr.size(); i++) {
        if (i) out += ',';
        if (!jsonCanonical(j.arr[i], out)) return false;
      }
      out += ']';
      break;
    case Json::OBJ: {
      std::vector<const std::pair<std::string, Json>*> items;
      for (const auto& kv : j.obj) items.push_back(&kv);
      // Python sort_keys:按 Unicode 码点排序;UTF-8 字典序与码点序一致
      std::ranges::sort(items, [](const auto* a, const auto* b) { return a->first < b->first; });
      out += '{';
      for (size_t i = 0; i < items.size(); i++) {
        if (i) out += ',';
        if (!jsonEscape(items[i]->first, out)) return false;
        out += ':';
        if (!jsonCanonical(items[i]->second, out)) return false;
      }
      out += '}';
      break;
    }
  }
  return true;
}
