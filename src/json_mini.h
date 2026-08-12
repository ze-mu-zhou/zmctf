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
            uint32_t cp;
            if (hex4(p + 1, cp) < 0) return false;
            p += 4;
            // 代理对:\uD83D\uDE00
            if (cp >= 0xD800 && cp <= 0xDBFF && p[1] == '\\' && p[2] == 'u') {
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

/** Python json.dumps 字符串转义(ensure_ascii=True):非 ASCII → \uXXXX(代理对) */
inline void jsonEscape(const std::string& s, std::string& out) {
  out += '"';
  for (size_t i = 0; i < s.size();) {
    uint8_t c = (uint8_t)s[i];
    if (c >= 0x20 && c < 0x7F && c != '"' && c != '\\') { out += (char)c; i++; continue; }
    uint32_t cp;
    size_t adv;
    if (c < 0x80) { cp = c; adv = 1; }
    else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; adv = 2; }
    else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; adv = 3; }
    else { cp = c & 0x07; adv = 4; }
    for (size_t k = 1; k < adv && i + k < s.size(); k++)
      cp = (cp << 6) | ((uint8_t)s[i + k] & 0x3F);
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
}

/** TaggedJSON 规范化:sort_keys + 紧凑分隔符 */
inline void jsonCanonical(const Json& j, std::string& out) {
  switch (j.type) {
    case Json::NIL: out += "null"; break;
    case Json::BOOL: out += j.b ? "true" : "false"; break;
    case Json::NUM: out += j.num; break;
    case Json::STR: jsonEscape(j.str, out); break;
    case Json::ARR:
      out += '[';
      for (size_t i = 0; i < j.arr.size(); i++) {
        if (i) out += ',';
        jsonCanonical(j.arr[i], out);
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
        jsonEscape(items[i]->first, out);
        out += ':';
        jsonCanonical(items[i]->second, out);
      }
      out += '}';
      break;
    }
  }
}
