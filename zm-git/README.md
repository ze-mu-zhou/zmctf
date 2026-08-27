# zm-git

.git 泄露利用工具 —— 融合 GitTools / GitHacker / git-dumper 三者优点的增强版。

## 与主流工具对比

| 能力 | GitTools | GitHacker | git-dumper | **zm-git** |
|---|---|---|---|---|
| 无需目录列举 | ❌ | ✅ | 部分 | ✅ |
| autoindex 全量爬取 | ✅ | ❌ | ✅ | ✅ |
| pack 文件下载（哑协议 `objects/info/packs`） | ❌ | ❌ | ❌ | ✅ |
| 分支/tag 引用爆破 | ❌ | ✅ | ❌ | ✅ |
| fsck 悬空对象闭环找回 | ❌ | ✅ | ❌ | ✅（循环至收敛） |
| 软 404 对抗（zlib 魔数校验） | ❌ | 部分 | ❌ | ✅ |
| 动态工作队列线程池 | ❌ | 部分 | ❌ | ✅ |
| 无本地 git 时手动解析 index 还原 | ❌ | ❌ | ❌ | ✅ |

## 用法

```bash
pip3 install -r requirements.txt

python3 zm-git.py                          # 交互式模式（彩色引导，逐个输入目标）
python3 zm-git.py 127.0.0.1:1234           # 裸地址：自动尝试 http/https + 补全 /.git/
python3 zm-git.py site.com/vps/.git -t 64  # 带子路径也识别
python3 zm-git.py https://site.com -p http://127.0.0.1:8080
```

### URL 输入格式（全部接受）

| 输入 | 自动解析为 |
|---|---|
| `127.0.0.1:1234` | `http://` + `https://` 都试，补 `/.git/` |
| `site.com` | 同上 |
| `site.com/sub` | `http(s)://site.com/sub/.git/` |
| `https://site.com/x/.git` | 原样保留，补尾部 `/` |

### 参数

| 参数 | 说明 |
|---|---|
| `-o` | 输出目录（默认固定为 `zm-git-output`，每次运行前覆盖） |
| `-t` | 协程并发数（默认自动拉满：CPU×32，上限 512） |
| `-p` | 显式代理（默认忽略系统环境变量代理，避免本地靶场踩坑） |
| `-H` | 自定义 HTTP 头，可重复（如 `-H "Authorization: Bearer xxx"`），同时透传给智能协议的 `git clone` |
| `--cert`/`--key` | 客户端证书/私钥 PEM（双向 TLS），clone 时透传为 `http.sslCert/sslKey` |
| `--p12` | PKCS#12 客户端证书（可选依赖 `cryptography`，`--p12-password` 给密码，缺省交互询问） |
| `--timeout` | 请求超时（默认 10s） |
| `--no-git` | 不调用本地 git，纯 Python 解析 index 还原 |
| `--no-crawl` | 禁用 autoindex 爬取模式 |
| `--no-brute` | 禁用分支/tag 爆破 |
| `-w` | 自定义分支/tag 名字典（每行一个，追加到内置字典） |
| `--pulls` | GitHub PR 引用爆破范围 refs/pull/1..N（默认 20，0 关闭） |
| `--no-color` | 禁用彩色输出（重定向到文件时自动关闭） |

## 工作流程

1. **检测**：HEAD 可读性 + 软 404 探测
2. **autoindex 模式**：目录列举开启 → 递归全量爬取 `.git`
3. **无列举模式**：静态文件 + 引用爆破 → `objects/info/packs` 下载 pack →
   index/logs/refs 提取 hash → 动态队列递归下载 loose objects（commit→tree→blob/tag，
   每个对象落盘前做 SHA1 自校验，防 MITM 篡改）
4. **净化**：下载来的 `.git/config` 整体替换为最小安全配置（防 `core.fsmonitor` / `core.hooksPath` 等可执行键 RCE，原文件保留为 `config.orig-from-server` 供分析），服务器下发的 hooks 隔离到 `quarantine/hooks/`，`info/exclude`、`info/attributes`、`info/grafts` 隔离到 `quarantine/info/`（防隐藏改动/绑定 filter 驱动/伪造提交历史）
5. **fsck 闭环**：`git fsck --lost-found` 找悬空对象 → 补下载 → 循环至收敛
6. **还原**：优先 `git checkout -f`（强制 `core.autocrlf=false` 保证字节保真），无 git 则手动解析 index 还原工作区

## 后续分析

```bash
cd <输出目录>
git log --all --oneline     # 全部提交历史
git show <sha>              # 查看提交内容 / 找 flag
git fsck --lost-found       # 悬空对象
ls .git/lost-found/commit/  # 找回的 commit（历史版本 flag 常藏这里）
```
