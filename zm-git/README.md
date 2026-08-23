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
| `-o` | 输出目录（默认用目标域名） |
| `-t` | 线程数（默认 32） |
| `-p` | 显式代理（默认忽略系统环境变量代理，避免本地靶场踩坑） |
| `--timeout` | 请求超时（默认 10s） |
| `--no-git` | 不调用本地 git，纯 Python 解析 index 还原 |
| `--no-crawl` | 禁用 autoindex 爬取模式 |
| `--no-brute` | 禁用分支/tag 爆破 |
| `--no-color` | 禁用彩色输出（重定向到文件时自动关闭） |

## 工作流程

1. **检测**：HEAD 可读性 + 软 404 探测
2. **autoindex 模式**：目录列举开启 → 递归全量爬取 `.git`
3. **无列举模式**：静态文件 + 引用爆破 → `objects/info/packs` 下载 pack →
   index/logs/refs 提取 hash → 动态队列递归下载 loose objects（commit→tree→blob/tag）
4. **fsck 闭环**：`git fsck --lost-found` 找悬空对象 → 补下载 → 循环至收敛
5. **还原**：优先 `git checkout -f`，无 git 则手动解析 index 还原工作区

## 后续分析

```bash
cd <输出目录>
git log --all --oneline     # 全部提交历史
git show <sha>              # 查看提交内容 / 找 flag
git fsck --lost-found       # 悬空对象
ls .git/lost-found/commit/  # 找回的 commit（历史版本 flag 常藏这里）
```
