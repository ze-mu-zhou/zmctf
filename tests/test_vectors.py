"""zemu-flask 对拍测试:用真 itsdangerous/Flask 出 cookie,校验 CLI 各命令。

用法(需先 pip install itsdangerous flask 到虚拟环境):
    python tests/test_vectors.py
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time

from flask.sessions import session_json_serializer
from itsdangerous import URLSafeTimedSerializer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "bin", "zemu-flask.exe")
WORDLIST = os.path.join(HERE, "wl-test.txt")


def make_serializer(secret: str) -> URLSafeTimedSerializer:
    # 与 Flask 3.1 get_signing_serializer 完全一致的构造
    return URLSafeTimedSerializer(
        secret_key=secret,
        salt="cookie-session",
        serializer=session_json_serializer,
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    )


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([TOOL, *args], capture_output=True, text=True, encoding="utf-8")


fails = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global fails
    print(("PASS" if ok else "FAIL"), name, extra)
    if not ok:
        fails += 1


# --- 1. decode:Python 签 → 工具解 ---
cases = [
    {"username": "admin", "uid": 1},
    {"a": [1, True, None], "中文": "键\n值", "f": 1.5},
    {},
]
for i, obj in enumerate(cases):
    cookie = make_serializer("secret123").dumps(obj)
    r = run("flask", "decode", "--cookie", cookie)
    got = json.loads(r.stdout.strip())
    check(f"decode#{i}", got == obj, r.stdout.strip()[:80])

# --- 2. verify:有效/无效密钥 ---
cookie = make_serializer("s3cr3t-key").dumps({"user": "test"})
r = run("flask", "verify", "--cookie", cookie, "--secret", "s3cr3t-key")
check("verify-good", r.returncode == 0 and r.stdout.strip() == "valid")
r = run("flask", "verify", "--cookie", cookie, "--secret", "wrong")
check("verify-bad", r.returncode == 1 and r.stdout.strip() == "invalid")

# --- 3. sign:工具签 → Python 验 ---
ser = make_serializer("my-secret")
for i, obj in enumerate(cases):
    r = run("flask", "sign", "--secret", "my-secret", "--json", json.dumps(obj))
    c = r.stdout.strip()
    try:
        back = ser.loads(c)
        ok = back == obj
        extra = ""
    except Exception as e:
        ok, extra = False, f"{type(e).__name__}: {e}"
    check(f"sign#{i}", ok, extra)

# --- 4. sign --legacy:ts 以 2011-01-01(EPOCH=1293840000)为基准,签名手算复现 ---
def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


r = run("flask", "sign", "--secret", "k", "--json", '{"x":1}', "--legacy")
parts = r.stdout.strip().split(".")
ts = int.from_bytes(b64d(parts[1]), "big")
dk = hmac.new(b"k", b"cookie-session", hashlib.sha1).digest()
expect_sig = base64.urlsafe_b64encode(
    hmac.new(dk, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha1).digest()
).rstrip(b"=").decode()
check("sign-legacy",
      len(parts) == 3 and abs(ts - (time.time() - 1293840000)) < 60 and parts[2] == expect_sig,
      r.stdout.strip()[:80])

# --- 5. sign 边界:重复 key 后者覆盖(对齐 Python json.loads),超深嵌套拒绝 ---
r = run("flask", "sign", "--secret", "my-secret", "--json", '{"a":1,"a":2}')
check("sign-dupkey", ser.loads(r.stdout.strip()) == {"a": 2})
r = run("flask", "sign", "--secret", "s", "--json", "[" * 300 + "1" + "]" * 300)
check("sign-deep-nest", r.returncode == 1)

# --- 5b. sign 健壮性:截断 \u 转义(防 hex4 越界读)与非法 UTF-8(jsonEscape 强校验)---
r = run("flask", "sign", "--secret", "s", "--json", '{"x":"\\u12')
check("sign-trunc-u", r.returncode == 1)
# 非法 UTF-8 字节(0xFF)经 serve 模式按原始字节喂入,须拒绝签名(rc=1)
payload = b'["flask", "sign", "--secret", "s", "--json", "{\\"x\\":\\"\xff\\"}"]\n'
r = subprocess.run([TOOL, "serve"], input=payload, capture_output=True)
check("sign-bad-utf8", b"<<<zk-rc=1>>>" in r.stdout)

# --- 6. crack 字典:CPU 与 GPU 双引擎 ---
cookie = make_serializer("dragon").dumps({"flag": "ctf{demo}"})
with open(WORDLIST, "w", encoding="utf-8") as f:
    f.write("\n".join(["123456", "password", "dragon", "qwerty"]) + "\n")
for engine in ("cpu", "gpu", "auto"):
    r = run("flask", "crack", "--cookie", cookie, "--wordlist", WORDLIST,
            "--threads", "4", "--engine", engine)
    check(f"crack-dict-{engine}", r.returncode == 0 and r.stdout.strip() == "dragon",
          r.stderr.strip().splitlines()[-1] if r.stderr else "")
os.unlink(WORDLIST)

# --- 6b. hybrid 字典含超长词:GPU 命中后不得再过 idxMap(回归:曾双重映射输出错误词) ---
cookie = make_serializer("target123").dumps({"x": 1})
with open(WORDLIST, "w", encoding="utf-8") as f:
    f.write("a" * 40 + "\n")        # 超 stride=32,GPU 打包跳过 → idxMap 非恒等
    f.write("target123\n")          # 原下标 1;GPU 命中 packed 0,映回原下标 1
    for i in range(2_000_000):      # 填充词拖住 CPU 侧(单线程从尾部降序吃块),让 GPU 先命中
        f.write(f"zz{i:07x}\n")
env = dict(os.environ, ZK_GPUTHRESH="1", ZK_NOPROG="1")  # 强制小字典也走 GPU+CPU 混合
r = subprocess.run([TOOL, "flask", "crack", "--cookie", cookie, "--wordlist", WORDLIST,
                    "--engine", "auto", "--threads", "1"],
                   capture_output=True, text=True, encoding="utf-8", env=env)
check("crack-dict-hybrid-skip", r.returncode == 0 and r.stdout.strip() == "target123",
      f"{r.stdout.strip()[:40]} | {r.stderr.strip().splitlines()[-1] if r.stderr else ''}")
os.unlink(WORDLIST)

# --- 7. crack 掩码:CPU 与 GPU 双引擎(密钥 ab12 → ?l?l?d?d) ---
cookie = make_serializer("ab12").dumps({"u": "x"})
for engine in ("cpu", "gpu", "auto"):
    r = run("flask", "crack", "--cookie", cookie, "--mask", "?l?l?d?d", "--engine", engine)
    check(f"crack-mask-{engine}", r.returncode == 0 and r.stdout.strip() == "ab12",
          r.stderr.strip().splitlines()[-1] if r.stderr else "")

# --- 8. --engine 校验:非法值拒绝;显式 gpu 超参报错不静默回退 ---
r = run("flask", "crack", "--cookie", cookie, "--mask", "?l?l", "--engine", "gpuu")
check("engine-invalid", r.returncode == 2)
r = run("flask", "crack", "--cookie", cookie, "--mask", "?l?l",
        "--engine", "gpu", "--salt", "s" * 40)
check("engine-gpu-overlimit", r.returncode == 1 and "超限" in r.stderr,
      r.stderr.strip()[:80])


# --- 9. 交互模式:管道喂菜单答案(interactive 子命令不检查 tty,可测) ---
def run_stdin(stdin_text: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([TOOL, *args], input=stdin_text,
                          capture_output=True, text=True, encoding="utf-8")


cookie = make_serializer("my-secret").dumps({"u": 1})
r = run_stdin(f"1\n{cookie}\n0\n", "interactive")
check("interactive-decode", json.loads(r.stdout.strip()) == {"u": 1},
      r.stdout.strip()[:80])

r = run_stdin('3\nmy-secret\n{"u": 2}\n\nn\n0\n', "interactive")
try:
    back = ser.loads(r.stdout.strip())
    ok, extra = back == {"u": 2}, ""
except Exception as e:
    ok, extra = False, f"{type(e).__name__}: {e}"
check("interactive-sign", ok, extra)

# 非 tty 无参数:不进交互,打印用法(rc 2)
r = run_stdin("")
check("noargs-non-tty", r.returncode == 2 and "用法" in r.stderr)

sys.exit(1 if fails else 0)
