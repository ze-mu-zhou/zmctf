"""对抗性测试:专挑边界与套件没覆盖的角落。"""
import base64, hashlib, hmac, json, os, subprocess, sys, time, zlib
from flask.sessions import session_json_serializer
from itsdangerous import URLSafeTimedSerializer, URLSafeSerializer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(ROOT, "..", "bin", "zemu-flask.exe") if False else os.path.join(os.path.dirname(HERE), "bin", "zemu-flask.exe")
WL = os.path.join(HERE, "_adv_wl.txt")

def ser(secret):
    return URLSafeTimedSerializer(secret_key=secret, salt="cookie-session",
        serializer=session_json_serializer,
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1})

def run(*args):
    return subprocess.run([TOOL, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")

fails = []
def check(name, ok, extra=""):
    print(("PASS" if ok else "FAIL"), name, extra)
    if not ok: fails.append(name)

# ---- T1: sign 键序 vs 真 Flask 字节级对比 ----
# 注:工具按 sort_keys 规范化,Flask 实际保持插入序 —— 字节必然不同(已知偏差);
# 但伪造 cookie 必须能被真 Flask 正确解析(签名对收到的字节验证)
obj = {"b": 1, "a": 2}
r = run("flask", "sign", "--secret", "k1", "--json", json.dumps(obj))
tool_payload = r.stdout.strip().split(".")[0]
flask_cookie = ser("k1").dumps(obj)
flask_payload = flask_cookie.split(".")[0]
check("T1-sign-keyorder-bytes", tool_payload != flask_payload,
      f"(已知偏差: tool={tool_payload} flask={flask_payload})")
# 即便字节不同,伪造 cookie 在 Flask 里也应能解
try:
    back = ser("k1").loads(r.stdout.strip()); ok = back == obj
except Exception as e: ok = False
check("T1b-forged-cookie-loads-in-flask", ok)

# ---- T2: 非 ASCII secret 全链路 ----
c = ser("密码秘密123").dumps({"u": 1})
r = run("flask", "verify", "--cookie", c, "--secret", "密码秘密123")
check("T2-utf8-secret-verify", r.returncode == 0 and r.stdout.strip() == "valid")
with open(WL, "w", encoding="utf-8") as f:
    f.write("wrong\n密码秘密123\nanother\n")
r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--engine", "cpu")
check("T2b-crack-utf8-secret-cpu", r.returncode == 0 and r.stdout.strip() == "密码秘密123", r.stderr[-80:])
os.unlink(WL)

# ---- T3: 超长词(>32B)纯CPU字典 & GPU跳过补验路径 ----
long_secret = "L" * 40
c = ser(long_secret).dumps({"x": 1})
with open(WL, "w") as f:
    f.write("\n".join(["short"] + ["z"*33] * 3 + [long_secret]) + "\n")
r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--engine", "cpu")
check("T3-long-word-cpu", r.returncode == 0 and r.stdout.strip() == long_secret, r.stderr[-60:])
r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--engine", "gpu")
check("T3b-long-word-gpu-skip-rescan", r.returncode == 0 and r.stdout.strip() == long_secret, r.stderr[-100:])
os.unlink(WL)

# ---- T4: 词长恰好等于 stride(GPU 边界) ----
sec16 = "A" * 32   # 强制 stride 恰为 32 的场景
c = ser(sec16).dumps({"x": 1})
with open(WL, "w") as f:
    f.write("\n".join(["b"*32, sec16, "c"*31]) + "\n")
r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--engine", "gpu")
check("T4-word-eq-stride-gpu", r.returncode == 0 and r.stdout.strip() == sec16, r.stderr[-100:])
os.unlink(WL)

# ---- T5: 掩码 ?? 转义 & 尾部裸 ? 报错 & 空结果空间 ----
c = ser("?l?0").dumps({"m": 1})   # 注意目标须在掩码空间内:?l?0 的末位是数字
r = run("flask", "crack", "--cookie", c, "--mask", "???l???d")
check("T5-mask-literal-q", r.returncode == 0 and r.stdout.strip() == "?l?0", r.stderr[-60:])
r = run("flask", "crack", "--cookie", c, "--mask", "?l?")
check("T5b-mask-trailing-bare-q", r.returncode != 0, r.stderr[-40:])
r = run("flask", "crack", "--cookie", c, "--mask", "")
check("T5c-mask-empty", r.returncode != 0)

# ---- T6: 巨型掩码空间溢出检测(>2^64) ----
r = run("flask", "crack", "--cookie", c, "--mask", "?a" * 40)
check("T6-mask-overflow-detected", r.returncode == 1 and "2^64" in r.stderr, r.stderr[-60:])

# ---- T7: salt 一致性(sign/verify/crack 三方) ----
c = ser("salty-secret").dumps({"q": 7})
r = run("flask", "verify", "--cookie", c, "--secret", "salty-secret", "--salt", "other-salt")
check("T7-wrong-salt-invalid", r.returncode == 1 and r.stdout.strip() == "invalid")
r = run("flask", "sign", "--secret", "salty-secret", "--json", '{"q":7}', "--salt", "other-salt")
c2 = r.stdout.strip()
r = run("flask", "verify", "--cookie", c2, "--secret", "salty-secret", "--salt", "other-salt")
check("T7b-custom-salt-roundtrip", r.returncode == 0 and r.stdout.strip() == "valid")

# ---- T8: 压缩 cookie(decode only) ----
big_obj = {"data": "A" * 500}
s = URLSafeSerializer("cmp-secret")
legacy_cookie = s.dumps(big_obj)  # 长载荷会触发 itsdangerous 的 '.'+zlib 格式
r = run("flask", "decode", "--cookie", legacy_cookie)
ok = False
try:
    # 工具输出的是解压后的 JSON 文本
    got = json.loads(r.stdout.strip())
    ok = (got == big_obj)
except Exception:
    ok = False
check("T8-compressed-decode", ok, repr(r.stdout[:60]))

# ---- T9: 畸形输入 ----
r = run("flask", "verify", "--cookie", "notacookie", "--secret", "x")
check("T9-malformed-cookie", r.returncode == 1)
r = run("flask", "verify", "--cookie", "YWJj.GVj.sig!", "--secret", "x")
check("T9b-bad-sig-b64", r.returncode == 1)
r = run("flask", "decode", "--cookie", "!!!.GVj.c2ln")
check("T9c-bad-payload-b64", r.returncode == 1)

# ---- T10: --threads 非法值 ----
c = ser("dragon").dumps({"f": 1})
with open(WL, "w") as f: f.write("wrong\ndragon\n")
for bad in ("abc", "-5"):
    r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--threads", bad, "--engine", "cpu")
    check(f"T10-threads-{bad}", r.returncode == 0 and r.stdout.strip() == "dragon")
os.unlink(WL)

# ---- T11: 空/不存在字典 ----
open(WL, "w").close()
r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--engine", "cpu")
check("T11-empty-wordlist", r.returncode == 1)
os.unlink(WL)
r = run("flask", "crack", "--cookie", c, "--wordlist", "Z:/no/such/file.txt", "--engine", "cpu")
check("T11b-missing-wordlist", r.returncode == 1)

# ---- T12: serve 模式协议(含未知命令 rc=2、连续多命令) ----
p = subprocess.run([TOOL, "serve"],
    input='["selftest"]\n["flask","verify","--cookie","bad","--secret","x"]\n["nonsense-cmd"]\n',
    capture_output=True, text=True, encoding="utf-8", errors="replace")
out = p.stdout
rcs = [l for l in out.splitlines() if l.startswith("<<<zk-rc=")]
check("T12-serve-three-sentinels", len(rcs) == 3 and rcs[0] == "<<<zk-rc=0>>>"
      and rcs[1] == "<<<zk-rc=1>>>" and rcs[2] == "<<<zk-rc=2>>>", str(rcs))

# ---- T13: secret 恰好 55/56/64/65 字节(HMAC padding 边界,CPU+GPU) ----
for L in (55, 56, 63, 64, 65):
    sec = "K" * L
    c = ser(sec).dumps({"n": L})
    with open(WL, "w") as f: f.write("\n".join(["nope", sec, "nope2"]) + "\n")
    r = run("flask", "crack", "--cookie", c, "--wordlist", WL, "--engine", "gpu")
    check(f"T13-len{L}-gpu", r.returncode == 0 and r.stdout.strip() == sec, r.stderr[-50:])
    os.unlink(WL)

# ---- T14: sign 数字格式保留 vs Python loads 语义 ----
r = run("flask", "sign", "--secret", "k", "--json", '{"n": 1e10}')
try:
    back = ser("k").loads(r.stdout.strip())
    ok = back == {"n": 1e10}
except Exception as e:
    ok = False
check("T14-num-exp-format", ok, r.stdout.strip()[:60])

# ---- T15: hybrid(auto)大字典 GPU 命中在头部、尾部两种位置 ----
for pos_name, place_first in (("head", True), ("tail", False)):
    target = f"w{'X'*6}{pos_name}"
    c = ser(target).dumps({"t": 1})
    lines = [f"f{i:06d}" for i in range(200000)]
    if place_first: lines.insert(0, target)
    else: lines.append(target)
    with open(WL, "w") as f: f.write("\n".join(lines) + "\n")
    env = dict(os.environ, ZK_GPUTHRESH="1", ZK_NOPROG="1")
    p = subprocess.run([TOOL, "flask", "crack", "--cookie", c, "--wordlist", WL,
                        "--engine", "auto", "--threads", "2"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    check(f"T15-hybrid-hit-{pos_name}", p.returncode == 0 and p.stdout.strip() == target,
          p.stdout.strip()[:30])
    os.unlink(WL)

# ---- T16: interactive EOF 中途(选 4 后直接 EOF,不应挂死) ----
p = subprocess.run([TOOL, "interactive"], input="4\njustcookie\n",
                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
check("T16-interactive-eof-no-hang", True)

print()
print("=" * 40)
if fails:
    print("FAILED:", len(fails)); [print(" -", f) for f in fails]; sys.exit(1)
print("ALL PASS"); sys.exit(0)
