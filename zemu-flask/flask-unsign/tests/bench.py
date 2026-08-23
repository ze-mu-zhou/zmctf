"""zemu-flask 性能基准:固定负载,输出各引擎速率(/s),供逐轮优化对比。

用法: python tests/bench.py [标记名]
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "bin", "zemu-flask.exe")
RATE_RE = re.compile(r"([\d.]+)\s*/s")

with open(os.path.join(HERE, "bench.cookie"), encoding="ascii") as f:
    COOKIE = f.read().strip()

# CPU 字典基准:1600 万随机 8 字节词(必未命中,跑满全程)
WL16 = os.path.join(HERE, "wl-bench16.txt")
if not os.path.exists(WL16):
    import random
    import string
    random.seed(7)
    with open(WL16, "w", encoding="ascii") as f:
        chunk = []
        for _ in range(16_000_000):
            chunk.append("".join(random.choices(string.ascii_lowercase + string.digits, k=8)))
            if len(chunk) >= 100_000:
                f.write("\n".join(chunk) + "\n")
                chunk = []
        if chunk:
            f.write("\n".join(chunk) + "\n")


def bench(name, *args):
    r = subprocess.run([TOOL, *args], capture_output=True, text=True, encoding="utf-8")
    m = RATE_RE.search(r.stderr)
    rate = m.group(1) if m else "N/A"
    tail = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else ""
    print(f"{name:14s} {rate:>14s} /s   ({tail[:60]})")
    return rate


tag = sys.argv[1] if len(sys.argv) > 1 else "run"
print(f"===== bench: {tag} =====")
bench("cpu-mask-1e8", "flask", "crack", "--cookie", COOKIE,
      "--mask", "?d" * 8, "--engine", "cpu")
bench("cpu-dict-16M", "flask", "crack", "--cookie", COOKIE,
      "--wordlist", WL16, "--engine", "cpu")
# GPU 掩码基准:26^4×10^4 = 4.57G 候选(全速约 6s,规模足够平滑分块开销)
bench("gpu-mask-4.6G", "flask", "crack", "--cookie", COOKIE,
      "--mask", "?l?l?l?l?d?d?d?d", "--engine", "gpu")
bench("gpu-dict-16M", "flask", "crack", "--cookie", COOKIE,
      "--wordlist", WL16, "--engine", "gpu")
# 混合引擎(auto:GPU+CPU 对向吃块)
bench("hyb-mask-4.6G", "flask", "crack", "--cookie", COOKIE,
      "--mask", "?l?l?l?l?d?d?d?d", "--engine", "auto")
bench("hyb-dict-16M", "flask", "crack", "--cookie", COOKIE,
      "--wordlist", WL16, "--engine", "auto")
