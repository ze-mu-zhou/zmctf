"""生成 crack 基准数据:100 万条字典,密钥放最后(跑满全程)。"""
import hashlib
import os
import random
import string

from flask.sessions import session_json_serializer
from itsdangerous import URLSafeTimedSerializer

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(1)
with open(os.path.join(HERE, "wl-bench.txt"), "w", encoding="ascii") as f:
    for _ in range(1_000_000):
        f.write("".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "\n")
    f.write("tArget9x\n")

ser = URLSafeTimedSerializer(
    secret_key="tArget9x",
    salt="cookie-session",
    serializer=session_json_serializer,
    signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
)
with open(os.path.join(HERE, "bench.cookie"), "w") as f:
    f.write(ser.dumps({"flag": "x"}))
print("bench ready")
