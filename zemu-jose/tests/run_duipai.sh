#!/usr/bin/env bash
# run_duipai.sh — 自研算法 vs 标准实现(Python hashlib/hmac/base64 + pyjwt/cryptography)对拍。
# 依赖:D:\Python\bin\python.exe(已装 pyjwt、cryptography)
set -e
cd "$(dirname "$0")"
export PATH="/c/msys64/ucrt64/bin:$PATH"
PY="/d/Python/bin/python.exe"

echo "== 生成 RSA 密钥对(供 RSA 对拍)=="
"$PY" - << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
open('duipai_rsa_priv.pem','wb').write(priv_pem)
pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
open('duipai_rsa_pub.pem','wb').write(pub_pem)
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
nums = priv.private_numbers()
jwk = json.dumps({'kty':'RSA',
  'n': b64u(nums.public_numbers.n.to_bytes(256,'big')),
  'e': b64u(nums.public_numbers.e.to_bytes(3,'big')),
  'd': b64u(nums.d.to_bytes(256,'big'))})
open('duipai_rsa_priv.jwk','w').write(jwk)
print('keys generated')
EOF

echo "== 编译 vectest =="
g++ -O2 -std=c++26 vectest.cpp -I../src -o vectest.exe

echo "== 运行 vectest,输出向量 =="
./vectest.exe duipai_rsa_priv.pem > vectest.out

echo "== Python 参考计算并对比 =="
"$PY" - << 'EOF'
import hashlib, hmac, base64, sys
# 确定性伪随机,与 C++ 侧 (i*131+17)%256 一致
def rbytes(n, off=0):
    return bytes(((i+off)*131+17) & 0xff for i in range(n))
expected = {}
seqOff = 0
for L in [0,1,55,56,63,64,65,111,112,127,128,129,1000,65536]:
    data = rbytes(L, seqOff); seqOff += L+7
    expected[f'sha256_len{L}'] = hashlib.sha256(data).hexdigest()
    expected[f'sha384_len{L}'] = hashlib.sha384(data).hexdigest()
    expected[f'sha512_len{L}'] = hashlib.sha512(data).hexdigest()
for klen in [0,1,20,63,64,65,128]:
    key = rbytes(klen, 100000+klen)
    msg = rbytes(200, 200000+klen)
    expected[f'hmac256_k{klen}'] = hmac.new(key,msg,hashlib.sha256).hexdigest()
    expected[f'hmac384_k{klen}'] = hmac.new(key,msg,hashlib.sha384).hexdigest()
    expected[f'hmac512_k{klen}'] = hmac.new(key,msg,hashlib.sha512).hexdigest()
for L in [0,1,2,3,4,5,6,7,8,100,1024]:
    data = rbytes(L, 300000+L)
    expected[f'b64_len{L}'] = base64.urlsafe_b64encode(data).rstrip(b'=').decode()
for bits in [256,512,1024,2048]:
    n = int.from_bytes(rbytes(bits//8, 400000+bits),'big')|1
    e = int.from_bytes(rbytes(bits//8, 500000+bits),'big')
    a = int.from_bytes(rbytes(bits//8, 600000+bits),'big')
    expected[f'modpow_{bits}'] = format(pow(a,e,n),'x')
# RSA:用同一个私钥,cryptography 直接对摘要做 PKCS1v15 签名
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
priv = serialization.load_pem_private_key(open('duipai_rsa_priv.pem','rb').read(), None)
msg = b'duipai-vector-message'
for alg, hs in [('RS256', hashes.SHA256()), ('RS384', hashes.SHA384()), ('RS512', hashes.SHA512())]:
    digest = hashlib.new({'RS256':'sha256','RS384':'sha384','RS512':'sha512'}[alg], msg).digest()
    sig = priv.sign(msg, padding.PKCS1v15(), hs)
    expected[f'rs_{alg}_sig'] = sig.hex()
    expected[f'rs_{alg}_digest'] = digest.hex()

bad = 0
for line in open('vectest.out'):
    line = line.strip()
    if '=' not in line: continue
    name, val = line.split('=', 1)
    if name == 'rsa_pem_loaded' or name.endswith('self_verify'):
        print(f'{name}={val}')
        continue
    if name in expected:
        if expected[name] != val:
            print(f'MISMATCH {name}')
            bad += 1
    else:
        print(f'UNKNOWN {name}')
        bad += 1
print('--- 对拍完成 ---')
sys.exit(1 if bad else 0)
EOF
echo "对拍结果: $?"
