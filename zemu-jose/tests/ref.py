#!/usr/bin/env python3
"""ref.py — zemu-jose 对拍参考实现(标准库 + pyjwt + cryptography)。
生成随机/固定向量,计算标准结果,与 zemu-jose 的 vectest 输出逐行对比。
用法:python ref.py <vectest_output>
"""
import sys, hashlib, hmac, base64, json, random

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def parse(line):
    # vectest 输出格式:name=hex
    if '=' not in line: return None
    name, val = line.strip().split('=', 1)
    return name, val

def main():
    expected = {}
    rng = random.Random(20260823)

    # --- SHA-256 / SHA-384 / SHA-512 向量(长度边界) ---
    for L in [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000, 65536]:
        data = bytes(rng.randrange(256) for _ in range(L))
        expected[f'sha256_len{L}'] = hashlib.sha256(data).hexdigest()
        expected[f'sha384_len{L}'] = hashlib.sha384(data).hexdigest()
        expected[f'sha512_len{L}'] = hashlib.sha512(data).hexdigest()

    # --- HMAC-SHA256/384/512(固定与随机 key) ---
    for klen in [0, 1, 20, 63, 64, 65, 128]:
        key = bytes(rng.randrange(256) for _ in range(klen))
        msg = bytes(rng.randrange(256) for _ in range(200))
        expected[f'hmac256_k{klen}'] = hmac.new(key, msg, hashlib.sha256).hexdigest()
        expected[f'hmac384_k{klen}'] = hmac.new(key, msg, hashlib.sha384).hexdigest()
        expected[f'hmac512_k{klen}'] = hmac.new(key, msg, hashlib.sha512).hexdigest()

    # --- base64url ---
    for L in [0, 1, 2, 3, 4, 5, 6, 7, 8, 100, 1024]:
        data = bytes(rng.randrange(256) for _ in range(L))
        expected[f'b64_len{L}'] = b64u(data)

    # --- 大整数模幂(与 Python pow 对拍) ---
    for bits in [256, 512, 1024, 2048]:
        n = int.from_bytes(bytes(rng.randrange(256) for _ in range(bits // 8)), 'big') | 1
        e = int.from_bytes(bytes(rng.randrange(256) for _ in range(bits // 8)), 'big')
        a = int.from_bytes(bytes(rng.randrange(256) for _ in range(bits // 8)), 'big')
        expected[f'modpow_{bits}'] = format(pow(a, e, n), 'x')

    # --- RSA 双向对拍(需 cryptography;签名/验签与 vectest 相同 key) ---
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa as c_rsa
        from cryptography.hazmat.primitives import serialization
        import jwt
        priv = c_rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = priv.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        msg = b'duipai-vector-message'
        for alg, hsh in [('RS256', hashlib.sha256), ('RS384', hashlib.sha384), ('RS512', hashlib.sha512)]:
            digest = hsh(msg).digest()
            # pyjwt 签名的 token(标准实现签名)
            tok = jwt.encode({'msg': msg.decode()}, priv_pem, algorithm=alg)
            expected[f'rs_{alg}_sig'] = tok.split('.')[2]
            expected[f'rs_{alg}_digest'] = digest.hex()
        # JWK 表示
        import json as _json
        def to_jwk(pub, priv_):
            nums = priv_.private_numbers()
            return _json.dumps({
                'kty': 'RSA', 'n': b64u(nums.public_numbers.n.to_bytes(256, 'big')),
                'e': b64u(nums.public_numbers.e.to_bytes(3, 'big')),
                'd': b64u(nums.d.to_bytes(256, 'big'))})
        expected['rsa_jwk'] = to_jwk(pub_pem, priv)
        expected['rsa_pem_pub'] = pub_pem.strip().decode()
    except ImportError:
        pass

    # --- 对比 vectest 输出 ---
    mismatches = 0
    seen = 0
    for line in sys.stdin:
        p = parse(line)
        if not p: continue
        name, val = p
        seen += 1
        if name in expected:
            if expected[name] != val:
                print(f'MISMATCH {name}: expect={expected[name][:40]}... got={val[:40]}...')
                mismatches += 1
        else:
            print(f'UNKNOWN {name}')
            mismatches += 1
    print(f'--- 对拍完成:对比 {seen} 项,不匹配 {mismatches} 项 ---')
    return 1 if mismatches else 0

if __name__ == '__main__':
    sys.exit(main())
