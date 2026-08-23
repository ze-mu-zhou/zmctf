# zemu-jose

JOSE(JWS/JWT/JWE)攻防工具集,C++26 自研实现,对标 flask-unsign 的四大功能
(decode / verify / sign / crack)+ **算法自动识别**。

## 功能

| 命令 | 说明 |
|---|---|
| `decode` | 解析 token,自动识别格式(3 段=JWS、5 段=JWE、2 段=alg=none、JSON 序列化)与算法 |
| `verify` | 验证签名(HS* 用 secret;RS/ES/EdDSA 用 PEM/JWK 密钥;算法从 header 自动识别) |
| `sign` | 签发 token(HS256/384/512、RS256/384/512、ES256/384/512、EdDSA、none) |
| `crack` | 爆破 HS* 密钥:hashcat 风格掩码 + 字典;**GPU(OpenCL)+ CPU 双引擎** |
| `selftest` | 自研算法 vs OpenSSL 对拍 |
| `gpuinfo` / `gputest` | OpenCL GPU 探测/冒烟 |
| `interactive` | 中文交互菜单 |
| `serve` | stdin 常驻服务(JSON 行协议) |

### 算法自动识别

标准 JWT 的 header 自带 `alg` 字段,因此无需手动指定:

```
3 段 → JWS:  alg = HS256/384/512 | RS256/384/512 | ES256/384/512 | EdDSA | none
5 段 → JWE:  alg(密钥管理) + enc(内容加密,AES-GCM dir 模式可解密)
2 段 → 无签名(alg=none)
```

`decode` 还会提示 header 中的风险字段(`kid` 路径穿越/SQLi、`jku`/`x5u` JWKS 拉取、`crit` 强制算法切换)。

## 自研 vs 标准实现(完全对拍)

| 组件 | 实现 | 对拍基准 |
|---|---|---|
| base64url | 自研(`src/b64.h`) | Python `base64.urlsafe_b64encode` |
| SHA-256/384/512 | 自研(`src/sha2.h`),SHA-256 含 **SHA-NI 硬件路径** | Python `hashlib` / FIPS 180-4 向量 |
| HMAC-SHA2 | 自研,爆破热路径预计算 | Python `hmac` / RFC 4231 |
| 大整数模幂 | 自研(`src/bigint.h`) | Python `pow(a,e,n)` |
| RSA PKCS#1 v1.5 | 自研(`src/rsa.h`),PEM/JWK 解析 | `cryptography` PKCS1v15 |
| ECDSA / EdDSA / JWE | OpenSSL 3.x 桥接(`src/ossl.cpp`) | 标准库本身 |
| JWT 全链路 | 上述组合 | pyjwt 2.13 双向互签互验 |

对拍脚本:`tests/run_duipai.sh`(确定性向量,零 mismatch)。

```
$ bash tests/run_duipai.sh
sha256_len0=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
...
--- 对拍完成 ---
```

## 性能:与 hashcat 7.1.2 同机实测对比

环境:RTX 4060 Laptop GPU(24 SM)+ 32 逻辑核(SHA-NI)。同一 HS256 JWT、同一任务,
均无命中跑满全空间(避免提前退出造成统计差异),交叉多轮取区间。

### 掩码爆破 `?d×10`(10^10 候选,跑满全空间)

| 引擎 | 速率(自报) | wall(含启动) |
|---|---|---|
| hashcat OpenCL(-d 2 -a 3 -w 3) | 579~596 MH/s | 20.2~21.3s(含 ~5s JIT) |
| hashcat CUDA(-d 1) | 493 MH/s | 24.5s |
| **zemu-jose GPU** | **579~584 MH/s(热态)~594 MH/s** | **17.2~19.4s(启动 <0.5s)** |
| zemu-jose CPU(32 线程) | 150 MH/s | — |

结论:纯计算速率与 hashcat 持平(同轮互有胜负,差异在热波动噪声内);计及启动延迟,
10^10 规模任务总耗时 zemu 稳定更短(17~19s vs 20~21s)。GPU kernel 为 hashcat 风格
寄存器流水线(见下)。

### 字典爆破(rockyou 379 万条,跑满)

| 引擎 | 速率 | wall |
|---|---|---|
| hashcat GPU(-a 0) | 30~32 MH/s | 1.5~2.2s(首轮含 JIT 更久) |
| **zemu-jose CPU(32 线程)** | **108 MH/s** | **0.2s** |
| zemu-jose GPU | 11 MH/s | 0.6s(字典传输开销,建议走 CPU) |

> 历史注记:初版 kernel 为字节导向(~400 MH/s,为 hashcat 的 ~70%);重写为 hashcat 风格
> 寄存器流水线后追平。更早版本另有 keyspace 截断 bug 导致虚高“GH/s”数据,均已修复。

### GPU kernel 优化历程(终版结构)

初版字节导向 kernel 的瓶颈经实测排除法定位:不是候选反解除法链(5 次 vs 10 次除法速率相同),
也不是 Ch/Maj 未走 LOP3(bitselect 改写无差异),而是 **字节数组落入 local memory**。
终版参照 hashcat `inc_hash_sha256.cl` 重写:

1. **寄存器常驻 u32 流水线**:16 个具名 u32 消息字 + 轮函数宏全展开,零字节数组、零动态下标;
   Ch/Maj 用 bitselect 形式(单条 LOP3);HMAC 的 ipad 以字为单位构建,opad 由 ipad ^ 0x6a6a6a6a
   现算(省 16 个持久寄存器,提升 occupancy);
2. **内层候选摊薄(hashcat Loops 同款)**:每 work-item 只做一次混合进制反解,
   内层 256 个候选递增+进位推进,且仅重建受影响的密钥字;
3. **字粒度数据流**:消息块/期望签名/字典词条全部由 host 预交换为 BE u32,按字加载,
   命中判定首字过滤 + CAS 记录。

### 爆破限制与语义

- 掩码顺序与 hashcat 一致:最右位变化最快(序号低位 = 掩码末位)
- 掩码位数上限 CPU/GPU 统一为 64 位;keyspace 乘积超出 uint64 时报错拒绝
- GPU:签名输入 ≤ 1024 字节(16 个 SHA-256 块),超出自动回退 CPU
- 字典词超长(>63B)在 GPU 模式下截断
- 性能调优备注:主循环 unroll 4 / 全展开 / unroll 8、每 work-item 2 候选 ILP、分块 2^28 / 2^30、
  显式 work-group size(256/512)均实测无显著差异;字节数组落 local memory 才是初版瓶颈,
  重写为寄存器流水线 + opad 异或推导后从 ~400 MH/s 提升至 ~580 MH/s(与 hashcat 持平)

## 构建

```bash
# MSYS2 UCRT64:需 mingw-w64-ucrt-x86_64-gcc(≥15)与 mingw-w64-ucrt-x86_64-openssl
bash build.sh   # 输出 bin/zemu-jose.exe(静态链接,免 DLL)
```

## 使用示例

```bash
# 解析(自动识别)
zemu-jose decode --token eyJhbGciOiJIUzI1NiJ9...

# 验签(HS256,自动识别算法)
zemu-jose verify --token <jwt> --secret 'secret'

# 验签(RS256,公钥文件)
zemu-jose verify --token <jwt> --key pub.pem

# 签发
zemu-jose sign --alg HS256 --secret 'secret' --json '{"admin":true}'
zemu-jose sign --alg RS256 --key priv.pem --json '{"admin":true}'

# 爆破(自动识别 HS256,GPU 优先)
zemu-jose crack --token <jwt> --mask '?l?l?l?d?d?d'
zemu-jose crack --token <jwt> --wordlist rockyou.txt --engine cpu --threads 32

# JWE dir 模式解密(A256GCM,key 支持 hex 或原始字节)
zemu-jose decode --token <jwe> --key <hexkey>
```

## 目录结构

```
src/
├── main.cpp        CLI + 交互菜单 + selftest
├── jose.h/.cpp     JOSE 核心:自动识别 + decode/verify/sign/crack
├── b64.h           base64url 自研
├── sha2.h          SHA-256/384/512 自研(SHA-NI 加速)+ HMAC 热路径
├── bigint.h        大整数自研
├── rsa.h           RSA PKCS#1 v1.5 自研(PEM/JWK)
├── ossl.h/.cpp     OpenSSL 桥接(ES*/EdDSA/JWE)
├── crack_cpu.h     CPU 爆破(字典/掩码,多线程)
└── gpu/
    ├── ocl.h/.cpp  OpenCL 动态加载(免 Khronos 头)
    └── kernel_jwt.h HS256 爆破 kernel(hashcat 风格寄存器流水线,详见性能章节)
tests/
├── vectest.cpp     自研算法向量输出
├── run_duipai.sh   对拍脚本(标准库 + cryptography)
└── ref.py          参考实现
bench/              基准数据(JWT、词表、密钥)
```
