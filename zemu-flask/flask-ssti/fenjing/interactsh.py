"""self-hosted interactsh 服务器的注册/轮询客户端

协议（与 projectdiscovery/interactsh client 一致）：
- POST /register  {"public-key": base64(PEM公钥), "secret-key": secret, "correlation-id": id}
- GET  /poll?id=<correlation-id>&secret=<secret> -> {"data": [...], "aes_key": ...}
- POST /deregister {"secret-key": ..., "correlation-id": ...}

服务器返回的 aes_key 用客户端公钥做了 RSA PKCS#1 OAEP(SHA-256) 加密，
data 中每条记录是 base64(IV + AES-CTR(密文))，明文为JSON。

为了不引入第三方加密依赖，这里用纯python实现了所需的全部密码学原语：
- RSA-1024 密钥生成（Miller-Rabin素数生成）
- RSA OAEP(SHA-256) 解密
- AES 分组加密（CTR模式只需要加密方向）与CTR加解密
"""

import base64
import hashlib
import json
import logging
import secrets
import string
import uuid
import warnings

import requests
import urllib3

logger = logging.getLogger("interactsh")
warnings.simplefilter("ignore", category=urllib3.exceptions.InsecureRequestWarning)


class InteractshError(Exception):
    """interactsh注册/轮询失败"""


# ---------------- 纯python AES（仅加密方向，CTR模式用） ----------------

_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


def _xtime(a: int) -> int:
    """GF(2^8)上乘x"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """GF(2^8)乘法"""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


class _AES:
    """AES分组加密（仅加密方向），支持128/192/256位密钥"""

    def __init__(self, key: bytes):
        self.nk = len(key) // 4
        if self.nk not in (4, 6, 8):
            raise ValueError(f"AES key length must be 16/24/32 bytes, got {len(key)}")
        self.nr = self.nk + 6
        words = [list(key[4 * i : 4 * i + 4]) for i in range(self.nk)]
        rcon = 1
        for i in range(self.nk, 4 * (self.nr + 1)):
            temp = list(words[i - 1])
            if i % self.nk == 0:
                temp = [_AES_SBOX[b] for b in temp[1:] + temp[:1]]
                temp[0] ^= rcon
                rcon = _xtime(rcon)
            elif self.nk > 6 and i % self.nk == 4:
                temp = [_AES_SBOX[b] for b in temp]
            words.append([words[i - self.nk][j] ^ temp[j] for j in range(4)])
        self.round_keys = words

    @staticmethod
    def _add_round_key(state, words):
        for c in range(4):
            for r in range(4):
                state[r][c] ^= words[c][r]

    @staticmethod
    def _sub_bytes(state):
        for r in range(4):
            for c in range(4):
                state[r][c] = _AES_SBOX[state[r][c]]

    @staticmethod
    def _shift_rows(state):
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]

    @staticmethod
    def _mix_columns(state):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            state[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
            state[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
            state[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
            state[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)

    def encrypt_block(self, block: bytes) -> bytes:
        """加密一个16字节分组"""
        state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_round_key(state, self.round_keys[0:4])
        for rnd in range(1, self.nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[4 * rnd : 4 * rnd + 4])
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[4 * self.nr : 4 * self.nr + 4])
        return bytes(state[r][c] for c in range(4) for r in range(4))


def aes_ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CTR加解密（对称），counter初始值为IV，大端递增

    Args:
        key (bytes): AES密钥
        iv (bytes): 16字节IV，作为counter初值
        data (bytes): 明文或密文

    Returns:
        bytes: 密文或明文
    """
    aes = _AES(key)
    counter = int.from_bytes(iv, "big")
    out = bytearray()
    for off in range(0, len(data), 16):
        keystream = aes.encrypt_block(counter.to_bytes(16, "big"))
        block = data[off : off + 16]
        out += bytes(b ^ k for b, k in zip(block, keystream))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


# ---------------- 纯python RSA与OAEP ----------------

_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
)


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    """Miller-Rabin素性测试"""
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    """生成指定位数的素数"""
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(n):
            return n


def gen_rsa_key(bits: int = 1024, e: int = 65537):
    """生成RSA密钥对

    Args:
        bits (int): 模数位数，interactsh用1024即可
        e (int): 公钥指数

    Returns:
        Tuple[int, int, int]: (n, e, d)
    """
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        return p * q, e, pow(e, -1, phi)


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_seq(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def rsa_public_key_pem(n: int, e: int) -> str:
    """把RSA公钥编码为PKCS#8 PEM（interactsh /register需要的格式）

    Args:
        n (int): 模数
        e (int): 公钥指数

    Returns:
        str: PEM文本
    """
    rsa_pub = _der_seq(_der_int(n), _der_int(e))
    alg_id = _der_seq(
        _der_tlv(0x06, bytes.fromhex("2A864886F70D010101")),  # rsaEncryption OID
        _der_tlv(0x05, b""),  # NULL
    )
    spki = _der_seq(alg_id, _der_tlv(0x03, b"\x00" + rsa_pub))
    b64 = base64.b64encode(spki).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"


def _mgf1(seed: bytes, length: int) -> bytes:
    """MGF1(SHA-256)"""
    out = b""
    for i in range((length + 31) // 32):
        out += hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
    return out[:length]


def rsa_oaep_sha256_decrypt(n: int, d: int, ciphertext: bytes) -> bytes:
    """RSA PKCS#1 OAEP(SHA-256, 空label)解密

    Args:
        n (int): RSA模数
        d (int): RSA私钥指数
        ciphertext (bytes): 密文

    Returns:
        bytes: 明文
    """
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(ciphertext, "big"), d, n).to_bytes(k, "big")
    hlen = 32
    masked_seed, masked_db = em[1 : 1 + hlen], em[1 + hlen :]
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1(masked_db, hlen)))
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1(seed, k - 1 - hlen)))
    if db[:hlen] != hashlib.sha256(b"").digest():
        raise InteractshError("OAEP decode failed: lHash mismatch")
    try:
        idx = db.index(b"\x01", hlen)
    except ValueError as e:
        raise InteractshError("OAEP decode failed: no separator") from e
    return db[idx + 1 :]


# ---------------- interactsh客户端 ----------------


class InteractshClient:
    """self-hosted interactsh服务器客户端：注册->获得回调子域名->轮询交互记录"""

    def __init__(self, server: str, token: str = "", timeout: int = 15):
        """传入interactsh服务器地址

        Args:
            server (str): 服务器域名，如 oob.zemu137.online；
                可带http://或https://前缀，默认https
            token (str): 服务器设置了鉴权时的token
            timeout (int): 请求超时时间
        """
        server = server.strip()
        self.scheme = "https"
        if server.startswith("http://"):
            self.scheme = "http"
            server = server[len("http://") :]
        elif server.startswith("https://"):
            server = server[len("https://") :]
        self.server = server.strip("/")
        self.token = token
        self.timeout = timeout
        self.correlation_id = ""
        self.secret = ""
        self.domain = ""
        self._n = 0
        self._d = 0

    @property
    def base_url(self) -> str:
        """服务器base URL"""
        return f"{self.scheme}://{self.server}"

    def _headers(self):
        return {"Authorization": self.token} if self.token else {}

    def _request_with_scheme_fallback(self, method: str, path: str, **kwargs):
        """发请求，默认https；遇到SSL错误时自动回退http（self-hosted常无TLS）"""
        try:
            return requests.request(
                method, f"{self.base_url}{path}", timeout=self.timeout,
                verify=False, **kwargs,
            )
        except requests.exceptions.SSLError:
            if self.scheme != "https":
                raise
            logger.warning(
                "[yellow]https连接失败，回退到http://%s 重试[/]",
                self.server,
                extra={"markup": True, "highlighter": None},
            )
            self.scheme = "http"
            return requests.request(
                method, f"{self.base_url}{path}", timeout=self.timeout,
                verify=False, **kwargs,
            )

    def register(self) -> str:
        """注册，返回分配到的回调子域名（<33字符随机id>.<server>）

        Returns:
            str: 回调子域名

        Raises:
            InteractshError: 注册失败
        """
        logger.info("向interactsh服务器 [blue]%s[/] 注册...", self.base_url,
                    extra={"markup": True, "highlighter": None})
        self._n, e, self._d = gen_rsa_key(1024)
        public_key = base64.b64encode(rsa_public_key_pem(self._n, e).encode()).decode()
        guid = "".join(secrets.choice(string.ascii_lowercase + string.digits)
                       for _ in range(33))
        self.correlation_id = guid[:20]
        self.secret = str(uuid.uuid4())
        self.domain = f"{guid}.{self.server}"
        try:
            resp = self._request_with_scheme_fallback(
                "POST",
                "/register",
                json={
                    "public-key": public_key,
                    "secret-key": self.secret,
                    "correlation-id": self.correlation_id,
                },
                headers=self._headers(),
            )
            msg = resp.json().get("message", "")
        except Exception as e:  # pylint: disable=broad-except
            raise InteractshError(f"register failed: {e}") from e
        if "registration successful" not in msg:
            raise InteractshError(f"register rejected by server: {msg or resp.text!r}")
        logger.info(
            "[green]注册成功[/]，回调子域名: [cyan bold]%s[/]",
            self.domain,
            extra={"markup": True, "highlighter": None},
        )
        return self.domain

    def poll(self) -> list:
        """轮询一次交互记录，返回解密后的交互列表

        Returns:
            list: 交互记录dict列表（protocol/raw-request/remote-address/timestamp等）
        """
        try:
            resp = self._request_with_scheme_fallback(
                "GET",
                "/poll",
                params={"id": self.correlation_id, "secret": self.secret},
                headers=self._headers(),
            )
            data = resp.json()
        except Exception as e:  # pylint: disable=broad-except
            raise InteractshError(f"poll failed: {e}") from e
        results = []
        if data.get("data"):
            aes_key = rsa_oaep_sha256_decrypt(
                self._n, self._d, base64.b64decode(data["aes_key"])
            )
            for item in data["data"]:
                raw = base64.b64decode(item)
                plain = aes_ctr_crypt(aes_key, raw[:16], raw[16:])
                results.append(json.loads(plain))
        return results

    def deregister(self) -> bool:
        """注销，释放服务器上的注册信息

        Returns:
            bool: 是否成功
        """
        try:
            resp = self._request_with_scheme_fallback(
                "POST",
                "/deregister",
                json={"secret-key": self.secret, "correlation-id": self.correlation_id},
                headers=self._headers(),
            )
            return "success" in resp.text
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("deregister failed: %s", e, extra={"highlighter": None})
            return False
