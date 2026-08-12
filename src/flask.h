/**
 * flask.h:Flask session cookie 命令(decode / verify / sign / crack)。
 * 格式与 itsdangerous 2.x(URLSafeTimedSerializer)+ Flask 3.x 逐字节对齐:
 *   cookie  = b64url(json) "." b64url(ts) "." b64url(hmac)
 *   ts      = int(unix_time) → 8 字节大端去前导零(legacy: time - 1293840000,itsdangerous <1.0 的 EPOCH)
 *   derived = HMAC-SHA1(key=secret, msg=salt)      // key_derivation='hmac'
 *   hmac    = HMAC-SHA1(key=derived, msg=b64url(json)"."b64url(ts))
 *   salt    = 'cookie-session'(Flask 固定)
 * 压缩格式('.' 开头 + zlib)是老 itsdangerous(<0.18)遗留,仅 decode 支持。
 */
#pragma once

#include <string>

int flaskDecode(const std::string& cookie);
int flaskVerify(const std::string& cookie, const std::string& secret, const std::string& salt);
int flaskSign(const std::string& secret, const std::string& jsonText, const std::string& salt,
              bool legacy);

/**
 * crack:wordlist 与 mask 二选一(mask 优先)。
 * engine: "auto"(GPU 优先回退 CPU)/ "gpu" / "cpu"。
 */
int flaskCrack(const std::string& cookie, const std::string& wordlist, const std::string& mask,
               const std::string& salt, int threads, const std::string& engine);
