# -*- coding: utf-8 -*-
"""无回显SSTI测试靶机：POST / 的code参数进render_template_string，
渲染结果只print到控制台，不写入响应（响应固定为"OK"）。
Flask默认提供/static/静态文件访问。
"""
import os
from pathlib import Path

from flask import Flask, request, render_template_string

# 保证static目录指向本文件所在目录下的static/
os.chdir(Path(__file__).parent)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    code = request.values.get("code", "")
    if code:
        try:
            result = render_template_string(code)
            print("[render]", result, flush=True)  # 只打印，不回显
        except Exception as e:  # pylint: disable=broad-except
            print("[render error]", e, flush=True)
    return "OK"


@app.route("/echo_cookie")
def echo_cookie():
    """回显请求携带的Cookie，仅用于测试session复用"""
    return request.headers.get("Cookie", "")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8001)
