# -*- coding: utf-8 -*-
"""smoke 测试: 朴素 / 插件直用 / plan z3 规划 / 错误路径 / 旧接口回归。"""
import ast
import contextlib
import io
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pkfn import dumps_cmd, dumps, dis, _Compiler, _compile
from plugins import find_class_blacklist_bypass as bypass

CMD = 'cmd /c echo pkfn-ok'
# dumps_cmd 走 subprocess.getoutput: 自带 shell, 返回 str。
# Windows 下 shell=True 会经 cmd /c "CMD" 双层包装, 输出尾部多一个 "
# (cmd 的引号保留规则); POSIX shell 目标无此现象。期望输出即 'pkfn-ok"'。
PASS = []


def check(name, cond, extra=''):
    status = 'PASS' if cond else 'FAIL'
    PASS.append(cond)
    print('[%s] %s %s' % (status, name, extra))


def refs_of(payload):
    """静态提取 payload 里所有 find_class 可见的 (module, name)。
    用 pickletools 走完整条 opcode 流, 不执行 payload, 结果是完整列表
    (不受运行时 dummy 对象断链影响)。"""
    import pickletools
    refs = []
    stack = []
    mark = object()
    sent = object()                     # 非字符串的栈上对象
    for op, arg, _pos in pickletools.genops(payload):
        n = op.name
        if n in ('GLOBAL', 'INST'):     # c / i opcode: arg 为 module 和 name
            refs.append(tuple(arg.split('\n')) if '\n' in arg
                        else tuple(arg.split(' ', 1)))
            stack.append(sent)          # GLOBAL 结果入栈
        elif n == 'STACK_GLOBAL':       # \x93: 栈顶 name, 其次 module
            name, module = stack.pop(), stack.pop()
            refs.append((module, name))
            stack.append(sent)
        elif n == 'MARK':
            stack.append(mark)
        elif n in ('TUPLE', 'LIST', 'DICT'):
            while stack[-1] is not mark:
                stack.pop()
            stack.pop()
            stack.append(sent)
        elif n in ('TUPLE1', 'TUPLE2', 'TUPLE3'):
            del stack[-int(n[-1]):]
            stack.append(sent)
        elif n == 'REDUCE':
            stack.pop()                 # args
            stack.pop()                 # callable
            stack.append(sent)
        elif n in ('NEWOBJ', 'NEWOBJ_EX'):
            stack.pop()                 # args (NEWOBJ_EX 另有 kwargs, 本框架不发)
            stack.pop()                 # cls
            stack.append(sent)
        elif n == 'BUILD':
            stack.pop()                 # state dict
            stack.pop()                 # obj
            stack.append(sent)
        elif n == 'SETITEM':
            stack.pop()                 # value
            stack.pop()                 # key
            stack.pop()                 # dict
        elif n == 'POP':
            stack.pop()
        elif n == 'DUP':
            stack.append(stack[-1])
        elif n in ('PROTO', 'FRAME', 'STOP', 'PUT', 'BINPUT', 'LONG_BINPUT',
                   'MEMOIZE'):
            pass                        # memo 写入 / 协议头, 不改变值栈
        else:
            # 常量 / 空容器 / GET(memo 读取) 等 push: 只关心字符串
            stack.append(arg if isinstance(arg, str) else sent)
    return refs


def run(name, plugins=(), bl=None, match='exact'):
    if bl is not None:
        plugins = (bypass.plan(bl, match=match),)
    payload = dumps_cmd(CMD, plugins=plugins)
    out = pickle.loads(payload)
    check(name, out == 'pkfn-ok"', '-> %r' % out)
    return payload


# 1. 朴素直通
p = run('plain (no plugin)')
check('plain refs', ('importlib', 'import_module') in refs_of(p)
      and ('builtins', 'getattr') in refs_of(p))

# 2. 模块级插件直用 (importlib 通道 + DottedGlobalCompiler)
run('plugin default (bypass)')

# 3. use() 指定通道
sc_idx = next(i for i, c in enumerate(().__class__.__base__.__subclasses__())
              if c.__name__ == 'catch_warnings')
use_cases = [
    'importlib', 'sys_modules', 'sys_direct', 'builtins_dict',
    'func_globals', 'func_globals_json', 'func_globals_re',
    'func_globals_base64', 'func_globals_functools', 'func_globals_copy',
    'func_globals_os', 'func_globals_shutil', 'func_globals_tempfile',
    'func_globals_warnings', 'func_globals_contextlib', 'func_globals_textwrap',
    'func_globals_posixpath', 'func_globals_urllib', 'func_globals_string',
]
for strat in use_cases:
    run('use(%r)' % strat, plugins=[bypass.use(strat)])
run('use(func_subclasses)', plugins=[bypass.use('func_subclasses',
                                                 index=sc_idx)])

# 3b. 新通道的 refs 画像: operator-free / 零模块名验证
p = dumps_cmd(CMD, plugins=[bypass.use('sys_direct')])
refs = refs_of(p)
check('sys_direct refs', all(r[0] == 'sys' for r in refs), 'refs=%s' % refs)
p = dumps_cmd(CMD, plugins=[bypass.use('builtins_dict')])
refs = refs_of(p)
check('builtins_dict refs', all(r[0] == 'builtins' for r in refs),
      'refs=%s' % refs)
p = dumps_cmd(CMD, plugins=[bypass.use('importlib')])
refs = refs_of(p)
check('importlib refs', ('importlib', 'import_module') in refs
      and ('builtins', 'getattr') in refs, 'refs=%s' % refs)
p = dumps_cmd(CMD, plugins=[bypass.use('func_subclasses', index=sc_idx)])
refs = refs_of(p)
check('func_subclasses refs', all(r[0] == 'operator' for r in refs),
      'refs=%s' % refs)

# 3c. 每条通道声明的 refs 必须覆盖静态扫描出的全部 refs (规划正确性依赖)
for ch in bypass.CHANNELS:
    payload = dumps_cmd(CMD, plugins=[bypass.use(ch['name'])])
    scanned = set(refs_of(payload))
    declared = set(ch['refs'])
    check('declared refs cover scanned: %s' % ch['name'],
          scanned <= declared,
          ('missing=%s' % sorted(scanned - declared))
          if not scanned <= declared else
          '%d refs, %d uses' % (len(declared), len(refs_of(payload))))

# 4. plan: 禁 importlib/operator/sys/builtins -> 应选 func_globals (glob)
bl = {'module': {'importlib', 'operator', 'sys', 'builtins'},
      'name': {'getattr', 'modules'}}
p = run('plan -> func_globals', bl=bl)
refs = refs_of(p)
check('func_globals refs', all(r[0] == 'glob' for r in refs), 'refs=%s' % refs)
check('func_globals protocol4', p.startswith(b'\x80\x04'))

# 4b. plan: 再禁 glob -> 应选 func_globals_json
bl = {'module': {'importlib', 'operator', 'sys', 'builtins', 'glob'},
      'name': {'getattr', 'modules'}}
p = run('plan -> func_globals_json', bl=bl)
refs = refs_of(p)
check('func_globals_json refs', all(r[0] == 'json' for r in refs),
      'refs=%s' % refs)

# 5. plan: 黑名单全空 -> 选代价最小的 importlib
p = run('plan empty blacklist', bl={})
check('empty-bl refs', ('importlib', 'import_module') in refs_of(p))

# 6. plan: substring 匹配 -> name 黑名单覆盖全部通道的 refs 子串 -> 全死
try:
    dumps_cmd(CMD, plugins=[bypass.plan(
        {'name': {'__globals__', 'import_module', '__import__', '__dict__',
                  'modules', 'attrgetter', 'itemgetter'}},
        match='substring')])
    check('substring blocked -> error', False)
except bypass.PlanningError as e:
    check('substring blocked -> error', True, str(e).splitlines()[0])

# 7. plan: 所有种子/依赖模块全禁 -> 无解报错
try:
    dumps_cmd(CMD, plugins=[bypass.plan({'module': {
        'importlib', 'operator', 'sys', 'builtins',
        'glob', 'json', 're', 'base64', 'functools', 'copy',
        'os', 'shutil', 'tempfile', 'warnings', 'contextlib', 'textwrap',
        'posixpath', 'urllib.request', 'string'}})])
    check('all blocked -> error', False)
except bypass.PlanningError as e:
    msg = str(e)
    check('all blocked -> error', True, msg.splitlines()[0])

# 7b. 除 operator 外全禁 -> func_subclasses 不进自动规划, 同样无解;
#     include_manual=True 时才会选中它
bl = {'module': {
    'importlib', 'sys', 'builtins',
    'glob', 'json', 're', 'base64', 'functools', 'copy',
    'os', 'shutil', 'tempfile', 'warnings', 'contextlib', 'textwrap',
    'posixpath', 'urllib.request', 'string'}}
try:
    dumps_cmd(CMD, plugins=[bypass.plan(bl)])
    check('plan excludes func_subclasses', False)
except bypass.PlanningError:
    check('plan excludes func_subclasses', True)
pl = bypass.plan(bl, include_manual=True)
check('include_manual -> func_subclasses',
      pl._channel['name'] == 'func_subclasses', repr(pl))

# 8. 长命令 (>255 字节) -> BINUNICODE
long_cmd = 'cmd /c echo ' + 'A' * 400
payload = dumps_cmd(long_cmd, plugins=[bypass.use('func_globals')])
out = pickle.loads(payload)
check('long command', out == 'A' * 400 + '"')

# 9. 旧接口回归: dumps(fn) 仍然工作
def exp():
    import os
    return os.system('echo legacy-ok')

payload = dumps(exp)
check('legacy dumps()', b'cos\nsystem' in payload or b'os\nsystem' in payload,
      repr(payload[:30]))

# 10. dis 可用
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    dis(exp)
check('legacy dis()', 'GLOBAL' in buf.getvalue() or 'global' in buf.getvalue())

# 11. letter_filter: 统一入口 lf.dumps_cmd, letters 驱动自动选型
from plugins import letter_filter as lf

WORDS = (b'subprocess', b'check_output', b'getoutput', b'pkfn-ok',
         b'importlib', b'import_module', b'getattr', b'attrgetter',
         b'itemgetter', b'operator', b'builtins', b'glob')

# 11a. 无约束 -> 朴素直通 (明文, 不转义)
p = lf.dumps_cmd(CMD)
check('lf plain exec', pickle.loads(p) == 'pkfn-ok"')
check('lf plain is plaintext', b'subprocess' in p)

# 11b. 禁字母 's' -> oct 通道 (代价最小: importlib), 零明文单词
p = lf.dumps_cmd(CMD, letters='s')
check('lf letters=s exec', pickle.loads(p) == 'pkfn-ok"')
leaked = [w for w in WORDS if w in p]
check('lf letters=s no plaintext', not leaked, 'leaked=%s' % leaked)
check('lf letters=s no s in payload', b's' not in p)

# 11c. 仅 find_class 黑名单 -> oct + 通道规划 (json 种子)
bl = {'module': {'importlib', 'operator', 'sys', 'builtins', 'glob'},
      'name': {'getattr', 'modules'}}
p = lf.dumps_cmd(CMD, blacklist=bl)
check('lf bl exec', pickle.loads(p) == 'pkfn-ok"')
refs = refs_of(p)
check('lf bl refs', all(r[0] == 'json' for r in refs), 'refs=%s' % refs)

# 11d. 禁 p/g/t (oct 的 memo opcode) -> az
p = lf.dumps_cmd(CMD, letters='pgt')
check('lf letters=pgt -> az exec', pickle.loads(p) == 'pkfn-ok"')
check('lf letters=pgt refs', refs_of(p) == [('subprocess', 'getoutput')],
      'refs=%s' % refs_of(p))

# 12. 禁全部小写 -> az, 零小写字节
p = lf.dumps_cmd(CMD, letters='abcdefghijklmnopqrstuvwxyz')
check('lf a-z exec', pickle.loads(p) == 'pkfn-ok"')
check('lf a-z zero lowercase', not any(0x61 <= b <= 0x7a for b in p))

# 12b. 禁小写 + 禁 subprocess -> az 换 exec 目标
p = lf.dumps_cmd('cmd /c rem pkfn', letters='abcdefghijklmnopqrstuvwxyz',
                 blacklist={'module': {'subprocess'}})
check('lf a-z bl -> system exec', pickle.loads(p) == 0)
check('lf a-z bl refs', refs_of(p) == [('os', 'system')],
      'refs=%s' % refs_of(p))

# 13. 禁 R/i/o/b (opcode 级) -> nor (NEWOBJ 调用链)
p = lf.dumps_cmd(CMD, letters='Riob')
out = pickle.loads(p)
check('lf nor exec', out == (0,), '-> %r' % (out,))
check('lf nor no banned bytes',
      not any(x in p for x in (b'R', b'i', b'o', b'b')))
# 模拟题目 replace 后的检查 (本 payload 不依赖替换也能过)
a = p.replace(b'builtin', b'BuIltIn').replace(b'os', b'Os').replace(b'bytes',
                                                                      b'Bytes')
check('lf nor challenge-style check',
      not any(x in a for x in (b'R', b'i', b'o', b'b')))
check('lf nor refs',
      refs_of(p) == [('builtins', 'tuple'), ('builtins', 'map'),
                     ('builtins', 'eval')],
      'refs=%s' % refs_of(p))

# 13b. 禁 R/i/o/b + 禁 builtins -> 无解, 报告标明死因
try:
    lf.dumps_cmd(CMD, letters='Riob', blacklist={'module': {'builtins'}})
    check('lf impossible -> error', False)
except lf.PlanningError as e:
    msg = str(e)
    check('lf impossible -> error', True, msg.splitlines()[0])

# 13c. 非 ASCII 命令 -> ValueError
try:
    lf.dumps_cmd(u'echo 中文', letters='s')
    check('lf non-ASCII -> error', False)
except ValueError:
    check('lf non-ASCII -> error', True)

# 13d. code= 参数: 锁定 nor, 自定义 eval 表达式
p = lf.dumps_cmd('', letters='Riob', code='1+1')
check('lf code= exec', pickle.loads(p) == (2,))
check('lf code= no banned bytes',
      not any(x in p for x in (b'R', b'i', b'o', b'b')))
p = lf.dumps_cmd('', code='len("abc")')   # 无 letters 也锁定 nor
check('lf code= no-letters exec', pickle.loads(p) == (3,))
try:
    lf.dumps_cmd('', letters='RiobS', code='1+1')   # nor 也死 -> 无解
    check('lf code= impossible -> error', False)
except lf.PlanningError:
    check('lf code= impossible -> error', True)

# 14. 禁 \ 和 ' (杀转义) -> chr (码点经 INT 重建, 零转义字符)
p = lf.dumps_cmd(CMD, letters="\\'")
check('lf chr exec', pickle.loads(p) == 0)
check('lf chr no escape chars',
      not any(x in p for x in (b'\\', b"'", b'S')))
check('lf chr refs',
      refs_of(p) == [('builtins', 'eval'), ('builtins', 'bytes')],
      'refs=%s' % refs_of(p))

# 14b. 仅禁 S -> chr
p = lf.dumps_cmd(CMD, letters='S')
check('lf letters=S -> chr exec', pickle.loads(p) == 0)
check('lf letters=S no S byte', b'S' not in p)

# 14c. code= + 杀转义 -> chr 档自定义表达式
p = lf.dumps_cmd('', letters="\\'", code='1+1')
check('lf chr code= exec', pickle.loads(p) == 2)

# 14d. chr 档支持非 ASCII 命令 (utf-8 码点)
p = lf.dumps_cmd('', letters="\\'", code=u'len("中文")')
check('lf chr utf-8 exec', pickle.loads(p) == 2)

# 15. 审核修复回归
# 15a. kwargs / 多目标赋值 / 相对导入 -> SyntaxError; star import 同样拒绝
def _exp_kw():
    import subprocess
    return subprocess.getoutput('cmd /c echo x', encoding='ascii')

def _exp_mt():
    a = b = 1
    return a

def _exp_rel():
    from . import os
    return 1

for _name, _fn in [('kwargs', _exp_kw), ('multi-target', _exp_mt),
                   ('relative import', _exp_rel)]:
    try:
        dumps(_fn)
        check('reject %s' % _name, False)
    except SyntaxError:
        check('reject %s' % _name, True)
try:
    # from x import * 在函数里是编译期 SyntaxError, 只能经 ast + _compile 测
    _fn_node = ast.parse('def exp():\n    from os import *\n    return 1\n').body[0]
    _compile(list(_fn_node.body), [])
    check('reject star import', False)
except SyntaxError:
    check('reject star import', True)

# 15b. 非 ASCII 命令 (朴素路径) -> 编译期 ValueError
try:
    dumps_cmd(u'echo 中文')
    check('plain non-ASCII -> error', False)
except ValueError:
    check('plain non-ASCII -> error', True)

# 15c. 属性赋值: dict-state BUILD + POP (栈平衡)
def _exp_attr():
    import types
    o = types.SimpleNamespace()
    o.a = 41
    return o.a

p = dumps(_exp_attr)
check('attr assign exec', pickle.loads(p) == 41)
check('attr assign balanced', b'db0' in p)

# 15d. alphabet 建模: 禁 \n -> 全灭无解; 禁 \x04 -> chr 存活
try:
    lf.dumps_cmd(CMD, letters=b'\n')
    check('ban newline -> error', False)
except lf.PlanningError:
    check('ban newline -> error', True)
p = lf.dumps_cmd(CMD, letters=b'\x04')
check('ban 0x04 -> chr exec', pickle.loads(p) == 0)
check('ban 0x04 no 0x04 byte', b'\x04' not in p)

# 15e. 黑名单空串 -> ValueError
try:
    lf.dumps_cmd(CMD, blacklist={'name': {''}})
    check('empty blacklist entry -> error', False)
except ValueError:
    check('empty blacklist entry -> error', True)

# 15f. letters 非法入参 -> ValueError
for _bad in (['R', 'i'], 5, u'é'):
    try:
        lf.dumps_cmd(CMD, letters=_bad)
        check('bad letters %r -> error' % (_bad,), False)
    except ValueError:
        check('bad letters %r -> error' % (_bad,), True)

# 15g. oct 通道运行时方法调用: 零明文单词
def _exp_meth():
    s = 'ab'
    return s.upper()

p = dumps(_exp_meth, plugins=[lf._OctPlugin(bypass.CHANNELS[0])])
check('oct method call exec', pickle.loads(p) == 'AB')
check('oct method call no plaintext',
      b'operator' not in p and b'attrgetter' not in p)

# 15h. verify=False: 编译期不可 import 的模块按首段发码
def _exp_fake():
    return fake_module.fake_attr

p = dumps(_exp_fake, plugins=[bypass.compiler_plugin(verify=False)])
check('verify=False unimportable module', b'fake_module' in p)

print()
print('ALL PASS' if all(PASS) else 'SOME FAILED: %d/%d'
      % (sum(PASS), len(PASS)))
sys.exit(0 if all(PASS) else 1)
