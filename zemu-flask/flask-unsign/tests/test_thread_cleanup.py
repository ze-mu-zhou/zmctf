"""Deterministic thread failure tests for the dedicated ZK_THREAD_TESTING build.

Build with: bash tests/build_thread_tests.sh
Run with: .venv/Scripts/python.exe tests/test_thread_cleanup.py
The production executable has no fault-injection hooks.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from flask.sessions import session_json_serializer
from itsdangerous import URLSafeTimedSerializer

ROOT = Path(__file__).resolve().parents[1]
TOOL = str(ROOT / 'bin' / 'test_thread_cleanup.exe')
serializer = URLSafeTimedSerializer('recovery-key', salt='cookie-session',
    serializer=session_json_serializer,
    signer_kwargs={'key_derivation': 'hmac', 'digest_method': hashlib.sha1})
cookie = serializer.dumps({'x': 1})
recovery = ['flask', 'crack', '--cookie', cookie, '--mask', 'recovery-key',
            '--threads', '1', '--engine', 'cpu']
failures = []
subprocess.run([str(ROOT / 'bin' / 'thread_group_test.exe')], check=True, timeout=15)

def check_failure(name, command, kind, at):
    env = dict(os.environ, ZK_GPUTHRESH='1', ZK_NOPROG='1')
    env.pop('ZK_TEST_THREAD_CREATE_AT', None)
    env.pop('ZK_TEST_THREAD_WORKER_AT', None)
    env['ZK_TEST_THREAD_' + kind + '_AT'] = str(at)
    data = ''.join(json.dumps(c) + '\n' for c in [command, recovery])
    r = subprocess.run([TOOL, 'serve'], input=data, capture_output=True,
                       text=True, encoding='utf-8', env=env, timeout=30)
    lines = r.stdout.splitlines()
    markers = [line for line in lines if line.startswith('<<<zk-rc=')]
    expected = '线程创建失败' if kind == 'CREATE' else '工作线程执行失败'
    ok = (r.returncode == 0 and markers == ['<<<zk-rc=1>>>', '<<<zk-rc=0>>>']
          and expected in r.stdout and lines.count('recovery-key') == 1
          and '跑完未命中' not in r.stdout and '已取消' not in r.stdout)
    print('PASS' if ok else 'FAIL', name, kind, at)
    if not ok:
        failures.append(name)
        print(r.stdout, r.stderr)

with tempfile.TemporaryDirectory(prefix='zemu-thread-test-') as tmp:
    dictionary = Path(tmp) / 'words.txt'
    dictionary.write_text('wrong-key\n' * 200000, encoding='utf-8')
    for mode, args in [('mask', ['--mask', '?d' * 10]),
                       ('dictionary', ['--wordlist', str(dictionary)])]:
        cpu = ['flask', 'crack', '--cookie', cookie, *args, '--threads', '2', '--engine', 'cpu']
        for kind in ['CREATE', 'WORKER']:
            for at in [1, 2]:
                check_failure('cpu-' + mode, cpu, kind, at)
        hybrid = cpu[:-1] + ['auto']
        # Mask: coordinator then CPU pool. Dictionary: two packing passes
        # (2 threads each), coordinator, then CPU pool. Includes partial creation.
        for kind in ['CREATE', 'WORKER']:
            for at in (range(1, 4) if mode == 'mask' else range(1, 8)):
                check_failure('hybrid-' + mode, hybrid, kind, at)

sys.exit(1 if failures else 0)
