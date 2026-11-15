"""Materialize the exact original CI plan once, then exec the reviewed runner."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SPEC = {'actual_pins': {'FROZEN_COUNTS': {'failed': 0,
                                   'ignored': 34,
                                   'passed': 1653,
                                   'retries': 0,
                                   'selected': 1687},
                 'ISOLATED_AUDIT_SHA': '7bbf25dd68f4eeb153775de0bac509869bc1903f7326a9dda3ac3fe4e97355b2',
                 'ISOLATED_SUMMARY_SHA': 'e55dbd56b9d8f74a4cbd4d848043fdfbf3b3ee27fdf7fe8b68299753003f4779',
                 'JOB_ID': '1a1aef7882f-fc05-6499',
                 'NATIVE_TERMINAL_SHA': '0be0d08ef301d3a119d307940f324e52b6b6c8b29fbf94ad6ee69fca2637c14c',
                 'PARENT_SHA': 'c7508892959e9393f7ade10948ef7a96a18f1930d7308e293b74a321435f4cee',
                 'PREPARATION_SHA': '16193325e19f7025631a2802d6322c332a1b79eb6c6b2c2112740c4e602d9db6',
                 'QUALIFICATION_BINDINGS_SHA': '080da4f9cddb07d8ccb8eafa48edd18bc6f875b4d0ec497d8936f7db5ce8cde9',
                 'QUALIFICATION_REPORT_SHA': 'a63cdd8cdcb5d6844d3f2ae5cf53e11e041f43a74278a5dd2a6fe2f9b7246e8a',
                 'SOURCE_MAP_SHA': '13cc2b374aff950e840b1d6914b70b92380cbe625f70d6002f6231e260d0de0d'},
 'manifest': {'bytes': 2122,
              'sha256': 'e0430679ea6622b17de8e42a317be0633b69e28175449c8a6ab33f5164ea0ee9'},
 'qualification_report': {'bytes': 83362,
                          'path': '/home/qian/hepta-runtime-optimization-20261106-r34/qualification-01/report.json',
                          'sha256': 'a63cdd8cdcb5d6844d3f2ae5cf53e11e041f43a74278a5dd2a6fe2f9b7246e8a'},
 'tools': {'audit_nextest_0137.py': {'bytes': 8563,
                                     'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'},
           'canonical-workflow.yml': {'bytes': 7631,
                                      'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'},
           'materialize_rust_ci_plan_01.py': {'bytes': 25727,
                                              'sha256': '2facb83365fd2172d1aaf6c41fd6d3f1ca3c0f2685fa2bbfa46d2de0c3aacae8'},
           'run_rust_ci_01.py': {'bytes': 15182,
                                 'sha256': '908f78d284d84935d5b3efecfe8b3be7bbaaf5893e51107c11cdd8b770d2159b'}}}
ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r34')
TOOLS = ROOT / 'rust-ci-tools-01'
PLAN = ROOT / 'rust-ci-plan-01.json'
OUT = ROOT / 'rust-ci-01'
CI_MANIFEST = Path('/home/qian/hepta-runtime-optimization-20261105-r25/ci-gates/ci-gate-manifest.json')
SELF = TOOLS / 'launch_exact_rust_ci_01.py'
NAMES = {'materialize_rust_ci_plan_01.py', 'run_rust_ci_01.py', 'audit_nextest_0137.py', 'canonical-workflow.yml'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def raw(path):
    need(path.resolve(strict=True) == path, 'indirect reviewed input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and 0 < before.st_size <= 16 * 1024 * 1024, 'unsafe or oversized reviewed input')
        body = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(len(body) == before.st_size and all(getattr(before, k) == getattr(after, k)
         == getattr(path.lstat(), k) for k in fields), 'reviewed input changed during read')
    return body


def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


need(type(SPEC) is dict, 'actual qualification package is not bound')
need(sys.platform == 'linux' and os.geteuid() != 0 and Path(__file__).resolve() == SELF,
     'fixed native Linux CI launcher required')
need(len(sys.argv) == 3 and sys.argv[1] == '--launcher-sha256'
     and hashlib.sha256(raw(SELF)).hexdigest() == sys.argv[2], 'actual launcher identity differs')
need(TOOLS.resolve(strict=True) == TOOLS and not os.path.lexists(PLAN) and not os.path.lexists(OUT),
     'fresh plan/output paths required; original CI must not be replayed')
need({p.name for p in TOOLS.iterdir()} == NAMES | {'package-manifest-01.json', SELF.name},
     'fixed six-file tool inventory differs')
manifest_raw = raw(TOOLS / 'package-manifest-01.json')
need(identity(manifest_raw) == SPEC['manifest'], 'frozen tool manifest differs')
manifest = json.loads(manifest_raw)
need(manifest['schema'] == 'hepta-r34-exact-rust-ci-tools/v1' and manifest['attempt'] == '01'
     and manifest['actual_qualification_job_id'] == SPEC['actual_pins']['JOB_ID']
     and manifest['qualification_report'] == SPEC['qualification_report']
     and manifest['executed'] is False and manifest['hosted_actions_passed'] is False
     and manifest['files'] == SPEC['tools'] and set(manifest['files']) == NAMES,
     'actual qualification/tool manifest binding differs')
for name, expected in SPEC['tools'].items():
    need(identity(raw(TOOLS / name)) == expected, 'reviewed tool differs: ' + name)
command = ['/usr/bin/python3', '-I', '-B', str(TOOLS / 'materialize_rust_ci_plan_01.py'),
    '--qualification-sha256', SPEC['actual_pins']['QUALIFICATION_REPORT_SHA'],
    '--terminal-status-sha256', SPEC['actual_pins']['NATIVE_TERMINAL_SHA'],
    '--ci-manifest', str(CI_MANIFEST), '--out', str(PLAN)]
print(json.dumps({'phase': 'materialize', 'automatic_retries': 0,
                  'qualification_job_id': SPEC['actual_pins']['JOB_ID'],
                  'tools_manifest_sha256': SPEC['manifest']['sha256']}), flush=True)
result = subprocess.run(command, cwd=ROOT, timeout=300)
if result.returncode != 0:
    raise SystemExit(result.returncode)
plan_sha = hashlib.sha256(raw(PLAN)).hexdigest()
need(identity(raw(TOOLS / 'package-manifest-01.json')) == SPEC['manifest'], 'manifest changed during materialization')
for name, expected in SPEC['tools'].items():
    need(identity(raw(TOOLS / name)) == expected, 'tool changed during materialization: ' + name)
need(hashlib.sha256(raw(SELF)).hexdigest() == sys.argv[2], 'launcher changed during materialization')
print(json.dumps({'phase': 'execute_original_ci', 'plan_sha256': plan_sha, 'automatic_retries': 0}), flush=True)
sys.stdout.flush()
sys.stderr.flush()
os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', '-B', str(TOOLS / 'run_rust_ci_01.py'),
    '--plan', str(PLAN), '--plan-sha256', plan_sha,
    '--materializer-sha256', SPEC['tools']['materialize_rust_ci_plan_01.py']['sha256'],
    '--auditor-sha256', SPEC['tools']['audit_nextest_0137.py']['sha256']])
