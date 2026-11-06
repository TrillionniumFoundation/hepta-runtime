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
                                   'passed': 1647,
                                   'retries': 0,
                                   'selected': 1681},
                 'ISOLATED_AUDIT_SHA': '6c33faf1b73d34a1a5ac5bcc8e5570c8a409f3fc8adc106321196ea40c4570c7',
                 'ISOLATED_SUMMARY_SHA': '38571b98196196dc7c6af43c61e3cecbb823f22f098353e31e5ee107e4625b41',
                 'JOB_ID': '1a1b1cb4862-fc05-7ad9',
                 'NATIVE_TERMINAL_SHA': 'd064a939e5707b9694a0853b87bd2fff92887966b1daea5b988fe8a5229fc1bb',
                 'PARENT_SHA': '070f53cec7359bfa3f390f45edd135f417d0013dbf091e35dd7334e0cefc0045',
                 'PREPARATION_SHA': '20ae4a6b83454d2079e23f012c62fddcf88434cce488d0935576d5aa83309035',
                 'QUALIFICATION_BINDINGS_SHA': '4e1810535fa9a7e4a2945f962fcbc3b3a1918e88f7e670d44ce2e815a3ba2890',
                 'QUALIFICATION_REPORT_SHA': 'd8af06696cbd7a1bbf0595bf628a18c112e82598cafb1b45b609a7955ced5e08',
                 'SOURCE_MAP_SHA': 'b9eff66ea8b14eca80d16069a59588a551fcf6feff0ac4c991690425df65462a'},
 'manifest': {'bytes': 2192,
              'sha256': '8bc77a3a37a3a1b4fa2c2af3b0b24be384e05907a6f959855b5974732b74a7b9'},
 'qualification_report': {'bytes': 83532,
                          'path': '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/qualification-01/report.json',
                          'sha256': 'd8af06696cbd7a1bbf0595bf628a18c112e82598cafb1b45b609a7955ced5e08'},
 'tools': {'audit_nextest_0137.py': {'bytes': 8563,
                                     'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'},
           'canonical-workflow.yml': {'bytes': 7631,
                                      'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'},
           'materialize_rust_ci_plan_01.py': {'bytes': 25717,
                                              'sha256': '9011fc8425a334157f7e18e3f307e92dffc245a91380135318a0d7ebe1dc9b1a'},
           'run_rust_ci_01.py': {'bytes': 15196,
                                 'sha256': 'f0a89af2ea85bda7007cc74b62a97e578231549ac9f0171e41c84a69510fa4b0'}}}
ROOT = Path('/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02')
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
need(manifest['schema'] == 'hepta-r36-exact-rust-ci-tools/v1' and manifest['attempt'] == '01'
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
