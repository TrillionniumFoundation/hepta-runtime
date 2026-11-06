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
                                   'passed': 1649,
                                   'retries': 0,
                                   'selected': 1683},
                 'ISOLATED_AUDIT_SHA': '8704d8609754b10ce148e6e014dd99279b6bb95f88c4ff712191f69f9e58568e',
                 'ISOLATED_SUMMARY_SHA': '352f613378c8e16a5ef23a658ff2692819eefd130ec1ebf079f6672a110ca096',
                 'JOB_ID': '1a1ae8ce865-fc05-603f',
                 'NATIVE_TERMINAL_SHA': 'd342cfc8c9976544f76e7f650ee8108d141a448bfbc7c47880d073e2987ad6f4',
                 'PARENT_SHA': '414337596c5585ec18f0aaa6d38c9bc287724463fee2a385f5ccfcbec414b90c',
                 'PREPARATION_SHA': '63ead27e4e2414be4daa840a5d8f20ce3e7f0f034fd71d66e4ec8b4e9da8c39b',
                 'QUALIFICATION_BINDINGS_SHA': 'b951299d551e522ca23c07d5a7ac376572b735466636d8de3f8137f6f85179eb',
                 'QUALIFICATION_REPORT_SHA': '00aed358a852cbdb9a54b9e97f6a63f66baf28b824dc4383ef900c8125d264a4',
                 'SOURCE_MAP_SHA': 'b3260c858e507f3661da233a9d05fec80399b48ba12fdce250ad29eeca0ba09e'},
 'manifest': {'bytes': 2122,
              'sha256': '8e67ce6dddf43e059eccb8a426143b00b73f12c9d085483f440e09bcac55b648'},
 'qualification_report': {'bytes': 83360,
                          'path': '/home/qian/hepta-runtime-optimization-20261106-r33/qualification-01/report.json',
                          'sha256': '00aed358a852cbdb9a54b9e97f6a63f66baf28b824dc4383ef900c8125d264a4'},
 'tools': {'audit_nextest_0137.py': {'bytes': 8563,
                                     'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'},
           'canonical-workflow.yml': {'bytes': 7631,
                                      'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'},
           'materialize_rust_ci_plan_01.py': {'bytes': 25727,
                                              'sha256': '34429d114a1d33695b04ab64f8b74a26921bff4e2579031dd7562aebcef69169'},
           'run_rust_ci_01.py': {'bytes': 15182,
                                 'sha256': 'bdb64479833a998fa6d8ca6722bd1476af051d61a30716b339a1a60421bacd08'}}}
ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r33')
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
need(manifest['schema'] == 'hepta-r33-exact-rust-ci-tools/v1' and manifest['attempt'] == '01'
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
