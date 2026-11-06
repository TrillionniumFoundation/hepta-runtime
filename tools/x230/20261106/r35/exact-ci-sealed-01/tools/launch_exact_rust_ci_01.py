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
                                   'passed': 1645,
                                   'retries': 0,
                                   'selected': 1679},
                 'ISOLATED_AUDIT_SHA': 'cdd5497f7646ddca0ba028cf2d93d4df76c737a87569e19e9596625620397894',
                 'ISOLATED_SUMMARY_SHA': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904',
                 'JOB_ID': '1a1af619097-fc05-6813',
                 'NATIVE_TERMINAL_SHA': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844',
                 'PARENT_SHA': '3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c',
                 'PREPARATION_SHA': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc',
                 'QUALIFICATION_BINDINGS_SHA': 'f9f0872c0b325809a2e0712537f173e8d7f1cac128ffdd54be11b6ad279a9e81',
                 'QUALIFICATION_REPORT_SHA': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1',
                 'SOURCE_MAP_SHA': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313'},
 'manifest': {'bytes': 2122,
              'sha256': 'f4f7734a14bd8c886a126d911e030d956c22ef9d08e37ea329f4bf3b989ba568'},
 'qualification_report': {'bytes': 83363,
                          'path': '/home/qian/hepta-runtime-optimization-20261106-r35/qualification-01/report.json',
                          'sha256': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1'},
 'tools': {'audit_nextest_0137.py': {'bytes': 8563,
                                     'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'},
           'canonical-workflow.yml': {'bytes': 7631,
                                      'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'},
           'materialize_rust_ci_plan_01.py': {'bytes': 25727,
                                              'sha256': '506a15cf4a73197e19025ff4413ec3f7a021e80f806064d9af58f90b85a68c2f'},
           'run_rust_ci_01.py': {'bytes': 15182,
                                 'sha256': '73762b3141daa33a8a90e332fa58ff898ad4608752bc0601c267dfabd36d2c79'}}}
ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
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
need(manifest['schema'] == 'hepta-r35-exact-rust-ci-tools/v1' and manifest['attempt'] == '01'
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
