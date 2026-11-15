"""Materialize the exact original CI plan once, then exec the reviewed runner."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SPEC = {'actual_pins': {'JOB_ID': '1a1aff8769c-fc05-6d26', 'SOURCE_MAP_SHA': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133', 'ISOLATED_SUMMARY_SHA': '30be482004f6159463564467d52f9088e558318a9408966b938e12cd745ec301', 'ISOLATED_AUDIT_SHA': 'c921ea020eb0d14c8634290cd55aef9e6014f734c95b24e68f2bdb331463c184', 'QUALIFICATION_REPORT_SHA': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437', 'PREPARATION_SHA': 'd76bc4ab72a3c579ee25e5c0381df391e78b6dd046a341b07e1343998829b27e', 'NATIVE_TERMINAL_SHA': 'c06e447a3adf5eb6f8afd0533e898a3f6417ce61d52e0a31b66f5277a991f303', 'PARENT_SHA': '11875566eefa5532495d4411974faa2232a4339d3fd4ee1acae230c7394daba7', 'QUALIFICATION_BINDINGS_SHA': '427096289824d1159887f3bc7533fe8d3e61be055bff918a18b8bab0480a28e5', 'FROZEN_COUNTS': {'passed': 1651, 'failed': 0, 'ignored': 34, 'selected': 1685, 'retries': 0}}, 'qualification_report': {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/report.json', 'bytes': 83976, 'sha256': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437'}, 'tools': {'materialize_rust_ci_plan_01.py': {'bytes': 25720, 'sha256': 'e6ec007f7fa869297cb2b5dacabb9949596f11da02945cc3f2106e6b43d9b700'}, 'run_rust_ci_01.py': {'bytes': 15177, 'sha256': '513dcbaac95d44538e745e37678fc0e5b6e0e4ac26d44eba9477e39292d7a2ff'}, 'audit_nextest_0137.py': {'bytes': 8563, 'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'}, 'canonical-workflow.yml': {'bytes': 7631, 'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'}}, 'manifest': {'bytes': 1952, 'sha256': '4d57f6e5e57208562bee4ab5d8643717fff512e1e55248112171e7254e29642d'}}
ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
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
need(manifest['schema'] == 'hepta-d1-exact-rust-ci-tools/v1' and manifest['attempt'] == '01'
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
