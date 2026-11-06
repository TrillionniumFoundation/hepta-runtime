"""Materialize the exact original CI plan once, then exec the reviewed runner."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SPEC = {'actual_pins': {'ISOLATED_AUDIT_SHA': 'c1ab01f10645b23d51926b5f4f65142b3da136cd538e86b93f3c55741a2c895f',
                 'ISOLATED_SUMMARY_SHA': '7e388326114b5be8abfc835cead435de0c597e8b2124442d4e293360937208d6',
                 'JOB_ID': '1a1ae1c32b8-fc05-5d7a',
                 'NATIVE_TERMINAL_SHA': 'f9f6de27c19b015e072f8169e7155783102d9b2ef3bc6ff2d8705927c0016b4e',
                 'PREPARATION_SHA': '77bdf6f1b008b65dfbedcac24b7ea3026e3946ad4fbff68ca96e5980b660d003',
                 'QUALIFICATION_REPORT_SHA': '489e62778972d9a8f4b2908c205b23791a968dbf21dc2bdb995350f29305c5a9',
                 'SOURCE_MAP_SHA': 'a4c654bd8b5057fb6884c36172b198eedcfcddab8e2b291155a4e73146707a3f'},
 'manifest': {'bytes': 2827,
              'sha256': 'dbf43466e09c4c11002aac1e31d6b63c9cc8d7d8cb9a7750924a44905c1235c1'},
 'qualification_report': {'bytes': 84072,
                          'path': '/home/qian/hepta-runtime-optimization-20261105-r31/qualification-01/report.json',
                          'sha256': '489e62778972d9a8f4b2908c205b23791a968dbf21dc2bdb995350f29305c5a9'},
 'tools': {'audit_nextest_0137.py': {'bytes': 8563,
                                     'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'},
           'canonical-workflow.yml': {'bytes': 7631,
                                      'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'},
           'materialize_rust_ci_plan_01.py': {'bytes': 31106,
                                              'sha256': '3419ffbbbc496171455e4b81563acbc92612d3fe18a2c2186331d03121cc24d7'},
           'run_rust_ci_01.py': {'bytes': 15182,
                                 'sha256': 'f9f7298662ba4d36e97aff006f58cf6a192c8c90b32555aaa735d62341430137'}}}
ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
TOOLS = ROOT / 'rust-ci-tools-02'
PLAN = ROOT / 'rust-ci-plan-02.json'
OUT = ROOT / 'rust-ci-02'
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
need(manifest['schema'] == 'hepta-r31-exact-rust-ci-tools/v2' and manifest['attempt'] == '02'
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
