"""Materialize the exact original CI plan once, then exec the reviewed runner."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SPEC = {'actual_pins': {'JOB_ID': '1a1b0cc0f51-fc05-7301', 'SOURCE_MAP_SHA': '4bdbae5e8dea5d7534b5bde6961b44eaeaf5524553a788e171fee9fb2ecf5209', 'ISOLATED_SUMMARY_SHA': '8a5707ab41ba7b427568edfc18d2653edf28980cff69fd73fbffa6bb5437ff3b', 'ISOLATED_AUDIT_SHA': '5351b3f2e42788a364a876627cae16c4aa9a5b82b2f13ba3d76571ec8e6caa40', 'QUALIFICATION_REPORT_SHA': '1cc52b4a0a86719c2da933872046d52ff42a21dcabb4ff59a21f440bbb5b9702', 'PREPARATION_SHA': '0588e6b5e840a3f42ab520bb53b1fd2d440e0bd44ee9dc7febd2a0813256da7b', 'NATIVE_TERMINAL_SHA': '4b268e9d34b0e85e727a07e1586e772a1ee9a91c02a32a13f49332a815c9c1cf', 'PARENT_SHA': '2a04eb862c4efe1377a3b78dad33b99f43573d7c91dc66503ad5f08690b17da9', 'QUALIFICATION_BINDINGS_SHA': '5a65dfb879fa0d6aa0b12640657f6947c6317e11deaabe9a66d7c4e950811580', 'FROZEN_COUNTS': {'passed': 1651, 'failed': 0, 'ignored': 34, 'selected': 1685, 'retries': 0}}, 'qualification_report': {'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-01/report.json', 'bytes': 84034, 'sha256': '1cc52b4a0a86719c2da933872046d52ff42a21dcabb4ff59a21f440bbb5b9702'}, 'tools': {'materialize_rust_ci_plan_01.py': {'bytes': 25732, 'sha256': '949051443631877d81bbe6b9d55b0d3d3d05c0c6825e2df311c62a82a6b016e4'}, 'run_rust_ci_01.py': {'bytes': 15182, 'sha256': 'ba44655087b3ab674425f5cd3c78a5e43414a60a608c60b791ab9d2129740660'}, 'audit_nextest_0137.py': {'bytes': 8563, 'sha256': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2'}, 'canonical-workflow.yml': {'bytes': 7631, 'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'}}, 'manifest': {'bytes': 1957, 'sha256': '52c512b3d947c0c1b2bab1b8e8b1db77e7c60bdd41bf72cc935cf0ef73cb63d3'}}
ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
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
need(manifest['schema'] == 'hepta-d2-exact-rust-ci-tools/v1' and manifest['attempt'] == '01'
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
