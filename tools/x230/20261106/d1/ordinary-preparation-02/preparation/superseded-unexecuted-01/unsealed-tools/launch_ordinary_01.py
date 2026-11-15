#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""After real Q and exact CI closure, exec the original qualifier with its three all-features flags removed."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tomllib
import types

SPEC = None
ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
TOOLS = ROOT / 'ordinary-tools-01'
SELF = TOOLS / 'launch_ordinary_01.py'
OUT = ROOT / 'ordinary-01'
PLAN = ROOT / 'ordinary-plan-01.json'
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
ORIGINAL_QUALIFIER_SHA = '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'
ORDINARY_QUALIFIER_SHA = '7b84265d7cbccab2ed22e6471e38252c441a9df3e4148db8c392abf898fa07a3'
DIAGNOSTIC_ENV = ('HEPTA_RUNTIME_PHASE_COST_MODE', 'HEPTA_RUNTIME_PHASE_COST_OUTPUT',
                  'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256')

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


need(type(SPEC) is dict and SPEC.get('sealed') is True, 'actual Q plus exact-CI prerequisites are not bound')
need(sys.platform == 'linux' and os.geteuid() != 0 and Path(__file__).resolve() == SELF,
     'fixed native Linux ordinary launcher required')
need(len(sys.argv) == 3 and sys.argv[1] == '--launcher-sha256'
     and hashlib.sha256(raw(SELF)).hexdigest() == sys.argv[2], 'actual launcher identity differs')
need(all(name not in os.environ for name in DIAGNOSTIC_ENV), 'diagnostic runtime environment must be absent')
need(not os.path.lexists(PLAN) and not os.path.lexists(OUT), 'original ordinary attempt must not be replayed')
need((ROOT / 'target-build').is_dir() and (ROOT / 'target-build').resolve() == ROOT / 'target-build',
     'reuse only the existing independent D1 build target')
need({p.name for p in TOOLS.iterdir()} == {'launch_ordinary_01.py', 'qualify_ordinary_01.py',
     'verify_ordinary_01.py', 'package-manifest-01.json'},
     'ordinary tool inventory differs')
manifest_raw = raw(TOOLS / 'package-manifest-01.json')
need(identity(manifest_raw) == SPEC['manifest'], 'ordinary manifest differs')
manifest = json.loads(manifest_raw)
need(manifest['schema'] == 'hepta-d1-ordinary-tools/v1' and manifest['sealed'] is True,
     'sealed ordinary tool manifest required')
ordinary = raw(TOOLS / 'qualify_ordinary_01.py')
original = raw(ROOT / 'source/tools/x230/20261028/qualify.py')
need(hashlib.sha256(original).hexdigest() == ORIGINAL_QUALIFIER_SHA
     and hashlib.sha256(ordinary).hexdigest() == ORDINARY_QUALIFIER_SHA
     and original.count(b', "--all-features"') == 3
     and ordinary == original.replace(b', "--all-features"', b''),
     'ordinary qualifier must differ by exactly the three removed feature arguments')
need(manifest['qualifier'] == identity(ordinary) and manifest['original_qualifier'] == identity(original),
     'ordinary qualifier derivation binding differs')
foundation_path = Path(SPEC['foundation']['path'])
need(foundation_path == ROOT / 'rust-ci-prerequisites-01/d1_prerequisites.py', 'foundation path differs')
foundation_raw = raw(foundation_path)
need(identity(foundation_raw) == {key: SPEC['foundation'][key] for key in ('bytes', 'sha256')},
     'reviewed full prerequisite foundation differs')
foundation = types.ModuleType('d1_ordinary_prerequisite_only')
foundation.__file__ = str(foundation_path)
exec(compile(foundation_raw, foundation.__file__, 'exec'), foundation.__dict__)
prerequisite_path = Path(SPEC['prerequisites']['path'])
need(prerequisite_path == ROOT / 'ordinary-prerequisites-01.json', 'completed prerequisite path differs')
prerequisite_raw = raw(prerequisite_path)
need(identity(prerequisite_raw) == {key: SPEC['prerequisites'][key] for key in ('bytes', 'sha256')},
     'actual completed Q/CI prerequisites differ')
prerequisites = json.loads(prerequisite_raw)
need(prerequisites['schema'] == 'hepta-d1-c1-prerequisites/v1'
     and prerequisites['qualification_sealed'] is True and prerequisites['exact_ci_sealed'] is True,
     'both original qualification and exact CI must have closed successfully')
bindings = [dict(path=str(foundation_path), **identity(foundation_raw)),
            dict(path=str(prerequisite_path), **identity(prerequisite_raw)),
            dict(path=str(SELF), **identity(raw(SELF))),
            dict(path=str(TOOLS / 'package-manifest-01.json'), **identity(manifest_raw)),
            dict(path=str(TOOLS / 'qualify_ordinary_01.py'), **identity(ordinary)),
            dict(path=str(ROOT / 'source/tools/x230/20261028/qualify.py'), **identity(original))]
def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
    result = foundation.checked(path, expected, maximum, retain)
    bindings.append(result[0] if retain else result)
    return result
proof = foundation.bind_d1_prerequisites(prerequisites, bind)
need(proof['passed'] is True, 'actual completed Q/CI prerequisites did not pass')
qualified_identity, qualified_raw = bind(ROOT / 'qualification-01/report.json', retain=True)
qualified = json.loads(qualified_raw)
map_identity, map_raw = bind(ROOT / 'qualification-01/source-map.json', retain=True)
source_map = json.loads(map_raw)
need(qualified['qualified'] is True and source_map == qualified['source_after'] == qualified['source_tested']
     and len(source_map) == 222, 'current qualified D1 source binding differs')
_, original_cargo_raw = bind(BASE / 'source/Cargo.toml',
                             expected=proof['baseline_compile_inputs']['Cargo.toml'], retain=True)
_, cargo_raw = bind(ROOT / 'source/Cargo.toml', expected=source_map['Cargo.toml'], retain=True)
original_cargo, cargo = tomllib.loads(original_cargo_raw.decode()), tomllib.loads(cargo_raw.decode())
need(original_cargo.get('features', {}) == {} and cargo['features'] == {'phase-cost-diagnostics': []}
     and {k:v for k,v in cargo.items() if k != 'features'} == original_cargo,
     'ordinary package feature set or dependency/default/profile selection changed')
feature_programs = {}
for name, value in qualified['binaries'].items():
    need(Path(value['path']) == ROOT / 'qualification-01' / name, 'feature executable is not the separately preserved original')
    feature_programs[name] = bind(Path(value['path']), expected=value['sha256'])
need(set(feature_programs) == {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'},
     'qualified feature executable inventory differs')
verifier = bind(TOOLS / 'verify_ordinary_01.py', expected=manifest['verifier'])
space = os.statvfs(ROOT)
free_bytes = space.f_bavail * space.f_frsize
need(free_bytes >= 3 * 1024 ** 3, 'the original three-GiB build-space prerequisite is not met')
command = ['/usr/bin/python3', '-B', '-u', str(TOOLS / 'qualify_ordinary_01.py'),
           '--source', str(ROOT / 'source'), '--output', str(OUT), '--target', str(ROOT / 'target-build'),
           '--cargo-home', str(CARGO_HOME), '--jobs', '2']
plan = {'schema': 'hepta-d1-ordinary-supplement-plan/v1', 'executed': False,
        'launcher': dict(path=str(SELF), **identity(raw(SELF))),
        'manifest': dict(path=str(TOOLS / 'package-manifest-01.json'), **identity(manifest_raw)),
        'foundation': dict(path=str(foundation_path), **identity(foundation_raw)),
        'prerequisites': dict(path=str(prerequisite_path), **identity(prerequisite_raw)),
        'source': str(ROOT / 'source'), 'source_files': source_map, 'source_map': map_identity,
        'qualification': qualified_identity, 'qualification_feature_programs': feature_programs,
        'completed_q_and_exact_ci_proof': proof, 'input_bindings': bindings,
        'package_features': [], 'dependency_defaults_changed': False, 'no_default_features_switch': False,
        'original_qualifier': dict(path=str(ROOT / 'source/tools/x230/20261028/qualify.py'), **identity(original)),
        'ordinary_qualifier': dict(path=str(TOOLS / 'qualify_ordinary_01.py'), **identity(ordinary)),
        'exact_removed_arguments': ['--all-features', '--all-features', '--all-features'],
        'free_bytes_before': free_bytes, 'original_free_bytes_threshold': 3 * 1024 ** 3,
        'result_verifier': verifier,
        'command': command, 'output': str(OUT), 'target': str(ROOT / 'target-build'),
        'diagnostic_environment_absent': True, 'feature_executables_preserved_separately': True,
        'original_eight_stages_retained': True, 'automatic_retries': 0,
        'ordinary_native_job_id': None, 'ordinary_result': None, 'ordinary_counts': None,
        'ordinary_release_programs': None, 'performance_acceptance_claim': False}
with PLAN.open('xb') as stream:
    stream.write((json.dumps(plan, indent=2, sort_keys=True) + '\n').encode())
    stream.flush()
    os.fsync(stream.fileno())
for binding in bindings:
    need(foundation.checked(Path(binding['path'])) == binding, 'bound prerequisite changed before ordinary exec')
need(hashlib.sha256(raw(SELF)).hexdigest() == sys.argv[2], 'ordinary launcher changed')
need(identity(raw(TOOLS / 'package-manifest-01.json')) == SPEC['manifest'], 'ordinary manifest changed')
need(all(name not in os.environ for name in DIAGNOSTIC_ENV), 'diagnostic environment changed before ordinary exec')
print(json.dumps({'phase':'execute_original_ordinary_qualification', 'plan_sha256':hashlib.sha256(raw(PLAN)).hexdigest(),
                  'automatic_retries':0, 'preserved_feature_executables':3}), flush=True)
sys.stdout.flush()
sys.stderr.flush()
os.execv('/usr/bin/python3', command)
