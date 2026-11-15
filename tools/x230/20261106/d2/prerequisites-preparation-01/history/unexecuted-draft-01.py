#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only D2 actual qualification and native exact-CI prerequisite proofs.

The caller first binds immutable foundation JSON. Q-only does not depend on CI.
No compiler, auditor, measurement, cache operation or remote request is started.
Prior D1 ownership is bound to the successful D2 preparation and exact originals;
its pre-rename cache validator is never replayed after the recorded rename.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
SOURCE = ROOT / "source"
QUALIFICATION = ROOT / "qualification-01"
BASE = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
CACHE_OWNER = BASE
MODULE_PATH = ROOT / "full-prerequisites-01/d2_prerequisites.py"
CARGO_HOME = Path("/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02")
NEXTEST_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137")
HEX = re.compile(r"[0-9a-f]{64}\Z")
JOB = re.compile(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}\Z")
BASELINE_COMMIT = '8eb1a0af7a85768e374717d24848fd9798871cc9'
STAGES = ['format',
 'fmt-check',
 'harness-tests',
 'clippy',
 'test-build',
 'isolated-tests',
 'audit-isolated-tests',
 'release']
DIAGNOSTIC_ENV = ('HEPTA_RUNTIME_PHASE_COST_MODE', 'HEPTA_RUNTIME_PHASE_COST_OUTPUT', 'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256')
PINNED = {'cache-owner-closure-inputs.json': {'bytes': 7338,
                                     'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/cache-owner-closure-inputs.json',
                                     'sha256': '425fb3d7e9f30f682720438ca160a728775ae09752076e48833bd893585acc1a'},
 'candidate/baseline-source-map.json': {'bytes': 24368,
                                        'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/baseline-source-map.json',
                                        'sha256': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133'},
 'candidate/candidate-source-map.json': {'bytes': 24368,
                                         'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/candidate-source-map.json',
                                         'sha256': '268e260d777f7cede272c798068c5c765b17052895423eb909d97d3c923921ae'},
 'candidate/candidate.patch': {'bytes': 4524,
                               'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/candidate.patch',
                               'sha256': '56c8bebbe71d9fffde1fe561fa1fdb586251a9db1eccd5a101178fd3316d5e4b'},
 'candidate/input.json': {'bytes': 53275,
                          'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/input.json',
                          'sha256': 'f3d4743ac331e529db92b0a93256dec455c4b8c0788daa6fd88eec4b2982cd99'},
 'candidate/package-manifest.json': {'bytes': 1789,
                                     'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/package-manifest.json',
                                     'sha256': '1bead3d6f37addd4892ccd64d525b70eb047fcf35b0f964627df5f461324575c'},
 'candidate/source/src/mcp/runtime/phase_cost.rs': {'bytes': 24075,
                                                    'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/source/src/mcp/runtime/phase_cost.rs',
                                                    'sha256': '54bda97a2776494927599877728f122f2f26ba3492f9963cbc76f39cf02bb8d5'},
 'candidate/source/src/mcp/runtime/ssh_observation_profile.rs': {'bytes': 26772,
                                                                 'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/source/src/mcp/runtime/ssh_observation_profile.rs',
                                                                 'sha256': '36c81fdaed51a957d1b87f9f3ae9035cc29d1b6dca19112297070d9262ea4717'},
 'candidate/summarize_trace_d2.py': {'bytes': 15070,
                                     'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/candidate/summarize_trace_d2.py',
                                     'sha256': 'ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927'},
 'prepare_qualify.py': {'bytes': 39590,
                        'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/prepare_qualify.py',
                        'sha256': '2e36a1f29f4edd7439c32bc6f6443873dca03d2998381931db67f7034db404fb'},
 'provenance/native-audit-native-read-000.json': {'bytes': 574,
                                                  'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/provenance/native-audit-native-read-000.json',
                                                  'sha256': '079ba103a62a4b3adfb1940a16bb8970f3a99742e05ad2a409123c7c5458ad36'},
 'provenance/native-audit-native.json': {'bytes': 727,
                                         'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/provenance/native-audit-native.json',
                                         'sha256': '701a68d5a28f87b91bc9a5cc459ef4870035f9058910c363005d083c30f1b339'},
 'provenance/native-audit-start.json': {'bytes': 1364,
                                        'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/provenance/native-audit-start.json',
                                        'sha256': '88097e9f08019df73df1efe0ed1c65475b4a6d5cbbe33023dab93e04dc631bde'},
 'qualification-input.json': {'bytes': 3381,
                              'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-input.json',
                              'sha256': 'db42905b89941203e06a3e7335b9e689e551abc02f6c154a0accd6f4a4412e0c'},
 'qualification-package-manifest.json': {'bytes': 2521,
                                         'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/qualification-package-manifest.json',
                                         'sha256': '1c5bf4ab0cba19413c024b5a063407f9fe366c8fac7473d490261d12aabfeaf6'}}
OWNER_INPUTS = {'c1_adapter': {'bytes': 14034,
                'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-adapter-evidence-01/adapter-report.json',
                'sha256': '0f2c2c504e2768b879ab3a2cfa56e21d3b1d28b6f5d7fce4d446e4d3f6abc8e2'},
 'c1_holder': {'bytes': 9216,
               'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-holder-report-01.json',
               'sha256': '641ba56e43d76790cc77bb3df6ee60c510dc2538126b528d2727285ea7762b2c'},
 'c1_native': {'bytes': 726,
               'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-holder-native-01.json',
               'sha256': '48def293f67227758b9844fb5b3bba9e347d7789dce8079a4afb69dcd0fd49a1'},
 'c1_parent': {'bytes': 460195,
               'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-campaign-01/report.json',
               'sha256': '9634d62d7bfd4ded40831306953f7c7cd69d105aedc3087755288069a0ea2990'},
 'c1_read': {'bytes': 1207,
             'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-holder-native-read-01-000.json',
             'sha256': 'ef6c717a16b892eb824696c24f0ff179f676c8ae015a6bc5c816bd5fe2e35a30'},
 'c1_report': {'bytes': 1254435,
               'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01/report.json',
               'sha256': '58303fa9ccc4f9dcb9c4ca4587761ecfdb2f7789fc68446512d163a264667da9'},
 'exact_ci_audit': {'bytes': 719,
                    'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-01/nextest-output-audit.json',
                    'sha256': '101111c3500b8b705e03beb7c7a6ad0101332f02adbf054fb83100cef30574cd'},
 'exact_ci_native': {'bytes': 731,
                     'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-native-01.json',
                     'sha256': '67ea82fa7f6d944bca9c2353f2ec1dba76373b181565b3f19f7a593df1dec85e'},
 'exact_ci_read': {'bytes': 5108,
                   'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-native-read-01.json',
                   'sha256': 'e653fc0f48e2fd76b2004946cb0dcf63c911615b325461a06281152b873bc8ec'},
 'exact_ci_report': {'bytes': 14029,
                     'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-01/report.json',
                     'sha256': 'a6d4675dfa3a35741eeee81896123347c9ad27ede140be42ec10b7ef208e3bc8'},
 'native_audit_native': {'bytes': 727,
                         'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/provenance/native-audit-native.json',
                         'sha256': '701a68d5a28f87b91bc9a5cc459ef4870035f9058910c363005d083c30f1b339'},
 'native_audit_read': {'bytes': 574,
                       'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/provenance/native-audit-native-read-000.json',
                       'sha256': '079ba103a62a4b3adfb1940a16bb8970f3a99742e05ad2a409123c7c5458ad36'},
 'native_audit_report': {'bytes': 51552,
                         'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-offline-interpretation-01/native-independent-summary.json',
                         'sha256': 'd7833ca3b5434de7ccc807ffa13be2ed66fab599ee31df45cd554f83ab83a6db'},
 'native_audit_start': {'bytes': 1364,
                        'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/provenance/native-audit-start.json',
                        'sha256': '88097e9f08019df73df1efe0ed1c65475b4a6d5cbbe33023dab93e04dc631bde'},
 'ordinary_map': {'bytes': 24368,
                  'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-02/source-map.json',
                  'sha256': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133'},
 'ordinary_native': {'bytes': 729,
                     'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-native-02.json',
                     'sha256': '02a5daf8bd346e10e9a2a01ae6a0c3e3d3e3b071ba9743af606e5ab3e86c269a'},
 'ordinary_postflight_native': {'bytes': 729,
                                'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-postflight-native-02.json',
                                'sha256': '3c62cd62bcc84c0a7ab392418eb697003e21b3590b728f7a9e5e1b6b1a8c5bd6'},
 'ordinary_postflight_read': {'bytes': 1230,
                              'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-postflight-native-read-02-000.json',
                              'sha256': '3f898f45c63daf3f486db6698ce6abddeab608f17a516413dd3e684169fb8870'},
 'ordinary_postflight_report': {'bytes': 223078,
                                'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-postflight-02.json',
                                'sha256': 'db8a2cddf7e13b48ad9dbcf8ebdf03664dd604114acb7e36dafe176598b17ed5'},
 'ordinary_read': {'bytes': 3055,
                   'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-native-read-02-000.json',
                   'sha256': 'a9ab2bca707d9f5e184751dda26b8d65b27e724f6a737e0d0f755a517d3849f1'},
 'ordinary_report': {'bytes': 82472,
                     'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-02/report.json',
                     'sha256': '6e14524b1f970efa62bba51873b8ed4db757216ff84eb9958b138ffa90274fce'},
 'qualification_map': {'bytes': 24368,
                       'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/source-map.json',
                       'sha256': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133'},
 'qualification_native': {'bytes': 731,
                          'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-terminal-status-01.json',
                          'sha256': 'c06e447a3adf5eb6f8afd0533e898a3f6417ce61d52e0a31b66f5277a991f303'},
 'qualification_preparation': {'bytes': 103083,
                               'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/preparation.json',
                               'sha256': 'd76bc4ab72a3c579ee25e5c0381df391e78b6dd046a341b07e1343998829b27e'},
 'qualification_read': {'bytes': 3809,
                        'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-native-read-01.json',
                        'sha256': 'f30107c30707be7926ce6e0ae24d743cd2deacee0f78a8d1d30efd4d9f5d3fa8'},
 'qualification_report': {'bytes': 83976,
                          'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/report.json',
                          'sha256': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437'},
 'qualification_summary': {'bytes': 6841,
                           'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/isolated-tests/summary.json',
                           'sha256': '30be482004f6159463564467d52f9088e558318a9408966b938e12cd745ec301'}}
OWNER_JOBS = {'c1_holder': '1a1b0849a11-fc05-7119',
 'exact_ci': '1a1b0238605-fc05-6e78',
 'native_audit': '1a1b09af362-fc05-71a6',
 'ordinary': '1a1b04c6cd1-fc05-6f94',
 'ordinary_postflight': '1a1b06d14dd-fc05-7074',
 'qualification': '1a1aff8769c-fc05-6d26'}
ORIGINAL_MISSING_PATHS = ['/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01/independent-summary.json',
 '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-campaign-01/summary.json']
QUALIFICATION_ARTIFACTS = ['preparation.json',
 'qualification-terminal-status-01.json',
 'qualification-01/report.json',
 'qualification-01/source-map.json',
 'qualification-01/isolated-tests/summary.json',
 'qualification-01/isolated-tests.audit.json']
CI_ARTIFACTS = ['rust-ci-plan-01.json',
 'rust-ci-01/report.json',
 'rust-ci-01/nextest-output-audit.json',
 'rust-ci-native-01.json']
CHANGED = {'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs'}
ADDED = set()
BASELINE_QUALIFICATION = {'bytes': 83976,
 'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-01/report.json',
 'sha256': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437'}
COUNT_KEYS = ('passed', 'failed', 'ignored', 'selected', 'retries')
BINARY_NAMES = ('hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver')
CI_COMMANDS = {'cargo-version': ['cargo', '--version'],
 'rustc-version': ['rustc', '--version'],
 'nextest-version': ['cargo', 'nextest', '--version'],
 'cargo-check': ['cargo', 'check', '--locked', '--all-targets', '--all-features'],
 'nextest-list': ['cargo',
                  'nextest',
                  'list',
                  '--locked',
                  '--all-targets',
                  '--all-features',
                  '--message-format',
                  'json'],
 'nextest-run': ['cargo',
                 'nextest',
                 'run',
                 '--locked',
                 '--all-targets',
                 '--all-features',
                 '--test-threads',
                 '1',
                 '--retries',
                 '0',
                 '--no-fail-fast']}
CI_ENVIRONMENT = {'PATH': '/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137/bin:/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
 'RUSTUP_TOOLCHAIN': '1.95.0',
 'CARGO_HOME': '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
 'CARGO_TARGET_DIR': '/home/qian/hepta-runtime-validation-cost-20261106-d2/target-build',
 'CARGO_BUILD_JOBS': '2',
 'CARGO_INCREMENTAL': '0',
 'CARGO_NET_OFFLINE': 'true',
 'RUST_TEST_THREADS': '1',
 'TOKIO_WORKER_THREADS': '2',
 'PYTHONDONTWRITEBYTECODE': '1',
 'PYTHONNOUSERSITE': '1',
 'CARGO_TERM_COLOR': 'never',
 'NEXTEST_STATUS_LEVEL': 'pass',
 'NEXTEST_FINAL_STATUS_LEVEL': 'fail',
 'NEXTEST_SUCCESS_OUTPUT': 'never'}
NEXTEST_BINARY = {'path': '/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137/bin/cargo-nextest',
 'bytes': 33831936,
 'sha256': '9c05bd3c7c5da1286b193873f12b37db386485fa483d8fa0554e68a53d9df550'}
CANONICAL_WORKFLOW = {'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/rust-ci-tools-01/canonical-workflow.yml',
 'bytes': 7631,
 'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'}
PRIVATE_SOURCE_WORKFLOW = {'path': '/home/qian/hepta-runtime-validation-cost-20261106-d2/source/.github/workflows/ci.yml',
 'bytes': 7235,
 'sha256': '5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d'}

def checked(path, expected=None, maximum=128 * 1024 * 1024, retain=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "indirect input path: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             "unsafe or oversized file: " + str(path))
        chunks, count, digest = [], 0, hashlib.sha256()
        while count <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
            if retain:
                chunks.append(block)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: tuple(getattr(value, name) for name in fields)
        need(count == before.st_size and count <= maximum and
             stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()), "file changed while reading: " + str(path))
    finally:
        os.close(fd)
    identity = {"path": str(path), "bytes": count, "sha256": digest.hexdigest()}
    if expected is not None:
        pin = expected if isinstance(expected, str) else expected["sha256"]
        need(isinstance(pin, str) and HEX.fullmatch(pin) and identity["sha256"] == pin, "SHA differs: " + str(path))
        if isinstance(expected, dict):
            need(type(expected["bytes"]) is int and identity["bytes"] == expected["bytes"], "byte length differs: " + str(path))
    return (identity, b"".join(chunks)) if retain else identity

def native_terminal(value, job_id, state='succeeded', exit_code=0):
    assert value['job_id'] == job_id and value['state'] == state and value['exit_code'] == exit_code
    assert value['output_complete'] is True and value['output_durable'] is True
    assert value['automatic_retry'] is False and value['timed_out'] is False and value['cancelled'] is False
    assert value['terminal_publication_confirmed'] is True and value['terminal_publication_protocol'] == 1
    for channel in ('stdout', 'stderr'):
        assert value['log_bytes'][channel]['seen'] == value['log_bytes'][channel]['stored']
        assert value['log_errors'][channel] is None
        assert value['log_synced'][channel] is True and value['log_truncated'][channel] is False

def need(value, message):
    if not value:
        raise RuntimeError(message)

def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()

def _identity(value, path=None):
    need(isinstance(value, dict) and {"path", "bytes", "sha256"} <= set(value),
         "an actual file identity is required")
    need(isinstance(value["path"], str) and Path(value["path"]).is_absolute()
         and type(value["bytes"]) is int and value["bytes"] >= 0
         and isinstance(value["sha256"], str) and HEX.fullmatch(value["sha256"]),
         "invalid original file identity")
    result = {key: value[key] for key in ("path", "bytes", "sha256")}
    if path is not None:
        need(result["path"] == str(path), "original file path differs: " + str(path))
    return result

def _declared(value, bind, maximum=8 * 1024 * 1024, retain=False):
    pin = _identity(value)
    path = Path(pin["path"])
    need(any(path.is_relative_to(root) for root in (ROOT, BASE, CACHE_OWNER, NEXTEST_ROOT)),
         "input lies outside the fixed experiment or original nextest roots")
    result = bind(path, pin, maximum=maximum, retain=retain)
    identity = result[0] if retain else result
    need(identity == pin, "stable reader returned another identity")
    return result

def _artifact(prerequisites, name, bind, retain=False, maximum=8 * 1024 * 1024):
    need(name in prerequisites["artifact_map"], "required artifact identity is absent: " + name)
    pin = _identity(prerequisites["artifact_map"][name], ROOT / name)
    if name in PINNED:
        need(pin == PINNED[name], "frozen preparation input differs: " + name)
    return _declared(pin, bind, maximum=maximum, retain=retain)

def _document(prerequisites, name, bind):
    identity, raw = _artifact(prerequisites, name, bind, retain=True)
    value = json.loads(raw)
    need(isinstance(value, dict), "expected an original JSON object: " + name)
    return identity, value

def _foundation(prerequisites, require_ci=False):
    need(not sys.flags.optimize, "original assertion-based receipt helpers require normal Python execution")
    need(isinstance(prerequisites, dict)
         and prerequisites.get("schema") == "hepta-d2-c1-prerequisites/v1"
         and prerequisites.get("qualification_sealed") is True,
         "actual D2 qualification prerequisites are not sealed")
    need(prerequisites.get("required_missing_qualification_bindings") == [],
         "qualification prerequisite identities remain missing")
    need(isinstance(prerequisites.get("artifact_map"), dict)
         and set(prerequisites["artifact_map"]) == set(PINNED) | set(QUALIFICATION_ARTIFACTS) | set(CI_ARTIFACTS),
         "the fixed prerequisite artifact map differs")
    for name in (*PINNED, *QUALIFICATION_ARTIFACTS):
        _identity(prerequisites["artifact_map"][name], ROOT / name)
    _identity(prerequisites.get("prerequisite_module"), MODULE_PATH)
    job = prerequisites.get("qualification_original_job_id")
    need(isinstance(job, str) and JOB.fullmatch(job), "actual D2 qualification job identity is required")
    need(prerequisites.get("performance_acceptance_claim") is False,
         "diagnostic prerequisites must not claim performance adoption")
    if require_ci:
        need(prerequisites.get("exact_ci_sealed") is True
             and prerequisites.get("required_missing_exact_ci_bindings") == [],
             "actual D2 exact-CI prerequisites are not sealed")
        ci_job = prerequisites.get("exact_ci_original_job_id")
        need(isinstance(ci_job, str) and JOB.fullmatch(ci_job) and ci_job != job,
             "a distinct actual exact-CI job identity is required")
        for name in CI_ARTIFACTS:
            _identity(prerequisites["artifact_map"][name], ROOT / name)

def _native(prerequisites, prefix, terminal, bind):
    job_key = "qualification_original_job_id" if prefix == "qualification" else "exact_ci_original_job_id"
    pages_key = "qualification_read_pages" if prefix == "qualification" else "exact_ci_read_pages"
    job = prerequisites[job_key]
    native_terminal(terminal, job)
    need(terminal.get("audit_recorded") is True, "native terminal audit receipt is missing")
    pages = prerequisites.get(pages_key)
    need(isinstance(pages, list) and 1 <= len(pages) <= 64,
         "complete original native read pages are required")
    basename = "qualification-native-read-01" if prefix == "qualification" else "rust-ci-native-read-01"
    names, originals, offsets = set(), [], {"stdout": 0, "stderr": 0}
    streams = {"stdout": [], "stderr": []}
    for number, pin in enumerate(pages):
        identity = _identity(pin)
        path = Path(identity["path"])
        need(path.parent == ROOT and
             re.fullmatch(re.escape(basename) + r"(?:-[0-9]{3})?\.json", path.name) is not None
             and path.name not in names, "unsafe or repeated native read page")
        names.add(path.name)
        actual, raw = _declared(identity, bind, maximum=256 * 1024, retain=True)
        value = json.loads(raw)
        need(value.get("job_id") == job and value.get("audit_recorded") is True,
             "native read page identifies another job")
        for stream in ("stdout", "stderr"):
            channel = value[stream]
            body = bytes.fromhex(channel["bytes_hex"])
            total = terminal["log_bytes"][stream]["stored"]
            need(type(total) is int and 0 <= total <= 1024 * 1024,
                 "native original stream exceeds the declared bound")
            need(type(channel["offset"]) is int and channel["offset"] == offsets[stream]
                 and channel["size"] == total and len(body) <= 16384
                 and channel["next_offset"] == offsets[stream] + len(body) <= total
                 and channel["text"] == body.decode("utf-8", errors="replace")
                 and channel["eof"] is (channel["next_offset"] == total),
                 "native original page has a gap, overlap, changed text or incorrect EOF")
            need(body or offsets[stream] == total, "native page made no progress")
            if number + 1 == len(pages):
                need(channel["eof"] is True, "the original native stream is incomplete")
            offsets[stream] = channel["next_offset"]
            streams[stream].append(body)
        originals.append(actual)
    result = {}
    for stream in streams:
        body = b"".join(streams[stream])
        need(len(body) == offsets[stream] == terminal["log_bytes"][stream]["stored"],
             "native page bytes do not reconcile with the original terminal")
        result[stream] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    return {"job_id": job, "read_pages": originals, "streams": result,
            "complete_original_native_bytes_verified": True, "fabricated_combined_read": False}

def _source_inputs(source, bind):
    # Same complete input scope as the original R35 parent; only its reader is injected.
    need(source.is_absolute() and source.resolve() == source and source.is_dir(),
         "direct qualified source directory missing")
    paths = {source / "Cargo.toml", source / "Cargo.lock"}
    for relative in ("build.rs", "rustfmt.toml", "rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml"):
        path = source / relative
        if os.path.lexists(path):
            paths.add(path)
    for relative in ("src", "examples"):
        root = source / relative
        need(root.is_dir() and root.resolve() == root, "source input subtree missing or indirect")
        for directory, subdirs, names in os.walk(root, followlinks=False):
            for name in subdirs:
                need(not (Path(directory) / name).is_symlink(), "symlinked source directory")
            paths.update(Path(directory) / name for name in names)
    files = {}
    for path in sorted(paths):
        identity = bind(path, maximum=16 * 1024 * 1024)
        files[path.relative_to(source).as_posix()] = {key: identity[key] for key in ("bytes", "sha256")}
    return {"root": str(source), "file_count": len(files), "files": files,
            "sha256": hashlib.sha256(canonical(files)).hexdigest(),
            "scope": "Cargo manifests, optional build/toolchain/config inputs, complete src and examples trees"}

def _module(prerequisites, bind):
    pin = _identity(prerequisites.get("prerequisite_module"), MODULE_PATH)
    canonical_id, canonical_raw = _declared(pin, bind, retain=True)
    executing_path = Path(__file__).resolve()
    current_id, current_raw = bind(executing_path, maximum=8 * 1024 * 1024, retain=True)
    need(current_id["path"] == str(executing_path) and current_raw == canonical_raw,
         "executing module copy differs from the frozen canonical prerequisite source")
    return canonical_id

def _previous_owner(prerequisites, preparation, build_inputs, bind):
    """Rebind exact D1 receipts and the successful original pre-rename check; do not replay it."""
    closure_id, closure = _document(prerequisites, "cache-owner-closure-inputs.json", bind)
    need(closure["schema"] == "hepta-d2-d1-cache-owner-closure/v1"
         and closure["sealed"] is True and closure["required_missing_bindings"] == []
         and closure["owner_root"] == str(CACHE_OWNER)
         and closure["inputs"] == OWNER_INPUTS and closure["jobs"] == OWNER_JOBS
         and closure["original_missing_paths"] == ORIGINAL_MISSING_PATHS
         and closure["original_c1_workflow_passed"] is False
         and closure["standalone_original_auditor_already_executed"] is True
         and closure["historical_auditors_to_execute"] == 0 and closure["candidate_adopted"] is False,
         "the exact closed D1 cache-owner input differs")
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "successful D2 preparation does not bind the fixed prior-owner input")
    docs = {}
    for role, pin in OWNER_INPUTS.items():
        _, raw = _declared(pin, bind, retain=True)
        docs[role] = json.loads(raw)
    need(all(not os.path.lexists(path) for path in ORIGINAL_MISSING_PATHS),
         "an original missing D1 output was subsequently created")
    closed = preparation["cache_owner_closure"]
    post = docs["ordinary_postflight_report"]
    releases = {**{row["path"]: row for row in post["qualified_feature_programs_after"].values()},
                **{row["path"]: row for row in post["ordinary_programs"].values()}}
    expected = {"closed": True, "source_input_count": 222,
        "qualification_counts": {key: docs["qualification_summary"][key] for key in COUNT_KEYS},
        "ordinary_counts": post["tests"], "original_jobs": OWNER_JOBS,
        "original_c1_workflow_passed": False, "c1_original_controller_closures": 8,
        "standalone_original_native_audit_passed": True, "historical_auditors_reexecuted": False,
        "candidate_adopted": False, "current_machine_idle_claimed": False,
        "future_live_cache_process_scan_required": True, "retained_release_programs": releases,
        "original_inputs": OWNER_INPUTS}
    need(closed == expected, "the original successful preparation recorded another owner closure")
    need(preparation["cache_transferred_by_rename"] is True
         and preparation["new_full_cache_copy_bytes"] == 0 and preparation["cache_deletions"] == 0
         and preparation["cache_to_transfer"] == str(CACHE_OWNER / "target-build"),
         "the original single cache rename receipt differs")
    target = ROOT / "target-build"
    need(target.resolve() == target and target.is_dir() and not os.path.lexists(CACHE_OWNER / "target-build"),
         "the cache is not at its recorded post-rename location")
    retained = preparation["retained_programs"]
    need(isinstance(retained, dict) and len(retained) >= 8 and len(releases) == 6
         and all(Path(path).is_relative_to(CACHE_OWNER / "qualification-01")
                 or Path(path).is_relative_to(CACHE_OWNER / "ordinary-02") for path in retained)
         and all(isinstance(digest, str) and HEX.fullmatch(digest) for digest in retained.values()),
         "original retained program custody is incomplete")
    for path, pin in releases.items():
        need(retained.get(path) == pin["sha256"], "the preserved D1 release copy differs")
        _declared(pin, bind, maximum=64 * 1024 * 1024)
    return {"input": closure_id, "original_identity_count": len(OWNER_INPUTS),
        "original_bytes_rebound": True, "original_jobs": OWNER_JOBS,
        "original_c1_workflow_passed": False, "c1_original_controller_closures": 8,
        "standalone_original_native_audit_passed": True,
        "old_preparer_cache_owner_closed_reexecuted": False,
        "current_cache_path": str(target), "original_successful_preparation_rename_bound": True,
        "prior_owner_performance_adopted": False, "old_auditors_reexecuted": False,
        "current_machine_idle_claimed": False, "retained_release_copies_rehashed": 6,
        "retained_test_copies": "bound to the successful original preparation receipt; not rehashed by this later binder"}

def bind_d2_qualification(prerequisites, bind):
    """Read-only Q proof. This function does not require or inspect future CI success."""
    _foundation(prerequisites)
    module_id = _module(prerequisites, bind)
    for name in PINNED:
        _artifact(prerequisites, name, bind)
    launcher_id = _artifact(prerequisites, "prepare_qualify.py", bind)
    input_id, build_inputs = _document(prerequisites, "qualification-input.json", bind)
    patch_id, patch_raw = _artifact(prerequisites, "candidate/candidate.patch", bind, retain=True)
    patch_git_blob = hashlib.sha1(b"blob " + str(len(patch_raw)).encode("ascii") + b"\0" + patch_raw).hexdigest()
    need(patch_git_blob == "c4c5359d5bc05bb37a8fa28d62f80f2f3a1263c4",
         "the frozen diagnostic patch Git blob differs")
    candidate_id, candidate = _document(prerequisites, "candidate/input.json", bind)
    manifest_id, candidate_manifest = _document(prerequisites, "candidate/package-manifest.json", bind)
    prep_id, preparation = _document(prerequisites, "preparation.json", bind)
    terminal_id, terminal = _document(prerequisites, "qualification-terminal-status-01.json", bind)
    qualified_id, qualified = _document(prerequisites, "qualification-01/report.json", bind)
    map_id, final_map = _document(prerequisites, "qualification-01/source-map.json", bind)
    test_id, tests = _document(prerequisites, "qualification-01/isolated-tests/summary.json", bind)
    audit_id, audit = _document(prerequisites, "qualification-01/isolated-tests.audit.json", bind)
    native = _native(prerequisites, "qualification", terminal, bind)
    baseline_id, baseline_raw = _declared(BASELINE_QUALIFICATION, bind, retain=True)
    baseline = json.loads(baseline_raw)
    need(build_inputs["schema"] == "hepta-d2-direct-qualification-input/v1"
         and build_inputs["sealed"] is True and build_inputs["required_missing_bindings"] == []
         and build_inputs["baseline_commit"] == build_inputs["source_construction_parent"] == BASELINE_COMMIT
         and build_inputs["preparation_tool"] == {"path": "prepare_qualify.py", "bytes": launcher_id["bytes"], "sha256": launcher_id["sha256"]},
         "frozen D2 qualification input differs")
    need(all(build_inputs[name] is None for name in ("actual_d2_qualification", "actual_d2_formatted_map",
         "actual_d2_test_counts", "actual_d2_release_programs")), "historical preparation inputs were rewritten with future results")
    need(candidate["schema"] == "hepta-x230-d2-candidate/v1"
         and candidate_manifest["schema"] == "hepta-x230-d2-source-package/v1"
         and candidate["baseline_commit"] == candidate["git_parent"] == BASELINE_COMMIT
         and candidate["protocol"]["diagnostic_only"] is True
         and candidate["protocol"]["runtime_adoption"] is False
         and candidate["candidate_patch"] == {"bytes": patch_id["bytes"],
             "sha256": patch_id["sha256"], "git_blob": patch_git_blob},
         "the frozen two-file diagnostic candidate and patch do not bind")
    before, preformat = candidate["baseline_compile_inputs"], candidate["candidate_compile_inputs"]
    need(len(before) == len(preformat) == 222 and set(candidate["changed_paths"]) == CHANGED
         and set(candidate["added_paths"]) == ADDED
         and set(preformat) - set(before) == ADDED and not set(before) - set(preformat)
         and {name for name in preformat if preformat[name] != before.get(name)} == CHANGED,
         "D2 is not the exact two-path/no-addition qualified-D1 patch")
    need(baseline["schema"] == "hepta-x230-composed-qualification/v1"
         and baseline.get("qualified") is True and baseline.get("finished_utc")
         and baseline["source"] == str(BASE / "source")
         and baseline["source_tested"] == baseline["source_after"] == before,
         "candidate preimage is not the exact qualified D1 source")
    need(preparation["schema"] == "hepta-x230-d2-preparation/v1"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and not preparation.get("error") and preparation["qualification_returncode"] == 0
         and preparation["automatic_retries"] == 0 and preparation["production_services_modified"] is False
         and preparation["source_baseline"] == BASELINE_COMMIT
         and preparation["performance_acceptance_claim"] is False
         and preparation["diagnostic_environment_absent"] is True
         and preparation["ordinary_supplemental_executed"] is False
         and preparation["qualification_started"] is True
         and preparation["first_actual_d2_qualification_required"] is True,
         "the actual D2 preparation did not close successfully")
    expected_command = ["/usr/bin/python3", "-B", "-u", str(SOURCE / "tools/x230/20261028/qualify.py"),
        "--source", str(SOURCE), "--output", str(QUALIFICATION), "--target", str(ROOT / "target-build"),
        "--cargo-home", str(CARGO_HOME), "--jobs", "2"]
    need(preparation["qualification_command"] == expected_command
         and preparation["free_bytes_before"] >= 3 * 1024 ** 3
         and preparation["process_check"]["matched_processes"] == []
         and preparation["process_check"]["compiler_processes"] == [],
         "the original qualifier command or preparation guards differ")
    need(preparation["input_binding"] == input_id
         and preparation["candidate_patch"] == {**patch_id, "git_blob": patch_git_blob}
         and preparation["qualification_report_sha256"] == qualified_id["sha256"]
         and preparation["baseline_qualification"] == build_inputs["baseline_qualification"] == BASELINE_QUALIFICATION
         and preparation["frozen_candidate_input"] == candidate_id
         and preparation["frozen_candidate_manifest"] == manifest_id,
         "actual preparation does not bind the frozen input and result bytes")
    need(qualified["schema"] == "hepta-x230-composed-qualification/v1"
         and qualified.get("qualified") is True and qualified.get("finished_utc") and not qualified.get("error")
         and qualified["source"] == str(SOURCE) and qualified["jobs"] == 2
         and qualified["automatic_test_retries"] == 0 and qualified["service_changes"] is False,
         "the complete original D2 qualification did not pass")
    need([row["name"] for row in qualified["stages"]] == STAGES
         and all(type(row["returncode"]) is int and row["returncode"] == 0
                 and isinstance(row["command"], list) and row["command"]
                 and HEX.fullmatch(row["stdout_sha256"]) and HEX.fullmatch(row["stderr_sha256"])
                 for row in qualified["stages"]), "the original eight qualification stages differ")
    for row in qualified["stages"]:
        if row["name"] in {"clippy", "test-build", "release"}:
            need({"--all-features", "--offline", "--locked"} <= set(row["command"]),
                 "the original all-features/offline/locked qualification command changed")
    need(preparation["source_before_qualification"] == qualified["source_input"] == preformat
         and preparation["source_after_qualification"] == qualified["source_tested"] == qualified["source_after"] == final_map
         and set(final_map) == set(preformat)
         and {name for name in final_map if final_map[name] != before.get(name)} == CHANGED
         and final_map["Cargo.toml"] == preformat["Cargo.toml"]
         and sum(name.endswith(".py") for name in final_map) == 17,
         "actual formatter/tested source does not preserve the frozen diagnostic change")
    harness = qualified["harness_after"]
    need(len(harness) == 19 and qualified["harness_before"] == harness
         == baseline["harness_before"] == baseline["harness_after"]
         == build_inputs["qualification_harness_sha256"] == preparation["qualification_harness_sha256"]
         and harness["qualify.py"] == "95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d",
         "the original nineteen qualification harnesses changed")
    need(tests["schema"] == "hepta-isolated-libtest/v1" and tests.get("success") is True
         and tests.get("filter") == "" and tests.get("enumeration_errors") == []
         and not tests.get("fatal_error"), "the complete isolated test summary did not pass")
    counts = {name: tests[name] for name in COUNT_KEYS}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0 and counts["failed"] == counts["retries"] == 0
         and counts["selected"] == counts["passed"] + counts["ignored"],
         "actual isolated inventory counts do not reconcile without retries")
    need(audit["schema"] == "hepta-isolated-libtest-audit/v1"
         and audit.get("success") is True and audit.get("expected_filter") == ""
         and audit.get("errors") == [] and not audit.get("fatal_error")
         and audit["evidence"] == str(QUALIFICATION / "isolated-tests")
         and audit["auditor_sha256"] == harness["audit_isolated_tests.py"]
         and all(audit[name] == counts[name] for name in ("passed", "failed", "ignored", "selected"))
         and audit["executed"] == counts["passed"] + counts["failed"]
         and audit["binaries"]
         and all(row["recorded_before_sha256"] == row["current_after_sha256"]
                 and HEX.fullmatch(row["current_after_sha256"]) for row in audit["binaries"]),
         "the original full-inventory auditor did not verify the actual tests and executable custody")
    current, baseline_current = _source_inputs(SOURCE, bind), _source_inputs(BASE / "source", bind)
    need({name: row["sha256"] for name, row in current["files"].items()} == final_map
         and {name: row["sha256"] for name, row in baseline_current["files"].items()} == before
         and set(current["files"]) - set(baseline_current["files"]) == ADDED
         and not set(baseline_current["files"]) - set(current["files"])
         and {name for name in current["files"] if current["files"][name] != baseline_current["files"].get(name)} == CHANGED,
         "current full Cargo/config/source inputs differ from the actual qualified patch")
    harness_root = SOURCE / "tools/x230/20261028"
    need({path.name for path in harness_root.glob("*.py")} == set(harness), "current harness file set differs")
    for name, digest in harness.items():
        need(Path(name).name == name, "unsafe original harness name")
        bind(harness_root / name, digest, maximum=8 * 1024 * 1024)
    for stage in qualified["stages"]:
        name = stage["name"]
        bind(QUALIFICATION / ("cargo-no-run.jsonl" if name == "test-build" else name + ".stdout"),
             stage["stdout_sha256"], maximum=128 * 1024 * 1024)
        bind(QUALIFICATION / (name + ".stderr"), stage["stderr_sha256"], maximum=128 * 1024 * 1024)
    expected_isolated = {"summary.json", "cargo-artifacts.jsonl", "source-manifest.input", "commands.jsonl", "tests.jsonl"}
    need(set(audit["input_sha256"]) == expected_isolated, "original test-audit input identities differ")
    for name, digest in audit["input_sha256"].items():
        bind(QUALIFICATION / "isolated-tests" / name, digest, maximum=128 * 1024 * 1024)
    need(audit["input_sha256"]["summary.json"] == test_id["sha256"]
         and audit["input_sha256"]["source-manifest.input"] == map_id["sha256"] == tests["source_manifest_sha256"],
         "isolated inventory uses another original source map")
    need(set(qualified["binaries"]) == set(BINARY_NAMES), "qualified release binary set differs")
    binaries = {}
    for name in BINARY_NAMES:
        row = qualified["binaries"][name]
        need(row["path"] == str(QUALIFICATION / name) and HEX.fullmatch(row["sha256"]),
             "the original qualifier release-copy path/hash differs")
        # The unchanged qualifier records path/SHA only; byte length comes
        # from the parent's stable reader, never from a fabricated report key.
        binaries[name] = bind(QUALIFICATION / name, row["sha256"], maximum=128 * 1024 * 1024)
    owner = _previous_owner(prerequisites, preparation, build_inputs, bind)
    return {"passed": True, "original_job_id": prerequisites["qualification_original_job_id"],
        "tests": counts, "binaries": binaries, "source_tested": final_map,
        "candidate_inputs": {"changed_paths": sorted(CHANGED), "added_paths": sorted(ADDED),
                             "baseline_compile_inputs": before, "candidate_compile_inputs": preformat},
        "source_baseline_commit": BASELINE_COMMIT, "qualified_source_files": len(final_map),
        "harness_files": len(harness), "qualification_harness": harness, "stages": STAGES,
        "preparation": prep_id, "terminal": terminal_id, "qualification": qualified_id,
        "qualification_launcher": launcher_id, "qualification_input": input_id, "candidate_patch": patch_id,
        "baseline_qualification": baseline_id, "isolated_summary": test_id, "isolated_audit": audit_id,
        "source_map": map_id, "full_source_inputs_sha256": current["sha256"],
        "baseline_full_source_inputs_sha256": baseline_current["sha256"], "source_inputs": current,
        "native": native, "source_chain_and_cache_owner": owner,
        "prerequisite_module": module_id,
        "qualified_release_kind": "original all-features diagnostic ELF; mode unset",
        "ordinary_supplemental_claimed": False, "performance_acceptance_claim": False,
        "original_auditors_reexecuted": False}

def qualification_legacy_inputs(prerequisites):
    """The six original materializer inputs, derived from the same frozen Q foundation."""
    _foundation(prerequisites)
    files = prerequisites["artifact_map"]
    terminal = dict(_identity(files["qualification-terminal-status-01.json"]),
                    job_id=prerequisites["qualification_original_job_id"])
    return {"qualification_launcher": _identity(files["prepare_qualify.py"]),
        "qualification_input": _identity(files["qualification-input.json"]),
        "candidate_patch": _identity(files["candidate/candidate.patch"]),
        "qualification_preparation": _identity(files["preparation.json"]),
        "qualification_terminal_status": terminal,
        "qualification_reports": [dict(_identity(files["qualification-01/report.json"]), success_field="qualified")]}

def bind_d2_prerequisites(prerequisites, bind):
    """Add actual native exact-CI closure to the Q-only proof; never launch CI."""
    _foundation(prerequisites, require_ci=True)
    qualification = bind_d2_qualification(prerequisites, bind)
    ci_id, ci = _document(prerequisites, "rust-ci-01/report.json", bind)
    plan_id, plan = _document(prerequisites, "rust-ci-plan-01.json", bind)
    audit_id, audit = _document(prerequisites, "rust-ci-01/nextest-output-audit.json", bind)
    terminal_id, terminal = _document(prerequisites, "rust-ci-native-01.json", bind)
    native = _native(prerequisites, "exact_ci", terminal, bind)
    need(ci["schema"] == "hepta-d2-external-rust-ci/v1" and ci.get("passed") is True
         and ci.get("finished_utc") and not ci.get("error")
         and ci["automatic_retries"] == 0 and ci["production_services_modified"] is False
         and ci["owned_children_closed"] is True and ci["source_inputs_unchanged"] is True
         and ci["home_unchanged"] is True and ci["hosted_actions_passed"] is False
         and ci["original_qualification_job_id"] == qualification["original_job_id"]
         and ci["plan"] == plan_id, "actual native exact-CI receipt is incomplete or identifies another qualification")
    need(plan["schema"] == "hepta-d2-materialized-exact-rust-ci-plan/v1"
         and plan["attempt"] == "01" and plan["executed"] is False and plan["hosted_actions_passed"] is False
         and plan["qualification_job_id"] == qualification["original_job_id"]
         and plan["qualification"] == qualification["qualification"]
         and plan["preparation"] == qualification["preparation"]
         and plan["qualification_terminal_status"] == qualification["terminal"]
         and plan["qualification_counts"] == qualification["tests"]
         and plan["source"] == str(SOURCE) and plan["source_map"] == qualification["source_map"]
         and plan["source_files"] == qualification["source_tested"]
         and plan["qualified_binaries"] == qualification["binaries"]
         and plan["qualification_harness"] == qualification["qualification_harness"]
         and plan["qualification_summary"] == qualification["isolated_summary"]
         and plan["qualification_independent_audit"] == qualification["isolated_audit"],
         "actual CI plan is not bound to the original successful Q")
    need(plan["commands"] == [
            {"workflow_step": "Check all targets", "argv": CI_COMMANDS["cargo-check"], "cwd": str(SOURCE)},
            {"workflow_step": "Test in isolated processes", "argv": CI_COMMANDS["nextest-run"], "cwd": str(SOURCE)}]
         and plan["inventory_command"]["argv"] == CI_COMMANDS["nextest-list"]
         and plan["inventory_command"]["cwd"] == str(SOURCE)
         and plan["inventory_command"]["timeout_seconds"] == 900,
         "the original exact Rust CI commands changed")
    contract = plan["execution_contract"]
    need(contract["fresh_evidence_directory"] == str(ROOT / "rust-ci-01")
         and contract["automatic_retries"] == 0 and contract["cargo_clean"] is False
         and contract["check_timeout_seconds"] == 1800 and contract["inventory_timeout_seconds"] == 900
         and contract["nextest_timeout_seconds"] == 3600 and contract["combined_timeout_seconds"] == 5400
         and contract["outer_budget_seconds"] == 6600
         and contract["retain_full_original_stdout_stderr"] is True
         and contract["no_extra_nextest_filters_or_weaker_flags"] is True,
         "the original native CI execution contract changed")
    need(ci["explicit_environment"] == plan["environment"]
         and all(name not in ci["explicit_environment"] for name in DIAGNOSTIC_ENV),
         "CI environment differs from its plan or enables diagnostic recording")
    for name, expected in CI_ENVIRONMENT.items():
        need(ci["explicit_environment"].get(name) == expected, "the original explicit CI environment differs: " + name)
    need([row["name"] for row in ci["stages"]] == list(CI_COMMANDS), "the original six CI stages differ")
    stage_ids = {}
    version_raw = None
    for stage in ci["stages"]:
        name = stage["name"]
        need(stage["argv"] == CI_COMMANDS[name] and stage["cwd"] == str(SOURCE)
             and stage["returncode"] == 0 and stage["passed"] is True
             and stage["waited_and_reaped"] is True and stage["owned_process_absent"] is True
             and stage["owned_process_group_absent"] is True and stage["timed_out"] is False,
             "an original CI stage did not close once with its original command: " + name)
        stage_ids[name] = {}
        for stream in ("stdout", "stderr"):
            pin = _identity(stage[stream], ROOT / "rust-ci-01" / (name + "." + stream))
            if name == "nextest-version" and stream == "stdout":
                identity, version_raw = _declared(pin, bind, maximum=1024 * 1024, retain=True)
            else:
                identity = _declared(pin, bind, maximum=128 * 1024 * 1024)
            stage_ids[name][stream] = identity
    need(version_raw is not None and version_raw.decode("utf-8").splitlines()[0].startswith("cargo-nextest 0.9.137 "),
         "actual nextest version is not the original 0.9.137 tool")
    need(ci["nextest_output_audit"] == audit and audit["verified"] is True
         and {name: audit[name] for name in COUNT_KEYS} == qualification["tests"]
         and audit["completed_exact_case_count"] == qualification["tests"]["passed"]
         and audit["progress_counter_complete"] is True
         and audit["raw_sha256"] == stage_ids["nextest-run"]["stderr"]["sha256"]
         and audit["raw_bytes"] == stage_ids["nextest-run"]["stderr"]["bytes"],
         "the original nextest audit does not reconcile with actual Q and original raw stderr")
    inventory = ci["structured_inventory"]
    expected = plan["expected_nextest"]
    need(inventory["verified"] is True
         and inventory["total"] == qualification["tests"]["selected"]
         and inventory["ignored"] == qualification["tests"]["ignored"]
         and inventory["case_inventory_sha256"] == audit["case_inventory_sha256"] == expected["case_inventory_sha256"]
         and inventory["original_stdout"] == stage_ids["nextest-list"]["stdout"],
         "the actual original nextest structured inventory differs")
    need({"passed": expected["passed"], "failed": expected["failed"], "ignored": expected["skipped"],
          "selected": expected["total"], "retries": expected["retries"]} == qualification["tests"]
         and len(expected["exact_cases"]) == qualification["tests"]["selected"]
         and sum(row["ignored"] for row in expected["exact_cases"]) == qualification["tests"]["ignored"]
         and hashlib.sha256(json.dumps(expected["exact_cases"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
         == expected["case_inventory_sha256"], "the sealed complete CI case set does not reconcile")
    need(plan["nextest_binary"] == NEXTEST_BINARY, "the original nextest binary pin differs")
    _declared(NEXTEST_BINARY, bind, maximum=64 * 1024 * 1024)
    nextest_receipt = _identity(plan["nextest_install_receipt"], NEXTEST_ROOT / "receipt.json")
    need(nextest_receipt["sha256"] == "2bbae481b3fbc6ac6d06a22bfe22e9500f5190b97ccddb16e8aba1ef1ed34f9d",
         "the original nextest installation receipt changed")
    _declared(nextest_receipt, bind)
    workflow = plan["workflow_binding"]
    need(workflow["canonical"] == CANONICAL_WORKFLOW
         and workflow["canonical_git_blob"] == "34afc29edffd3130df158601c6a14fee5efbf79c"
         and workflow["private_source"] == PRIVATE_SOURCE_WORKFLOW
         and workflow["qualified_source_modified"] is False, "the original workflow closure differs")
    _, workflow_raw = _declared(CANONICAL_WORKFLOW, bind, retain=True)
    need(hashlib.sha1(b"blob " + str(len(workflow_raw)).encode() + b"\0" + workflow_raw).hexdigest()
         == workflow["canonical_git_blob"], "canonical workflow Git blob differs")
    _declared(PRIVATE_SOURCE_WORKFLOW, bind)
    manifest_id = _identity(plan["ci_manifest"])
    original_ci_manifest = {
        "path": "/home/qian/hepta-runtime-optimization-20261105-r25/ci-gates/ci-gate-manifest.json",
        "bytes": 45857, "sha256": "bf0df5f7d29ebd249854fbf75887fb0fb136f18a63a0c240abf8420655fb195e"}
    need(manifest_id == original_ci_manifest, "the exact original 85-input CI manifest changed")
    # One exact historical input, not an extension of _declared's allowed roots.
    need(bind(Path(original_ci_manifest["path"]), original_ci_manifest, maximum=8 * 1024 * 1024)
         == original_ci_manifest, "stable reader returned another original CI manifest")
    need(all(identity in plan["input_bindings"] for identity in
         (qualification["qualification"], qualification["preparation"], qualification["terminal"],
          qualification["source_map"], qualification["isolated_summary"], qualification["isolated_audit"])),
         "the original CI plan omits a qualification binding")
    binder_id = _module(prerequisites, bind)
    need(binder_id == qualification["prerequisite_module"] and binder_id in plan["input_bindings"],
         "the actual CI plan did not bind the same canonical D2 prerequisite module")
    old_binder_block = b"    binder_id = bind(ROOT / \"rust-ci-prerequisites-01/d2_prerequisites.py\", maximum=8 * 1024 * 1024)\n    current_binder = bind(Path(__file__).resolve(), maximum=8 * 1024 * 1024)\n    need(binder_id in plan[\"input_bindings\"]\n         and all(binder_id[key] == current_binder[key] for key in (\"bytes\", \"sha256\")),\n         \"the outer binder differs from the actual CI qualification binder\")\n"
    old_manifest_block = b"    manifest_id = _identity(plan[\"ci_manifest\"])\n    need(manifest_id[\"sha256\"] == \"bf0df5f7d29ebd249854fbf75887fb0fb136f18a63a0c240abf8420655fb195e\",\n         \"the original 85-input CI manifest changed\")\n    _declared(manifest_id, bind)\n"
    new_manifest_block = b"    manifest_id = _identity(plan[\"ci_manifest\"])\n    original_ci_manifest = {\n        \"path\": \"/home/qian/hepta-runtime-optimization-20261105-r25/ci-gates/ci-gate-manifest.json\",\n        \"bytes\": 45857, \"sha256\": \"bf0df5f7d29ebd249854fbf75887fb0fb136f18a63a0c240abf8420655fb195e\"}\n    need(manifest_id == original_ci_manifest, \"the exact original 85-input CI manifest changed\")\n    # One exact historical input, not an extension of _declared's allowed roots.\n    need(bind(Path(original_ci_manifest[\"path\"]), original_ci_manifest, maximum=8 * 1024 * 1024)\n         == original_ci_manifest, \"stable reader returned another original CI manifest\")\n"
    old_return_line = b"            \"qualification_binder\": binder_id,\n"
    new_return_line = b"            \"qualification_binder\": binder_id,\n            \"qualification_binder_correction\": binder_correction,\n"
    need(corrected_raw.count(begin_marker) == corrected_raw.count(end_marker) == 1,
         "the exact correction provenance block differs")
    before_block, body_and_after = corrected_raw.split(begin_marker, 1)
    _, after_block = body_and_after.split(end_marker, 1)
    restored = before_block + old_binder_block + after_block
    need(restored.count(new_manifest_block) == restored.count(new_return_line) == 1,
         "the exact manifest or returned-provenance edit differs")
    restored = restored.replace(new_manifest_block, old_manifest_block, 1)
    restored = restored.replace(new_return_line, old_return_line, 1)
    need(restored == original_binder_raw,
         "corrected source changed outside the reviewed manifest/provenance edits")
    binder_correction = {
        "schema": "hepta-d2-full-ci-manifest-binding-correction/v1",
        "original_ci_binder": binder_id, "reviewed_corrected_binder": corrected_id,
        "executing_copy_matches_corrected_source": True,
        "exact_inverse_edits_reconstruct_original_binder": True,
        "original_ci_plan_unchanged": True, "generic_declared_roots_unchanged": True,
        "sole_extra_manifest": original_ci_manifest}
    # END D2_REVIEWED_MANIFEST_CORRECTION_03
    for row in plan["tool_configuration_inventory"]:
        path = Path(row["path"])
        need(path.is_relative_to(SOURCE) and os.path.lexists(path) is row["exists"],
             "qualified source tool configuration presence changed")
        if row["exists"]:
            _declared(_identity(row["identity"], path), bind)
    tools = {}
    for key, filename in (("launcher", "run_rust_ci_01.py"),
                          ("materializer", "materialize_rust_ci_plan_01.py"),
                          ("auditor", "audit_nextest_0137.py")):
        identity = _identity(ci[key], ROOT / "rust-ci-tools-01" / filename)
        tools[key] = _declared(identity, bind)
    need(tools["auditor"]["sha256"] == "03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2",
         "the original nextest auditor source changed")
    return {"passed": True, "binaries": qualification["binaries"],
        "changed_paths": sorted(CHANGED), "added_paths": sorted(ADDED),
        "baseline_compile_inputs": qualification["candidate_inputs"]["baseline_compile_inputs"],
        "source_tested": qualification["source_tested"], "qualification": qualification,
        "exact_ci": {"passed": True, "original_job_id": prerequisites["exact_ci_original_job_id"],
            "report": ci_id, "plan": plan_id, "audit": audit_id, "terminal": terminal_id,
            "native": native, "tools": tools, "stages": stage_ids, "tests": qualification["tests"],
            "qualification_binder": binder_id,
            "source_inputs_unchanged": True, "owned_children_closed": True,
            "hosted_actions_claimed": False, "original_auditor_reexecuted": False},
        "diagnostic_environment_enabled_during_qualification_or_ci": False,
        "ordinary_supplemental_claimed": False, "performance_acceptance_claim": False}
