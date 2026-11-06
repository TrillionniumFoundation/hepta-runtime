#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual D1 Q-only and Q-plus-native-CI receipts for the C1 diagnostic parent.

This module creates no files and starts no child, host request, compiler,
auditor, measurement or cache operation. The caller must bind the immutable
foundation JSON before passing its body and the original stable file reader.
Both actual result flags are false in the companion unsealed example.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
SOURCE = ROOT / "source"
QUALIFICATION = ROOT / "qualification-01"
BASE = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261106-r35")
CARGO_HOME = Path("/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02")
NEXTEST_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137")
HEX = re.compile(r"[0-9a-f]{64}\Z")
JOB = re.compile(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}\Z")
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
STAGES = ['format',
 'fmt-check',
 'harness-tests',
 'clippy',
 'test-build',
 'isolated-tests',
 'audit-isolated-tests',
 'release']
DIAGNOSTIC_ENV = ('HEPTA_RUNTIME_PHASE_COST_MODE', 'HEPTA_RUNTIME_PHASE_COST_OUTPUT', 'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256')
OWNER_POSTFLIGHT_JOB = '1a1afe8986e-fc05-6ca9'
OWNER_JOBS = {'qualification': '1a1af619097-fc05-6813',
 'exact_ci': '1a1af88c330-fc05-696f',
 'observation': '1a1af9bb312-fc05-6a14',
 'lifecycle_materialization': '1a1afb8c456-fc05-6b1d',
 'normal_lifecycle': '1a1afc4fb4a-fc05-6b7f'}
OWNER_COUNTS = {'passed': 1645, 'failed': 0, 'ignored': 34, 'selected': 1679, 'retries': 0}
PINNED = {'prepare_qualify.py': {'bytes': 47509,
                        'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/prepare_qualify.py',
                        'sha256': '05fcf39aeb418e626ceec048f51c4919bc5ba0b85d180f89c8580cfa2adf876c'},
 'qualification-input.json': {'bytes': 5386,
                              'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/qualification-input.json',
                              'sha256': '6035b89808862402a49cb070e4d511dfbf4965ed16399c590ac035bb9690020a'},
 'cache-owner-closure-inputs.json': {'bytes': 42678,
                                     'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/cache-owner-closure-inputs.json',
                                     'sha256': 'cfb1f49ea5c9b15433c5411a9f3c9453fa7220d9e9b800a3aac44c2a0ab69601'},
 'candidate/input.json': {'bytes': 53222,
                          'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/candidate/input.json',
                          'sha256': 'd2c45351d8a11a1f472c06e68689c43e8ab821ee3c93428057de401644fb59cc'},
 'candidate/package-manifest.json': {'bytes': 10557,
                                     'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/candidate/package-manifest.json',
                                     'sha256': '3f5944705884d1e071f28978fc7ffb911875bf2a93a9c719b2cbe076bbb78fe0'},
 'candidate/candidate.patch': {'bytes': 64987,
                               'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/candidate/candidate.patch',
                               'sha256': '3940b39d5cdde7d4b76ba1e94f49ca461c6964b1edb2c2f44506fdf7c8a50523'},
 'provenance/source-anchor-and-publication-parent.json': {'bytes': 2400,
                                                          'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/provenance/source-anchor-and-publication-parent.json',
                                                          'sha256': '99d1e7c4faef98fd680aa7136c3d73e163ca3f64e15f75a1704a6394c8c1fd34'}}
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
CHANGED = {'Cargo.toml',
 'src/main.rs',
 'src/mcp/runtime/jobs.rs',
 'src/mcp/runtime/mod.rs',
 'src/mcp/runtime/phase_cost.rs',
 'src/mcp/runtime/phase_cost_tests.rs',
 'src/mcp/runtime/ssh.rs',
 'src/mcp/runtime/ssh_observation_agent_timeout_tests.rs',
 'src/mcp/runtime/ssh_observation_maintenance_tests.rs',
 'src/mcp/runtime/ssh_observation_pool.rs',
 'src/mcp/runtime/ssh_observation_pool_tests.rs',
 'src/mcp/runtime/ssh_observation_validation.rs',
 'src/mcp/server.rs'}
ADDED = {'src/mcp/runtime/phase_cost_tests.rs', 'src/mcp/runtime/phase_cost.rs'}
BASELINE_QUALIFICATION = {'bytes': 83365,
 'path': '/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/report.json',
 'sha256': 'bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971'}
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
 'CARGO_TARGET_DIR': '/home/qian/hepta-runtime-phase-cost-20261106-d1/target-build',
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
CANONICAL_WORKFLOW = {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-tools-01/canonical-workflow.yml',
 'bytes': 7631,
 'sha256': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51'}
PRIVATE_SOURCE_WORKFLOW = {'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/source/.github/workflows/ci.yml',
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



def native_stream_pages(pages, terminal):
    """Verify original read pages; never replace them with a fabricated single page."""
    assert isinstance(pages, list) and 1 <= len(pages) <= 16
    offsets = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for index, page in enumerate(pages):
        assert page['job_id'] == terminal['job_id'] and page['audit_recorded'] is True
        for name in ('stdout', 'stderr'):
            channel = page[name]
            raw = bytes.fromhex(channel['bytes_hex'])
            total = terminal['log_bytes'][name]['stored']
            assert type(total) is int and 0 <= total <= 256 * 1024
            assert type(channel['offset']) is int and channel['offset'] == offsets[name]
            assert channel['size'] == total and len(raw) <= 16384
            assert channel['next_offset'] == channel['offset'] + len(raw) <= total
            assert channel['text'] == raw.decode('utf-8', errors='replace')
            assert channel['eof'] is (channel['next_offset'] == total)
            # A stream already at EOF may recur as an empty EOF on later calls.
            # A pending stream must make progress, with no gaps or overlaps.
            assert raw or offsets[name] == total
            if index + 1 == len(pages):
                assert channel['eof'] is True
            offsets[name] = channel['next_offset']
            chunks[name].append(raw)
    assert all(offsets[name] == terminal['log_bytes'][name]['stored'] for name in offsets)
    return {name: b''.join(parts) for name, parts in chunks.items()}



def postflight_bytes(report_raw, terminal_raw, page_raws, receipt_identity):
    """Validate actual successful postflight custody without reading any host file."""
    report, terminal = json.loads(report_raw), json.loads(terminal_raw)
    native_terminal(terminal, OWNER_POSTFLIGHT_JOB)
    assert terminal['audit_recorded'] is True
    assert terminal['log_bytes']['stdout'] == {'seen': 46206, 'stored': 46206}
    assert terminal['log_bytes']['stderr'] == {'seen': 0, 'stored': 0}
    assert len(page_raws) == 3
    pages = [json.loads(raw) for raw in page_raws]
    assert [page['stdout']['offset'] for page in pages] == [0, 16384, 32768]
    streams = native_stream_pages(pages, terminal)
    assert streams['stderr'] == b'' and streams['stdout'].endswith(b'\n')
    assert hashlib.sha256(streams['stdout']).hexdigest() == '7820315a573794b9f6789d04ff71283cae1510fffb15d719da886b960a29b0fd'
    rows = streams['stdout'].splitlines()
    assert len(rows) == 1
    original_receipt = {'path': str(CACHE_OWNER / 'lifecycle-owner-postflight-01.json'),
                        'bytes': len(report_raw), 'sha256': hashlib.sha256(report_raw).hexdigest()}
    assert receipt_identity['bytes'] == original_receipt['bytes']
    assert receipt_identity['sha256'] == original_receipt['sha256']
    assert json.loads(rows[0]) == {'receipt': original_receipt, **report}
    assert report['schema'] == 'hepta-r35-rejected-lifecycle-owner-postflight/v1'
    assert report['postflight_job_id_from_supervisor'] == OWNER_POSTFLIGHT_JOB
    assert report['postflight_script'] == {
        'path': str(CACHE_OWNER / 'postflight_r35_lifecycle_owner_01.py'), 'bytes': 46387,
        'sha256': '6b03c0025b2bffc0f0552e53e95d7867a45fbb78ebf05d601172cddf91434c7e'}
    assert report['accepted_baseline_commit'] == BASELINE_COMMIT
    assert report['cache_owner'] == str(CACHE_OWNER) and report['cache_path'] == str(CACHE_OWNER / 'target-build')
    for name in ('cache_moved', 'cache_deleted', 'candidate_adopted', 'current_machine_idle_claimed',
                 'tests_benchmarks_or_auditors_reexecuted', 'archive_member_verifier_reexecuted',
                 'original_observation_postflight_modified'):
        assert report[name] is False
    for name in ('future_preparer_must_check_cache_referencing_processes', 'current_source_matches_qualified_map',
                 'qualification_harness_matches_original', 'source_harness_and_retained_programs_rechecked_before_output',
                 'qualification_completed', 'exact_ci_closed', 'observation_workflow_closed', 'observation_gate_passed',
                 'observation_performance_passed', 'lifecycle_materialization_started', 'normal_lifecycle_started',
                 'normal_lifecycle_workflow_closed', 'normal_lifecycle_controllers_closed', 'normal_lifecycle_gate_verified',
                 'lifecycle_archive_whole_file_identity_rechecked'):
        assert report[name] is True
    assert report['compiler_input_count'] == 220 and report['embedded_python_input_count'] == 17
    assert report['qualification_harness_count'] == 19 and report['retained_release_program_count'] == 3
    assert report['qualification_counts'] == report['exact_ci_counts'] == OWNER_COUNTS
    assert report['observation_rejection_reasons'] == [] and report['new_workloads_started'] == 0
    assert report['normal_lifecycle_reported_workflow_passed'] is False
    assert report['normal_lifecycle_reported_adoption_passed'] is False and report['normal_lifecycle_gate_passed'] is False
    assert report['normal_lifecycle_rounds'] == 4 and report['normal_lifecycle_standard_shutdown_count'] == 8
    assert len(report['normal_lifecycle_shutdowns']) == 8
    assert report['normal_lifecycle_required_failed_flags'] == [
        {'comparison': 'concurrent_cancel', 'gate': 'throughput', 'adoption_required': True}]
    fields = {'qualification': 'original_qualification_job_id', 'exact_ci': 'original_exact_ci_job_id',
              'observation': 'original_observation_job_id', 'lifecycle_materialization': 'original_lifecycle_materializer_job_id',
              'normal_lifecycle': 'original_normal_lifecycle_job_id'}
    assert all(report[field] == OWNER_JOBS[name] for name, field in fields.items())
    for name, state, code in (('observation_holder', 'succeeded', 0), ('lifecycle_holder', 'failed', 1)):
        row = report[name]
        key = 'observation' if name == 'observation_holder' else 'normal_lifecycle'
        assert row['job_id'] == OWNER_JOBS[key] and row['state'] == state and row['exit_code'] == code
        assert all(row[field] is True for field in ('complete_native_bytes_verified', 'owned_agent_reaped',
                   'owned_agent_directory_absent', 'owned_agent_socket_absent'))
    assert isinstance(report['originals'], dict) and len(report['originals']) == 150
    for name, identity in report['originals'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        assert identity['path'] == str(CACHE_OWNER / relative)
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    return report



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
         and prerequisites.get("schema") == "hepta-d1-c1-prerequisites/v1"
         and prerequisites.get("qualification_sealed") is True,
         "actual D1 qualification prerequisites are not sealed")
    need(prerequisites.get("required_missing_qualification_bindings") == [],
         "qualification prerequisite identities remain missing")
    need(isinstance(prerequisites.get("artifact_map"), dict)
         and set(prerequisites["artifact_map"]) == set(PINNED) | set(QUALIFICATION_ARTIFACTS) | set(CI_ARTIFACTS),
         "the fixed prerequisite artifact map differs")
    for name in (*PINNED, *QUALIFICATION_ARTIFACTS):
        _identity(prerequisites["artifact_map"][name], ROOT / name)
    job = prerequisites.get("qualification_original_job_id")
    need(isinstance(job, str) and JOB.fullmatch(job), "actual D1 qualification job identity is required")
    need(prerequisites.get("performance_acceptance_claim") is False,
         "diagnostic prerequisites must not claim performance adoption")
    if require_ci:
        need(prerequisites.get("exact_ci_sealed") is True
             and prerequisites.get("required_missing_exact_ci_bindings") == [],
             "actual D1 exact-CI prerequisites are not sealed")
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


def _previous_owner(prerequisites, preparation, build_inputs, bind):
    closure_id, closure = _document(prerequisites, "cache-owner-closure-inputs.json", bind)
    need(closure["schema"] == "hepta-d1-r35-cache-owner-closure/v1"
         and closure["sealed"] is True and closure["required_missing_bindings"] == []
         and closure["cache_owner"] == str(CACHE_OWNER)
         and closure["cache_path"] == str(CACHE_OWNER / "target-build"),
         "the sealed prior cache owner differs")
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "preparation does not bind the frozen cache-owner input")
    pins = closure["postflight"]
    report_id, report_raw = _declared(pins["report"], bind, retain=True)
    _, native_raw = _declared(pins["native"], bind, retain=True)
    page_raws = [_declared(pin, bind, retain=True)[1] for pin in pins["read_pages"]]
    postflight = postflight_bytes(report_raw, native_raw, page_raws, report_id)
    _declared(postflight["postflight_script"], bind)
    need(closure["inputs"] == postflight["originals"], "the actual old-owner original identity set differs")
    for identity in closure["inputs"].values():
        _declared(identity, bind)
    expected = {"inputs": closure["inputs"], "postflight": pins,
        "qualification_and_exact_ci_succeeded": True, "observation_performance_passed": True,
        "normal_lifecycle_executed": True, "normal_lifecycle_workflow_closed": True,
        "normal_lifecycle_controllers_closed": True, "normal_lifecycle_performance_passed": False,
        "original_required_failed_flags": postflight["normal_lifecycle_required_failed_flags"],
        "owned_agents_reaped": True, "original_auditors_reexecuted": False, "r35_adoption_claimed": False}
    need(preparation["cache_owner_closure"] == expected,
         "actual preparation did not record the frozen old-owner closure")
    need(preparation["cache_transferred_by_rename"] is True
         and preparation["new_full_cache_copy_bytes"] == 0 and preparation["cache_deletions"] == 0
         and preparation["cache_to_transfer"] == str(CACHE_OWNER / "target-build"),
         "the original cache transfer receipt differs")
    target = ROOT / "target-build"
    need(target.resolve() == target and target.is_dir() and not os.path.lexists(CACHE_OWNER / "target-build"),
         "the cache is not at its recorded post-rename location")
    status = target.stat()
    need((status.st_dev, status.st_ino) ==
         (postflight["cache_directory_identity"]["device"], postflight["cache_directory_identity"]["inode"]),
         "the current cache directory is not the original renamed directory")
    retained = preparation["retained_programs"]
    need(isinstance(retained, dict) and len(retained) >= 5
         and all(Path(name).is_relative_to(CACHE_OWNER / "qualification-01")
                 and isinstance(digest, str) and HEX.fullmatch(digest) for name, digest in retained.items()),
         "original retained program custody is incomplete")
    for identity in postflight["retained_release_programs"].values():
        need(retained.get(identity["path"]) == identity["sha256"], "the retained original release copy differs")
        _declared(identity, bind, maximum=64 * 1024 * 1024)
    return {"input": closure_id, "postflight": report_id, "postflight_job_id": OWNER_POSTFLIGHT_JOB,
        "original_identity_count": len(closure["inputs"]), "original_bytes_rebound": True,
        "old_preparer_cache_owner_closed_reexecuted": False,
        "current_cache_path": str(target), "cache_directory_identity_preserved": True,
        "prior_owner_performance_adopted": False, "old_auditors_reexecuted": False,
        "current_machine_idle_claimed": False,
        "retained_release_copies_rehashed": len(postflight["retained_release_programs"]),
        "retained_test_copies": "bound to the successful original preparation receipt; not rehashed by this later binder"}


def bind_d1_qualification(prerequisites, bind):
    """Read-only Q proof. This function does not require or inspect future CI success."""
    _foundation(prerequisites)
    for name in PINNED:
        _artifact(prerequisites, name, bind)
    launcher_id = _artifact(prerequisites, "prepare_qualify.py", bind)
    input_id, build_inputs = _document(prerequisites, "qualification-input.json", bind)
    patch_id, patch_raw = _artifact(prerequisites, "candidate/candidate.patch", bind, retain=True)
    patch_git_blob = hashlib.sha1(b"blob " + str(len(patch_raw)).encode("ascii") + b"\0" + patch_raw).hexdigest()
    need(patch_git_blob == "3de16de910158951dc17bb8f52883b88dd832d5a",
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
    need(build_inputs["schema"] == "hepta-d1-direct-qualification-input/v1"
         and build_inputs["sealed"] is True and build_inputs["required_missing_bindings"] == []
         and build_inputs["baseline_commit"] == build_inputs["source_construction_parent"] == BASELINE_COMMIT
         and build_inputs["preparation_tool"] == {"path": "prepare_qualify.py", "bytes": launcher_id["bytes"], "sha256": launcher_id["sha256"]},
         "frozen D1 qualification input differs")
    need(all(build_inputs[name] is None for name in ("actual_d1_qualification", "actual_d1_formatted_map",
         "actual_d1_test_counts", "actual_d1_release_programs")), "historical preparation inputs were rewritten with future results")
    need(candidate["schema"] == "hepta-r24-phase-cost-candidate/v1"
         and candidate["revision"] == candidate_manifest["revision"] == "recovery-02"
         and candidate["baseline_commit"] == candidate["git_parent"] == BASELINE_COMMIT
         and candidate_manifest["schema"] == "hepta-r24-phase-cost-preparation-package/v1"
         and candidate["nondefault_feature"] == "phase-cost-diagnostics"
         and candidate["performance_acceptance_claim"] is False
         and patch_id["sha256"] == candidate["patch_sha256"] and patch_id["bytes"] == candidate["patch_bytes"],
         "the frozen diagnostic candidate and patch do not bind")
    before, preformat = candidate["baseline_compile_inputs"], candidate["candidate_compile_inputs"]
    need(len(before) == 220 and len(preformat) == 222 and set(candidate["changed_paths"]) == CHANGED
         and set(candidate["added_paths"]) == ADDED
         and set(preformat) - set(before) == ADDED and not set(before) - set(preformat)
         and {name for name in preformat if preformat[name] != before.get(name)} == CHANGED,
         "D1 is not the exact thirteen-path/two-addition R24 patch")
    need(baseline["schema"] == "hepta-x230-composed-qualification/v1"
         and baseline.get("qualified") is True and baseline.get("finished_utc")
         and baseline["source"] == str(BASE / "source")
         and baseline["source_tested"] == baseline["source_after"] == before,
         "candidate preimage is not the accepted R24 qualification")
    need(preparation["schema"] == "hepta-x230-d1-preparation/v1"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and not preparation.get("error") and preparation["qualification_returncode"] == 0
         and preparation["automatic_retries"] == 0 and preparation["production_services_modified"] is False
         and preparation["source_baseline"] == BASELINE_COMMIT
         and preparation["performance_acceptance_claim"] is False
         and preparation["diagnostic_environment_absent"] is True
         and preparation["ordinary_supplemental_executed"] is False
         and preparation["qualification_started"] is True
         and preparation["first_actual_d1_qualification_required"] is True,
         "the actual D1 preparation did not close successfully")
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
         "the complete original D1 qualification did not pass")
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


def bind_d1_prerequisites(prerequisites, bind):
    """Add actual native exact-CI closure to the Q-only proof; never launch CI."""
    _foundation(prerequisites, require_ci=True)
    qualification = bind_d1_qualification(prerequisites, bind)
    ci_id, ci = _document(prerequisites, "rust-ci-01/report.json", bind)
    plan_id, plan = _document(prerequisites, "rust-ci-plan-01.json", bind)
    audit_id, audit = _document(prerequisites, "rust-ci-01/nextest-output-audit.json", bind)
    terminal_id, terminal = _document(prerequisites, "rust-ci-native-01.json", bind)
    native = _native(prerequisites, "exact_ci", terminal, bind)
    need(ci["schema"] == "hepta-d1-external-rust-ci/v1" and ci.get("passed") is True
         and ci.get("finished_utc") and not ci.get("error")
         and ci["automatic_retries"] == 0 and ci["production_services_modified"] is False
         and ci["owned_children_closed"] is True and ci["source_inputs_unchanged"] is True
         and ci["home_unchanged"] is True and ci["hosted_actions_passed"] is False
         and ci["original_qualification_job_id"] == qualification["original_job_id"]
         and ci["plan"] == plan_id, "actual native exact-CI receipt is incomplete or identifies another qualification")
    need(plan["schema"] == "hepta-d1-materialized-exact-rust-ci-plan/v1"
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
    need(manifest_id["sha256"] == "bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e",
         "the original 85-input CI manifest changed")
    _declared(manifest_id, bind)
    need(all(identity in plan["input_bindings"] for identity in
         (qualification["qualification"], qualification["preparation"], qualification["terminal"],
          qualification["source_map"], qualification["isolated_summary"], qualification["isolated_audit"])),
         "the original CI plan omits a qualification binding")
    binder_id = bind(ROOT / "rust-ci-prerequisites-01/d1_prerequisites.py", maximum=8 * 1024 * 1024)
    current_binder = bind(Path(__file__).resolve(), maximum=8 * 1024 * 1024)
    need(binder_id in plan["input_bindings"]
         and all(binder_id[key] == current_binder[key] for key in ("bytes", "sha256")),
         "the outer binder differs from the actual CI qualification binder")
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
