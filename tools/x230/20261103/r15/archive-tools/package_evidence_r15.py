#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen R15 configuration-only evidence; derived from reviewed R14 stable packager.

Default/--show-policy only print policy, with no gate reads. Explicit packaging
checks frozen reports once, scans the exact selection, writes and reads back a
new archive, then rechecks membership, identities and gates. No workloads,
network, subprocess, polling, retries, source reads or compiled binary reads.
"""
import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

R15 = Path('/home/qian/hepta-runtime-optimization-20261103-r15')
R14_SOURCE = Path('/home/qian/hepta-runtime-optimization-20261103-r14/source')
R14_QUAL = R14_SOURCE.parent / 'qualification-01'
RUNTIME_SHA = '51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d'
RELEASE_SHA = {'hepta-runtime': RUNTIME_SHA,
 'hepta-runtime-jobctl': '84572095b80a56ff893ea41b01e170444dc2483a49091277d0b4ada4fbc1c1b0',
 'native_process_driver': '551aa5ba0f990908d0143c34f513a0f1937f14198335c5e4a611a112b82f944e'}
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024
MAX_FILES = 300000
MANIFEST_NAME = '_evidence/selection-manifest.json'
POLICY = json.loads(r'''{"candidate_adoption_claimed":false,"credential_scan":"Original bytes, bounded decompressed gzip, and parsed JSON string fields; no redaction.","determinism":"Sorted paths; mtime=0; uid/gid=0; empty owner/gzip filename; mode 0644/0755.","execution":"Explicit --package only; default/--show-policy read no files or gates.","gate_mode":"One attempt. Missing, incomplete, changed or failed inputs stop nonzero.","gates":[{"label":"configuration_qualification","path":"configuration-qualification-01/report.json","required_true":"success","finished_utc_required":true,"stage_order":null},{"label":"local","path":"local-campaigns-01/report.json","required_true":"success","finished_utc_required":true,"stage_order":["isolated-tests","audit-isolated-tests","cancel-r14-r15","analyze-cancel-r14-r15","cancel-r11-r15","analyze-cancel-r11-r15"]},{"label":"remote","path":"remote-campaigns-01/report.json","required_true":"success","finished_utc_required":true,"stage_order":["native-r14-r15","analyze-native-r14-r15","native-r11-r15","analyze-native-r11-r15","six-host-cancel-recovery","verify-six-host-cancel-recovery"]},{"label":"qualification_audit","path":"qualification-audit-summary.json","required_true":"success","finished_utc_required":false,"stage_order":null},{"label":"performance_audit","path":"independent-performance-audit.json","required_true":"success","finished_utc_required":false,"stage_order":null},{"label":"recovery_audit","path":"independent-recovery-audit.json","required_true":"success","finished_utc_required":false,"stage_order":null},{"label":"performance_report_data","path":"performance-report-data.json","required_true":"success","finished_utc_required":false,"stage_order":null},{"label":"performance_release","path":"perf-ready-01.json","required_true":"success","finished_utc_required":false,"stage_order":null},{"label":"socket_cleanup","path":"independent-audit-tools/socket-cleanup-01.json","required_true":"success","finished_utc_required":true,"stage_order":null}],"limits":{"decompressed_file_bytes":134217728,"decompressed_total_bytes":4294967296,"file_count":300000,"raw_file_bytes":134217728,"raw_total_bytes":4294967296},"output":"Strictly new R15/evidence-package-* direct child; default evidence-package-01.","pinned_input_sha256":{"baseline-binding.json":"d701ad5c2d101ed389614083b386324c092182dcf19cb4f4bf0777e232d3c37a","configuration/configuration-ready.json":"fb4a2e8eab0bfafb0c272c4c3e259cd1d68dffbaa479796854a73a1100fcc947","configuration-qualification-01/report.json":"bce0c05b8f13e6858ecd14d024364450cc08fd90f8adabb55d5c1323c0944a89","local-campaigns-01/report.json":"b65a3d425edd91620f859ee8e14a4556b40651f4d94a022c088f7707e8a180e8","remote-campaigns-01/report.json":"defff42c03b3a7f0a7910c627b7d0c6f392064980f5b3bb4a7f8b99d0a9acafd","qualification-audit-summary.json":"5d99035bb3800fab4edcd7b21534d98f215f1a1411317999905677a81d5ae901","independent-performance-audit.json":"3a3724e5a1cfbd4daade73d68ad96f2e97aad71f47a2f948fb8d1669cacfe4db","independent-recovery-audit.json":"b276c885da5b821192ce454c6117c6fce6d7300df1164331d4d9c81b71ebbb5e","performance-report-data.json":"e8203c3477de1ebeb353dfa74affc2bbc65090d33477b74c7852a39ae0f2f2b2","run-state-01.json":"619e9d2ee317ed27a372e0253c4db7a2d2217de01bc0de2f005f23fd53f795cf","run-state-03.json":"1d1887110af045536a208f222d64f6a5719f7bb1cfc7c25e75676ca3e79930c1","local-campaigns-01/bindings/r14-qualification.json":"d6a46164b30c6677cf49ec7eea156748a8445589c71034795d016a62795610cd","local-campaigns-01/bindings/r14-implementation-ready.json":"efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442","local-campaigns-01/bindings/r14-isolated-summary.json":"25b7c25f60cc115d65a4c038912c34691f548a9103bbea82fd6366a5ce6759bb","local-campaigns-01/bindings/source-map.json":"d24d2cc040c3f3d9849112e55a076834d06d12a65ec647987c5e419c3621354c","local-campaigns-01/bindings/retained-artifacts.jsonl":"48b7515a568094403f153c68371242b7ebe534539f1c9513c1f60f91947a828a","independent-audit-tools/tooling-install-01.json":"34f0d32bcdf5057ec1cf8148a51dd13773f1235841074e0f2b8914bdfb8e461d","independent-audit-tools/environment-selftest-01.json":"0d82f2ee23f0bd5a8c92f431d7a403b413ca097b4ab0a7c53d392d15758f85fa","independent-audit-tools/allocator-tooling-review.json":"8c87efb5b5aaa0e347bcc3f8beaa61d7c66d21011daf006550a41367b30f7cbb","independent-audit-tools/local-orchestrator-ready-01.json":"f321182f6bd94b948b22948e524b5eaa0c42d08436e49ed9bf778f8a27196960","independent-audit-tools/remote-orchestrator-ready-01.json":"181c6385afeb9b253435dd15cb90c7804928512ad1e361fcfed1c644efaa2d20","independent-audit-tools/configuration-recovery-auditors-ready-01.json":"480ad67baa64c1fcf28c781335d3c707ad5c0e98151e4557f9d2c0ef21cdae22","cancel-recovery-01/report.json":"f5f80f466ce4d1f33caecc605591576d3487d9aa808023ad9502b78e8b7a698c","independent-audit-tools/frontier-assessment-before-r15.json":"bb406ff39275ab5698d7221831e583fde8d678d2c5d5a9d26545662e27faa463","performance-results.md":"50f856ef773022898495915e5382610953fe21ac824de6d816029e1f063489f7","independent-audit-tools/frontier-decision-after-r15.json":"c72943c46d2f578fbeeff2d4cb96d85928507a2fa6a3cd1418e95cc5593d0e5d","independent-audit-tools/performance-report-rendering.json":"57492c844d459a2635efda985ad48ec2a904ab9f1f44ae8e9e0e62e8de9b0098","independent-audit-tools/socket-cleanup-01.json":"48557d7cb53f4501545742a4e33497dd7cfea2e596c2a37b63a5d4b710b58024","independent-audit-tools/socket-residual-readonly-01.json":"45f86817d18b5b93a37279ef4ddee9273819f4800c0881aaa6c2508bda1176ab","independent-audit-tools/socket-residual-source-02.json":"cc7447a02609f7a848cfec9f15f5bdd6b78765833a757a2921decdb3c2b59bb3","perf-ready-01.json":"a5d865206468be9b06bf84e85645469ae0a629564df7e1a853bc40f679717435"},"preserved":["Original compressed test logs","All selected raw replies/state/fixtures","Negative results","Text bin/ssh guards","Safe arbitrary durable binary data","Public known_hosts, profile.json and ssh_config","Allocator configuration/loader/selftests and actual environment evidence","Root explicit performance-release gate and run states","Failed read-only diagnostic attempt and exact stale-socket cleanup evidence"],"private_filename_rule":"Private-key/credential/token files and .env are excluded with reasons.","prune_compiled_names":["hepta-runtime","hepta-runtime-jobctl","native_process_driver","hepta-effect-ownerctl"],"prune_compiled_suffixes":[".pyc",".pyo",".o",".obj",".a",".so",".dylib",".dll",".exe",".class",".wasm"],"prune_names":[".git","__pycache__","source","target","test-binaries","tmp","temp","temporary","unpack","unpacked","extract","extracted","node_modules"],"prune_nested_package_suffixes":[".zip",".tar",".tar.gz",".tar.bz2",".tar.xz",".tgz",".tbz2",".txz",".7z",".rar",".whl",".deb",".rpm"],"rejected":["Unsafe relative names","Selected symlinks/hardlinks/special files","ELF/PE/Mach-O content","Suspected credentials","Concurrent changes"],"report_data_sha256":"e8203c3477de1ebeb353dfa74affc2bbc65090d33477b74c7852a39ae0f2f2b2","roots":{"r15":"/home/qian/hepta-runtime-optimization-20261103-r15"},"schema":1,"scope":{"r15":{"required_files":["baseline-binding.json","perf-ready-01.json","run-state-03.json","qualification-audit-summary.json","independent-performance-audit.json","independent-recovery-audit.json","performance-report-data.json","performance-results.md"],"required_trees":["configuration","configuration-qualification-01","local-campaigns-01","remote-campaigns-01","cancel-r14-r15-01","cancel-r11-r15-01","native-r14-r15-01","native-r11-r15-01","cancel-recovery-01","measurement-tools","independent-audit-tools","archive-tools"],"root_globs":["run-state-*.json"]}},"source_binding":{"source":"/home/qian/hepta-runtime-optimization-20261103-r14/source","qualification_reused":"/home/qian/hepta-runtime-optimization-20261103-r14/qualification-01/report.json","compiler_invocations":0,"rust_source_modified":false,"complete_source_file_count":219,"release_binary_count":3,"retained_test_binary_count":5,"equality":"Frozen R14 qualification/ready/source-map snapshots equal; pinned independent R15 qualification audit rehashed current 219 source files and 8 binaries.","read_scope":"Compare frozen metadata and audit bindings only; never rehash source tree or compiled binaries."},"source_trees_included":false,"verification":"Readback without extraction; then recheck selected set, identities, and all gate hashes.","reviewed_reference":{"sha256":"126ae590f81819428db46afd3c37162ec4ffa3c2c4f795f2f978aebdca215529","git_blob_sha1":"ea8d5d0daa2ee1127071035dfd0f750456e0ccd9","stable_functions_kept":15}}''')
PINNED_INPUTS = POLICY['pinned_input_sha256']
R15_FILES = POLICY['scope']['r15']['required_files']
R15_TREES = POLICY['scope']['r15']['required_trees']
R15_GLOBS = POLICY['scope']['r15']['root_globs']
PRUNE_NAMES = POLICY['prune_names']
BINARY_NAMES = POLICY['prune_compiled_names']
PACKAGE_SUFFIXES = POLICY['prune_nested_package_suffixes']
COMPILED_SUFFIXES = POLICY['prune_compiled_suffixes']


def fail(message):
    raise RuntimeError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_relative(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '\\' in name or '\x00' in name:
        fail('Unsafe relative name')
    if any(x in ('', '.', '..') for x in name.split('/')):
        fail('Unsafe relative name')
    return p


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def open_absolute(path, final_flags):
    """Open every component with NOFOLLOW, including the absolute root chain."""
    path = Path(path)
    if not path.is_absolute() or any(x in ('.', '..') for x in path.parts):
        fail('Unsafe absolute input path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return os.open(path.name, final_flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    finally:
        os.close(fd)


def regular(st, label):
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        fail('Nonregular or hardlinked selected file: ' + label)


def compiled(head, fd, size):
    if head[:4] in (b'\x7fELF', b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                    b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                    b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                    b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
        return True
    if head[:2] == b'MZ' and len(head) >= 64:
        off = int.from_bytes(head[60:64], 'little')
        return 64 <= off <= size - 4 and os.pread(fd, 4, off) == b'PE\0\0'
    return False


def read_stable(path, label, expected=None, cap=MAX_FILE, reject_compiled=True):
    fd = open_absolute(path, os.O_RDONLY)
    try:
        before = os.fstat(fd)
        regular(before, label)
        ident = identity(before)
        if expected is not None and ident != expected:
            fail('Selected file changed: ' + label)
        if before.st_size > cap:
            fail('Input exceeds per-file cap: ' + label)
        head = os.read(fd, min(cap + 1, 65536))
        if reject_compiled and compiled(head, fd, before.st_size):
            fail('Compiled content in selected input: ' + label)
        chunks = [head]
        size = len(head)
        while size <= cap:
            chunk = os.read(fd, min(1024 * 1024, cap + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > cap or size != before.st_size or identity(os.fstat(fd)) != ident:
            fail('Unstable or oversized input: ' + label)
    finally:
        os.close(fd)
    check = open_absolute(path, os.O_RDONLY)
    try:
        if identity(os.fstat(check)) != ident:
            fail('Input replaced during read: ' + label)
    finally:
        os.close(check)
    return b''.join(chunks), ident


def json_input(rel):
    raw, ident = read_stable(R15 / rel, rel, cap=4 * 1024 * 1024)
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError):
        fail('Invalid gate JSON: ' + rel)
    if not isinstance(doc, dict):
        fail('Gate must be a JSON object: ' + rel)
    return doc, digest(raw), ident


def binds_path_hash(value, paths, sha):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            vals = list(item.values())
            if any(isinstance(v, str) and v in paths for v in vals) and sha in vals:
                return True
            if any(k in paths and v == sha for k, v in item.items()):
                return True
            stack.extend(v for v in vals if isinstance(v, (dict, list)))
        elif isinstance(item, list):
            stack.extend(item)
    return False


def check_gates():
    """One frozen evidence check; no workload launch, polling, retry or binary read."""
    docs, hashes, ids = {}, {}, {}
    def register(rel):
        safe_relative(rel)
        if rel not in hashes:
            raw, ident = read_stable(R15 / rel, rel, cap=4 * 1024 * 1024)
            hashes[rel], ids[rel] = digest(raw), ident
        return hashes[rel]
    def remember(rel):
        if rel not in docs:
            doc, sha, ident = json_input(rel)
            docs[rel], hashes[rel], ids[rel] = doc, sha, ident
        return docs[rel]
    def binding(value, rel):
        sha = register(rel)
        if not isinstance(value, dict) or value.get('path') != str(R15 / rel) or value.get('sha256') != sha:
            fail('Path/hash binding differs: ' + rel)
        if 'bytes' in value and value['bytes'] != ids[rel][4]:
            fail('Binding size differs: ' + rel)
    for gate in POLICY['gates']:
        label, rel = gate['label'], gate['path']
        doc = remember(rel)
        if doc.get(gate['required_true']) is not True:
            fail('Gate not successful: ' + label)
        if gate['finished_utc_required'] and not doc.get('finished_utc'):
            fail('Gate unfinished: ' + label)
        expected = gate['stage_order']
        if expected is not None:
            stages = doc.get('stages')
            if not isinstance(stages, list) or not all(isinstance(x, dict) for x in stages):
                fail('Invalid stage records: ' + label)
            if [x.get('name', x.get('stage')) for x in stages] != expected:
                fail('Wrong or incomplete stage order: ' + label)
            if any(type(x.get('returncode')) is not int or x['returncode'] != 0 for x in stages):
                fail('Nonzero or incomplete stage: ' + label)
            if doc.get('automatic_retries') != 0 or doc.get('compilation_started') is not False or doc.get('state') != 'completed':
                fail('Unexpected retry, compilation or pipeline state: ' + label)
    for rel, expected in sorted(PINNED_INPUTS.items()):
        if register(rel) != expected:
            fail('Frozen evidence digest differs: ' + rel)
    qrel = 'configuration-qualification-01/report.json'
    lrel, rrel = 'local-campaigns-01/report.json', 'remote-campaigns-01/report.json'
    q, local, remote = remember(qrel), remember(lrel), remember(rrel)
    qa = remember('qualification-audit-summary.json')
    perf = remember('independent-performance-audit.json')
    rec = remember('independent-recovery-audit.json')
    data = remember('performance-report-data.json')
    config = remember('configuration/configuration-ready.json')
    q14rel = 'local-campaigns-01/bindings/r14-qualification.json'
    readyrel = 'local-campaigns-01/bindings/r14-implementation-ready.json'
    maprel = 'local-campaigns-01/bindings/source-map.json'
    q14, ready, source_map = remember(q14rel), remember(readyrel), remember(maprel)
    source = ready.get('source_after')
    if (ready.get('ready') is not True or ready.get('source_frozen') is not True
            or ready.get('source_count') != 219 or not isinstance(source, dict)
            or len(source) != 219 or q14.get('qualified') is not True
            or q14.get('source_tested') != source or q14.get('source_after') != source or source_map != source):
        fail('Frozen R14 219-file qualification/ready/source-map snapshots differ')
    if (q.get('source') != str(R14_SOURCE) or q.get('qualification_reused') != str(R14_QUAL / 'report.json')
            or q.get('r14_qualification_sha256') != hashes[q14rel]
            or q.get('source_manifest_sha256') != hashes[maprel] or q.get('source_files') != 219
            or q.get('source_tested_after_current_frozen_equal') is not True
            or q.get('compiler_invocations') != 0 or q.get('rust_source_modified') is not False
            or q.get('automatic_retries') != 0):
        fail('Configuration qualification does not bind unchanged R14 inputs')
    if (qa.get('qualification_report_sha256') != hashes[qrel]
            or qa.get('reused_r14_qualification_report_sha256') != hashes[q14rel]
            or qa.get('source_map_sha256') != hashes[maprel] or qa.get('source_input_count') != 219
            or qa.get('source_tested_after_current_equal') is not True
            or qa.get('source_matches_frozen_implementation') is not True
            or qa.get('compiler_invocations') != 0 or qa.get('rust_source_modified') is not False):
        fail('Independent qualification audit does not bind frozen/current R14 source')
    tests = {'passed': 1637, 'failed': 0, 'ignored': 33, 'selected': 1670, 'retries': 0}
    observations = {'verified': 1647, 'unavailable_process_exited': 0}
    env = {'MALLOC_ARENA_MAX': '1'}
    for label, doc in [('configuration', q), ('qualification-audit', qa)]:
        if any(doc.get('tests', {}).get(k) != v for k, v in tests.items()):
            fail('Unexpected test totals: ' + label)
        if doc.get('allocator_environment') != env or doc.get('allocator_observation_counts') != observations:
            fail('Allocator/test environment proof differs: ' + label)
        if doc.get('configuration_ready_sha256') != hashes['configuration/configuration-ready.json']:
            fail('Configuration-ready binding differs: ' + label)
    for flag in ['executed_binary_bindings_matched', 'r14_identity_and_status_inventory_unchanged',
                 'strict_stdout_and_inventory_audit_passed']:
        if qa['tests'].get(flag) is not True:
            fail('Strict test inventory proof missing: ' + flag)
    if q.get('runtime_sha256') != RUNTIME_SHA or q.get('release_binaries') != q14.get('binaries'):
        fail('Reused release artifacts differ from R14 qualification')
    if set(q['release_binaries']) != set(RELEASE_SHA):
        fail('Release artifact set differs')
    qa_input = qa.get('input_sha256', {})
    for name, sha in RELEASE_SHA.items():
        expected = {'path': str(R14_QUAL / name), 'sha256': sha}
        if q['release_binaries'][name] != expected:
            fail('Release identity differs: ' + name)
        row = qa.get('release_binaries', {}).get(name, {})
        if row.get('path') != expected['path'] or row.get('sha256') != sha or qa_input.get(expected['path']) != sha:
            fail('Independent release rehash proof differs: ' + name)
    retained = q.get('retained_test_binaries')
    independent = qa.get('retained_test_binaries')
    if not isinstance(retained, list) or not isinstance(independent, list) or len(retained) != 5 or len(independent) != 5:
        fail('Exactly five retained test executable identities required')
    original = {x['path']: x['sha256'] for x in retained}
    checked = {x['path']: x['sha256'] for x in independent}
    if len(original) != 5 or original != checked or any(qa_input.get(p) != h for p, h in checked.items()):
        fail('Retained test executable digest proofs differ')
    if any(Path(p).parent != R14_QUAL / 'test-binaries' for p in checked):
        fail('Unexpected retained executable path')
    for rel, original_path in [(maprel, R14_QUAL / 'source-map.json'),
            (q14rel, R14_QUAL / 'report.json'),
            (readyrel, R14_SOURCE.parent / 'implementation-ready.json'),
            ('local-campaigns-01/bindings/retained-artifacts.jsonl', R14_QUAL / 'retained-artifacts.jsonl')]:
        if qa_input.get(str(original_path)) != register(rel):
            fail('Independent metadata snapshot binding differs: ' + rel)
    if q.get('artifacts_sha256') != register('local-campaigns-01/bindings/retained-artifacts.jsonl'):
        fail('Reused retained inventory digest differs')
    binding(q.get('summary'), 'configuration-qualification-01/isolated-tests/summary.json')
    binding(q.get('audit'), 'configuration-qualification-01/isolated-audit.json')
    if config.get('success') is not True or config.get('selected_arena_max') != '1':
        fail('Frozen configuration is not arena 1')
    expected_config = {'README.md', 'allocator-policy.json', 'hepta-runtime-x230-glibc.sh',
                       'loader-precedence.json', 'validate_configuration.py', 'wrapper-validation.json'}
    if set(config.get('files', {})) != expected_config:
        fail('Configuration file inventory differs')
    for name, row in config['files'].items():
        rel = 'configuration/' + name
        if row.get('sha256') != register(rel) or row.get('bytes') != ids[rel][4]:
            fail('Configuration file digest differs: ' + name)
    binding(local.get('configuration_qualification'), qrel)
    binding(remote.get('configuration_qualification'), qrel)
    binding(remote.get('local_gate'), lrel)
    if (remote['local_gate'].get('success') is not True
            or remote['local_gate'].get('configuration_qualification_sha256') != hashes[qrel]):
        fail('Remote local/config gate proof differs')
    release = remember('perf-ready-01.json')
    if (release.get('release_performance') is not True or release.get('archive_io_finished') is not True
            or release.get('configuration_qualification_sha256') != hashes[qrel]
            or release.get('configuration_qualification_path') != str(R15 / qrel)
            or release.get('configuration_ready_sha256') != hashes['configuration/configuration-ready.json']
            or release.get('candidate_runtime_sha256') != RUNTIME_SHA):
        fail('Explicit root performance release is not bound to this configuration')
    wait = local.get('performance_gate_wait', {})
    if wait.get('passed') is not True or wait.get('wait_attempts') != 1:
        fail('Performance release was not consumed by one bounded wait')
    binding(wait.get('gate'), 'perf-ready-01.json')
    for label, doc in [('performance-audit', perf), ('performance-data', data)]:
        if doc.get('candidate_sha256') != RUNTIME_SHA or doc.get('candidate_allocator_environment') != env:
            fail('Performance candidate identity differs: ' + label)
        gate = doc.get('gate_proof', {})
        for key, rel in [('configuration_qualification_sha256', qrel), ('local_report_sha256', lrel), ('remote_report_sha256', rrel)]:
            if gate.get(key) != hashes[rel]:
                fail('Performance pipeline binding differs: ' + label + '/' + key)
    binding(perf.get('performance_report_data'), 'performance-report-data.json')
    for rel in (qrel, lrel, rrel):
        if perf.get('input_sha256', {}).get(str(R15 / rel)) != hashes[rel]:
            fail('Independent performance audit input binding differs: ' + rel)
        if rec.get('gate_input_sha256', {}).get(str(R15 / rel)) != hashes[rel]:
            fail('Independent recovery audit input binding differs: ' + rel)
    if (rec.get('candidate_sha256') != RUNTIME_SHA or rec.get('allocator_environment') != env
            or rec.get('qualification_audit_sha256') != hashes['qualification-audit-summary.json']
            or rec.get('raw_report_sha256') != hashes['cancel-recovery-01/report.json']):
        fail('Independent recovery candidate/qualification/raw binding differs')
    rec_counts = {'hosts': 6, 'native_replies': 90, 'ssh_probes': 36,
                  'ssh_stdout_and_stderr_files': 72, 'embedded_artifacts_rehashed': 150,
                  'embedded_artifact_bytes_rehashed': 224885, 'new_starts': 6,
                  'same_key_lookups': 12, 'cancel_calls': 12,
                  'extra_read_only_terminal_polls': 0, 'automatic_rpc_retries': 0}
    if rec.get('counts') != rec_counts:
        fail('Recovery independent counts differ')
    live = rec.get('allocator_environment_verification', {})
    if live.get('verified') is not True or live.get('controllers_with_live_environment') != 3:
        fail('Recovery must bind three actual live allocator environments')
    for flag in ['controller_sigkill_confirmed', 'owned_rog_ssh_master_sigkill_confirmed',
                 'master_generation_replaced', 'network_and_services_unchanged']:
        if rec.get('faults', {}).get(flag) is not True:
            fail('Recovery fault proof differs: ' + flag)
    for pipeline, cases, suffixes in [
            (local, ['cancel-r14-r15-01', 'cancel-r11-r15-01'],
             ['report.json', 'independent-summary.json', 'independent-summary.md']),
            (remote, ['native-r14-r15-01', 'native-r11-r15-01', 'cancel-recovery-01'],
             ['report.json', 'independent-summary.json'])]:
        for case in cases:
            for suffix in suffixes:
                rel = case + '/' + suffix
                sha = register(rel)
                if not binds_path_hash(pipeline.get('retained_result_files'), {str(R15 / rel), rel}, sha):
                    fail('Pipeline retained result binding differs: ' + rel)
    state = remember('run-state-03.json')
    for field, rel in [('configuration_qualification', qrel), ('local_report', lrel),
                       ('remote_report', rrel), ('performance_release', 'perf-ready-01.json')]:
        binding(state.get(field), rel)
    if (state.get('formal_campaigns_completed') is not True or state.get('new_compilation') is not False
            or state.get('source_modified') is not False or state.get('automatic_retries') != 0):
        fail('Root frozen run state differs')
    cleanup = remember('independent-audit-tools/socket-cleanup-01.json')
    after = cleanup.get('after', {})
    if (cleanup.get('signals_sent') != 0 or len(cleanup.get('removed', [])) != 8
            or after.get('parent_exists') is not False or after.get('pool_exists') is not False
            or set(after.get('selected_sockets_exist', {})) != {'m-13', 'm-15', 'm-19', 'm-21', 'm-23', 'm-55'}
            or any(after['selected_sockets_exist'].values())):
        fail('Owned stale socket cleanup proof incomplete')
    return hashes, ids


def check_packager_ready(expected, hashes, ids):
    if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
        fail('Explicit --expected-ready-sha256 is required for packaging')
    rel = 'archive-tools/package-ready-01.json'
    ready, sha, ident = json_input(rel)
    if sha != expected or ready.get('success') is not True:
        fail('Packager ready identity differs')
    hashes[rel], ids[rel] = sha, ident
    files = ready.get('files', {})
    if set(files) != {'package_evidence_r15.py', 'selection-rules-01.json', 'static-review-01.json'}:
        fail('Packager ready file inventory differs')
    for name, row in files.items():
        rel = 'archive-tools/' + name
        raw, ident = read_stable(R15 / rel, rel, cap=1024 * 1024)
        sha = digest(raw)
        if row.get('sha256') != sha or row.get('bytes') != len(raw):
            fail('Reviewed packager input changed: ' + name)
        hashes[rel], ids[rel] = sha, ident


def verify_audited_selection(selected, gate_hashes):
    """Compare selected bytes to existing independent input bindings; no source/binary read."""
    verified = {}
    external = set()
    for rel, fields in [
            ('qualification-audit-summary.json', ['input_sha256']),
            ('independent-performance-audit.json', ['input_sha256']),
            ('independent-recovery-audit.json', ['input_sha256', 'gate_input_sha256'])]:
        raw, _ = read_stable(R15 / rel, rel, cap=4 * 1024 * 1024)
        if digest(raw) != gate_hashes[rel]:
            fail('Independent audit changed before selection validation')
        doc = json.loads(raw)
        for field in fields:
            values = doc.get(field)
            if not isinstance(values, dict):
                fail('Independent input digest map absent: ' + rel + '/' + field)
            for path, expected in values.items():
                p = Path(path)
                if not p.is_absolute() or not re.fullmatch(r'[0-9a-f]{64}', expected):
                    fail('Invalid independent input digest binding')
                try:
                    within = p.relative_to(R15)
                except ValueError:
                    external.add(path)
                    continue
                name = 'r15/' + str(within)
                safe_relative(name)
                if name not in selected or selected[name]['sha256'] != expected:
                    fail('Archived input differs from independent audit: ' + name)
                verified[name] = expected
    for rel, expected in gate_hashes.items():
        name = 'r15/' + rel
        if name not in selected or selected[name]['sha256'] != expected:
            fail('Archived input differs from frozen gate: ' + name)
    return {'unique_selected_input_bindings': len(verified),
            'gate_bindings': len(gate_hashes),
            'external_source_and_binary_binding_paths_not_reread': len(external)}


PRIVATE_NAME = re.compile(r'(^|[._-])(credentials?|secrets?|passwords?|tokens?|private[._-]?keys?)([._-]|$)', re.I)
PRIVATE_SUFFIXES = ('.pem', '.key', '.p12', '.pfx', '.p8', '.keystore')


def exclusion(name):
    n = name.lower()
    if n in PRUNE_NAMES or n.startswith(('tmp-', 'temp-', 'unpack-', 'extract-', 'evidence-package-')):
        return 'pruned build/cache/temporary/output subtree'
    if n in BINARY_NAMES or n.removesuffix('.exe') in BINARY_NAMES:
        return 'named compiled executable; existing reported hashes remain evidence'
    if n.endswith(tuple(COMPILED_SUFFIXES)) or re.search(r'\.so\.\d', n):
        return 'compiled-file extension'
    if n.endswith(tuple(PACKAGE_SUFFIXES)):
        return 'nested package/archive'
    if n == '.env' or n.startswith('.env.') or n in ('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'):
        return 'private credential/key filename'
    if n.endswith(PRIVATE_SUFFIXES) or PRIVATE_NAME.search(n):
        return 'private credential/key/token filename'
    return None


def collect():
    selected, excluded = {}, {}
    total = 0

    def visit(parent_fd, name, alias, relative):
        nonlocal total
        safe_relative(relative)
        arc = alias + '/' + relative
        why = exclusion(name)
        if why:
            excluded[arc] = why
            return
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            fail('Selected symlink: ' + arc)
        if stat.S_ISDIR(st.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            try:
                if identity(os.fstat(child)) != identity(st):
                    fail('Directory changed during traversal: ' + arc)
                for entry in sorted(os.listdir(child)):
                    visit(child, entry, alias, relative + '/' + entry)
            finally:
                os.close(child)
            return
        regular(st, arc)
        if arc in selected:
            if selected[arc]['identity'] != identity(st):
                fail('Duplicate input identity changed: ' + arc)
            return
        if st.st_size > MAX_FILE:
            fail('Selected input exceeds per-file cap: ' + arc)
        total += st.st_size
        if total > MAX_TOTAL or len(selected) >= MAX_FILES:
            fail('Selected evidence exceeds total/file-count limits')
        root = R15
        selected[arc] = {'path': root / relative, 'identity': identity(st),
                         'size': st.st_size, 'mode': 0o755 if st.st_mode & 0o111 else 0o644}

    def select(alias, root, rel):
        safe_relative(rel)
        parent = open_absolute(root / PurePosixPath(rel).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            visit(parent, PurePosixPath(rel).name, alias, rel)
        finally:
            os.close(parent)

    def select_glob(alias, root, pattern, required=False):
        p = safe_relative(pattern)
        parent = open_absolute(root / p.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            matches = [x for x in sorted(os.listdir(parent)) if fnmatch.fnmatchcase(x, p.name)]
            if required and not matches:
                fail('Required selection pattern has no matches: ' + alias + '/' + pattern)
            for name in matches:
                rel = name if str(p.parent) == '.' else str(p.parent / name)
                visit(parent, name, alias, rel)
        finally:
            os.close(parent)

    for rel in R15_FILES + R15_TREES:
        select('r15', R15, rel)
    for pattern in R15_GLOBS:
        select_glob('r15', R15, pattern)
    return selected, excluded


# Patterns require actual credential-shaped values. Plain names, paths and these
# regex source definitions do not match themselves. No matching value is emitted.
SECRET_PATTERNS = [re.compile(x, re.I if flags else 0) for x, flags in [
    (rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', False),
    (rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b', False),
    (rb'\bgh[pousr]_[A-Za-z0-9]{32,}\b', False),
    (rb'\bgithub_pat_[A-Za-z0-9_]{40,}\b', False),
    (rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', False),
    (rb'\bxox[baprs]-[A-Za-z0-9-]{20,}\b', False),
    (rb'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{12,}\b', False),
    (rb'\bBearer[ \t]+[A-Za-z0-9._~+/-]{24,}={0,2}', True),
    (rb'["\x27]?(?:access_token|refresh_token|api_key|secret_key|password)["\x27]?[ \t]*[:=][ \t]*["\x27]?[A-Za-z0-9_+/-]{24,}={0,2}', True),
]]
SENSITIVE_FIELD = re.compile(r'^(?:access_token|refresh_token|api_key|secret_key|password|authorization)$', re.I)
TOKEN_VALUE = re.compile(r'^(?:Bearer\s+)?[A-Za-z0-9._~+/-]{24,}={0,2}$', re.I)
PLACEHOLDER = re.compile(r'^(?:redacted|masked|placeholder|example|dummy|not[_-]?set|none|null|false|true)$', re.I)


def scan_bytes(data, label):
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        fail('Suspected credential in selected evidence: ' + label)


def scan_json(value, label):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            scan_bytes(item.encode('utf-8', errors='surrogatepass'), label)
        elif isinstance(item, dict):
            for key, value in item.items():
                stack.append(key)
                if isinstance(value, str) and SENSITIVE_FIELD.fullmatch(str(key)):
                    val = value.strip()
                    if TOKEN_VALUE.fullmatch(val) and not PLACEHOLDER.fullmatch(val):
                        fail('Suspected credential in structured field: ' + label)
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)


def scan_payload(data, label):
    scan_bytes(data, label)
    documents = []
    try:
        documents.append(json.loads(data))
    except (ValueError, UnicodeError, RecursionError):
        # Invalid JSON fixtures remain byte-for-byte evidence. Valid JSONL rows
        # still receive decoded-string scanning, including escaped key headers.
        for line in io.BytesIO(data):
            if line.lstrip().startswith((b'{', b'[', b'"')):
                try:
                    documents.append(json.loads(line))
                except (ValueError, UnicodeError, RecursionError):
                    pass
    structured_documents = len(documents)  # Record BEFORE consuming the stack.
    for document in documents:
        scan_json(document, label)
    return structured_documents


def scan_and_hash(selected):
    expanded_total = 0
    for arc in sorted(selected):
        entry = selected[arc]
        raw, _ = read_stable(entry['path'], arc, entry['identity'])
        scan_payload(raw, arc)
        if arc.endswith('.gz'):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as z:
                    decoded = z.read(MAX_FILE + 1)
            except (OSError, EOFError):
                fail('Compressed evidence could not be credential-scanned: ' + arc)
            if len(decoded) > MAX_FILE:
                fail('Decompressed evidence exceeds per-file cap: ' + arc)
            expanded_total += len(decoded)
            if expanded_total > MAX_TOTAL:
                fail('Decompressed evidence exceeds total cap')
            scan_payload(decoded, arc + ' (decompressed)')
        entry['sha256'] = digest(raw)


def manifest(selected, excluded, gate_hashes):
    return {
        'schema': 1, 'candidate_adoption_claimed': False,
        'qualification_claimed_by_packager': False,
        'policy_sha256': digest(encoded(POLICY)),
        'gate_hashes': {'r15/' + k: v for k, v in sorted(gate_hashes.items())},
        'included': [{'path': arc, 'size': e['size'], 'sha256': e['sha256'],
                      'mode': format(e['mode'], '04o')} for arc, e in sorted(selected.items())],
        'excluded': [{'path': p, 'reason': why} for p, why in sorted(excluded.items())],
    }


def member_info(name, size, mode):
    safe_relative(name)
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, mode, 0
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    return info


def write_archive(path, selected, manifest_bytes):
    with path.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0, compresslevel=6) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name in sorted(list(selected) + [MANIFEST_NAME]):
                    if name == MANIFEST_NAME:
                        raw, mode = manifest_bytes, 0o644
                    else:
                        entry = selected[name]
                        raw, _ = read_stable(entry['path'], name, entry['identity'])
                        if digest(raw) != entry['sha256']:
                            fail('Selected content changed while packing: ' + name)
                        mode = entry['mode']
                    tar.addfile(member_info(name, len(raw), mode), io.BytesIO(raw))
        output.flush()
        os.fsync(output.fileno())


def verify_archive(path, selected, manifest_bytes):
    expected = {name: (e['size'], e['sha256'], e['mode']) for name, e in selected.items()}
    expected[MANIFEST_NAME] = (len(manifest_bytes), digest(manifest_bytes), 0o644)
    seen = set()  # Constant-time membership even for hundreds of thousands of files.
    with tarfile.open(path, mode='r|gz') as tar:
        for member in tar:
            name = member.name
            safe_relative(name)
            if name not in expected or name in seen or not member.isfile():
                fail('Unexpected/duplicate/nonregular archive member')
            size, sha, mode = expected[name]
            if (member.size, member.mode, member.uid, member.gid, member.mtime,
                    member.uname, member.gname) != (size, mode, 0, 0, 0, '', ''):
                fail('Archive metadata mismatch: ' + name)
            stream = tar.extractfile(member)
            h, count = hashlib.sha256(), 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                h.update(chunk)
            if count != size or h.hexdigest() != sha:
                fail('Archive readback hash mismatch: ' + name)
            seen.add(name)
    if seen != set(expected):
        fail('Archive member set is incomplete')


def recheck(selected, excluded, gate_hashes, gate_ids):
    current, current_excluded = collect()
    if set(current) != set(selected) or current_excluded != excluded:
        fail('Selected/excluded evidence set changed during packaging')
    if any(current[p]['identity'] != selected[p]['identity'] for p in selected):
        fail('Selected evidence identity changed during packaging')
    # A final readback checks the same exact gate bytes, without re-running work.
    for rel, sha in gate_hashes.items():
        raw, _ = read_stable(R15 / rel, rel, gate_ids[rel], cap=4 * 1024 * 1024)
        if digest(raw) != sha:
            fail('Gate content changed during packaging: ' + rel)


def output_path(value):
    p = Path(value)
    if not p.is_absolute():
        p = R15 / p
    if p.parent != R15 or not re.fullmatch(r'evidence-package-[A-Za-z0-9][A-Za-z0-9._-]*', p.name):
        fail('Output must be a new evidence-package-* direct child of R15')
    return p


def write_new(path, raw):
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def file_meta(path):
    before = path.stat()
    size = before.st_size
    sha256 = hashlib.sha256()
    git = hashlib.sha1(b'blob ' + str(size).encode() + b'\0')
    count = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            count += len(chunk)
            sha256.update(chunk)
            git.update(chunk)
    if count != size or identity(path.stat()) != identity(before):
        fail('New output changed during metadata hashing: ' + path.name)
    return {'path': path.name, 'bytes': size, 'sha256': sha256.hexdigest(),
            'git_blob_sha1': git.hexdigest()}


def package(value, expected_ready):
    destination = output_path(value)  # Lexical only; no directory or gate read.
    gate_hashes, gate_ids = check_gates()
    check_packager_ready(expected_ready, gate_hashes, gate_ids)
    rules, _ = read_stable(R15 / 'archive-tools/selection-rules-01.json', 'selection-rules-01.json', cap=1024 * 1024)
    if rules != encoded(POLICY):
        fail('Selection rules differ from this packager policy')
    selected, excluded = collect()
    scan_and_hash(selected)
    audited_bindings = verify_audited_selection(selected, gate_hashes)
    manifest_bytes = encoded(manifest(selected, excluded, gate_hashes))
    destination.mkdir(mode=0o700, exist_ok=False)
    partial = destination / 'evidence.tar.gz.partial'
    write_archive(partial, selected, manifest_bytes)
    verify_archive(partial, selected, manifest_bytes)
    recheck(selected, excluded, gate_hashes, gate_ids)
    archive = destination / 'r15-original-evidence-01.tar.gz'
    os.link(partial, archive)  # Exclusive publication: never overwrite a target.
    partial.unlink()
    selection = destination / 'selection-manifest.json'
    write_new(selection, manifest_bytes)
    selection_gz = destination / 'archive-selection-01.json.gz'
    write_new(selection_gz, gzip.compress(manifest_bytes, compresslevel=6, mtime=0))
    result = {'schema': 'hepta-r15-configuration-evidence-archive/v1', 'success': True,
              'candidate_adoption_claimed': False,
              'archive': file_meta(archive), 'selection_index': file_meta(selection_gz),
              'uncompressed_selection': file_meta(selection),
              'selected_file_count': len(selected), 'tar_member_count': len(selected) + 1,
              'selected_bytes': sum(e['size'] for e in selected.values()),
              'excluded_path_count': len(excluded),
              'gate_hashes': {'r15/' + k: v for k, v in sorted(gate_hashes.items())},
              'archive_member_hashes_verified': True, 'selected_set_rechecked': True,
              'independent_input_bindings_verified': audited_bindings,
              'known_credential_pattern_matches': 0,
              'credential_scan_scope': 'Original bytes, bounded decompressed gzip, and parsed JSON strings.',
              'source_trees_included': False, 'compiled_binaries_included': False}
    write_new(destination / 'package-result.json', encoded(result))
    write_new(destination / 'archive-summary-01.json', encoded(result))
    print(encoded(result).decode(), end='')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--show-policy', action='store_true')
    action.add_argument('--package', action='store_true')
    parser.add_argument('--output', default='evidence-package-01')
    parser.add_argument('--expected-ready-sha256')
    args = parser.parse_args()
    if not args.package:
        print(encoded(POLICY).decode(), end='')
        return 0
    try:
        package(args.output, args.expected_ready_sha256)
    except (OSError, RuntimeError, ValueError, tarfile.TarError) as error:
        print('Evidence packaging stopped: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
