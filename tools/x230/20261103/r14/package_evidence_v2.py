#!/usr/bin/env python3
"""Reviewed v2: deterministic frozen R14 evidence, including both diagnostics.

Default and --show-policy only print the built-in policy. They read no gates.
No task launch, network, subprocess, polling, retry, or source/binary rehashing.
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

R14 = Path('/home/qian/hepta-runtime-optimization-20261103-r14')
R12 = Path('/home/qian/hepta-runtime-optimization-20261103-r12')
READY_SHA = 'efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442'
REPORT_SHA = 'ffa94324ddc72f4a7fe1976621d22e9fe052990b9697eded9917667e52b4c0fd'
PINNED_INPUTS = {
    "implementation-ready.json": "efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442",
    "report-data.json": "ffa94324ddc72f4a7fe1976621d22e9fe052990b9697eded9917667e52b4c0fd",
    "qualification-01/report.json": "d6a46164b30c6677cf49ec7eea156748a8445589c71034795d016a62795610cd",
    "local-campaigns-01/report.json": "3371dbffb2240eb33fc5a0792a87f0c4e5382d46caf6e46a6c7ddf1b46dbcdd5",
    "remote-campaigns-01/report.json": "de3feacde5b7cee903a51207483e59e2678fa6388d3c6c95ea31c2bb358527e4",
    "qualification-audit-summary.json": "667e9e966b43ce1e14c228b0ab7ab9b8fc017c26c95a41adba4e97cea1487ff3",
    "independent-performance-audit.json": "03e030f4329b0037069ba63687e1a1ebcaf42ccba472b026d8d5b5ddffe0dba7",
    "independent-recovery-audit.json": "128d0408c8674b21c5c53cd11f46bdeafdcdbd803bebc9a70a3e66be54fa982e",
    "diagnostic-summary.json": "053996e41ebb0b29d9e76f92ed381bb7af0c9db5a22298ae2d92cb6803586020",
    "thread-arena-diagnostic-01/report.json": "1395c0e75c4c53e10386d7865e3e2f45c7f44bab184d7dffeb9e461dfb600937",
    "thread-arena-diagnostic-02/report.json": "20a37ece2406a3aaeb0819bb4ecd2c0d4cdb2fcdafc785a4687077ebbe184889",
    "diagnostic-tools/probe_cancel_threads.py": "67e26e38b16ae9c829fe66b75e766217ea83951529e4e1462ecd451154c82e1c",
    "diagnostic-tools/probe_cancel_arenas_1_4.py": "179ad5088edcaa9db66dcf3e6d2c09e0a10b94c4103809196df9f1d4e3e5da5d",
    "diagnostic-tools/summarize_arena_diagnostics.py": "deac0afa61c84cfb9c5e111d77adde6a0e103efbb77997f8d397fa8609d7b7ad",
    "qualification-01/source-map.json": "d24d2cc040c3f3d9849112e55a076834d06d12a65ec647987c5e419c3621354c",
    "publication-r14/tests/evidence/20261103-x230-r14/compile-input-manifest.json": "6d80a964576e8ad4c21cbd3cd21950bc22cc694184901440f7f519df8f9dad45"
}
DRAFT_SHA = '71866c55744f06e31414d51bdd07f2e83c14f4eecb7f9139cbd3f352d0151d9c'
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024
MAX_FILES = 300000
MANIFEST_NAME = '_evidence/selection-manifest.json'
Q_STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
            'isolated-tests', 'audit-isolated-tests', 'release']
L_STAGES = ['cancel_r13_r14-campaign', 'cancel_r13_r14-analysis',
            'cancel_r11_r14-campaign', 'cancel_r11_r14-analysis']
R_STAGES = ['native-observation', 'analyze-native',
            'six-host-cancel-recovery', 'verify-recovery']
GATES = [
    ('qualification', 'qualification-01/report.json', 'qualified', Q_STAGES),
    ('local', 'local-campaigns-01/report.json', 'success', L_STAGES),
    ('remote', 'remote-campaigns-01/report.json', 'success', R_STAGES),
    ('qualification_audit', 'qualification-audit-summary.json', 'success', None),
    ('performance_audit', 'independent-performance-audit.json', 'success', None),
    ('recovery_audit', 'independent-recovery-audit.json', 'success', None),
    ('diagnostic_01', 'thread-arena-diagnostic-01/report.json', 'success', None),
    ('diagnostic_02', 'thread-arena-diagnostic-02/report.json', 'success', None),
    ('diagnostic_summary', 'diagnostic-summary.json', 'success', None),
]
R14_FILES = [
    'build-preflight-01.json', 'implementation-ready.json', 'baseline-binding.json',
    'source-diff.patch', 'format-01.json', 'qualification-launch-01.py',
    'implementation-design-and-frontier.md', 'preparation-call-sites.txt',
    'github-compiler-tree-verification-01.json', 'publication-r14-manifest.json',
    'publication-r14/preupload-complete.json',
    'publication-r14/tests/evidence/20261103-x230-r14/compile-input-manifest.json',
    'qualification-audit-summary.json', 'independent-performance-audit.json',
    'independent-recovery-audit.json', 'report-data.json', 'diagnostic-summary.json',
]
R14_TREES = [
    'qualification-01', 'local-campaigns-01', 'remote-campaigns-01',
    'cancel-r13-r14-01', 'cancel-r11-r14-01', 'native-r11-r14-01',
    'measurement-tools', 'independent-audit-tools', 'archive-tools',
    'publication-r14/receipts',
    'diagnostic-tools', 'thread-arena-diagnostic-01', 'thread-arena-diagnostic-02',
]
R14_GLOBS = ['format-01.stdout*', 'format-01.stderr*',
             'runner-validation-*.json', 'run-state-*.json']
PRUNE_NAMES = [
    '.git', '__pycache__', 'source', 'target', 'test-binaries', 'tmp', 'temp', 'temporary',
    'unpack', 'unpacked', 'extract', 'extracted', 'node_modules',
]
BINARY_NAMES = ['hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver', 'hepta-effect-ownerctl']
PACKAGE_SUFFIXES = ['.zip', '.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.tgz',
                    '.tbz2', '.txz', '.7z', '.rar', '.whl', '.deb', '.rpm']
COMPILED_SUFFIXES = ['.pyc', '.pyo', '.o', '.obj', '.a', '.so', '.dylib',
                     '.dll', '.exe', '.class', '.wasm']
POLICY = {
    'schema': 1,
    'candidate_adoption_claimed': False,
    'execution': 'Explicit --package only; default/--show-policy read no files or gates.',
    'gate_mode': 'One attempt. Missing, incomplete, changed or failed inputs stop nonzero.',
    'roots': {'r14': str(R14), 'r12': str(R12)},
    'gates': [{'label': a, 'path': b, 'required_true': c,
               'finished_utc_required': d is not None or a in ('diagnostic_01', 'diagnostic_02'), 'stage_order': d}
              for a, b, c, d in GATES],
    'source_binding': {
        'implementation_ready_sha256': READY_SHA,
        'complete_source_file_count_attested_by_pinned_ready': 219,
        'equality': 'qualification.source_tested == qualification.source_after == ready.source_after',
        'read_scope': 'Compare existing reports only; never rehash source tree or compiled binaries.',
    },
    'report_data_sha256': REPORT_SHA,
    'reviewed_from_draft_sha256': DRAFT_SHA,
    'pinned_input_sha256': PINNED_INPUTS,
    'source_trees_included': False,
    'diagnostic_scope': 'Both frozen diagnostic runs and independently recomputed summary; separate from formal throughput evidence.',
    'scope': {
        'r14': {'required_files': R14_FILES, 'required_trees': R14_TREES,
                'root_globs': R14_GLOBS},
        'r12': {'required_trees': ['r14-candidate-cancel-recovery-01'],
                'required_globs': []},
    },
    'prune_names': PRUNE_NAMES,
    'prune_compiled_names': BINARY_NAMES,
    'prune_compiled_suffixes': COMPILED_SUFFIXES,
    'prune_nested_package_suffixes': PACKAGE_SUFFIXES,
    'private_filename_rule': 'Private-key/credential/token files and .env are excluded with reasons.',
    'preserved': ['Original compressed test logs', 'All selected raw replies/state/fixtures',
                  'Negative results', 'Text bin/ssh guards', 'Safe arbitrary durable binary data',
                  'Public known_hosts, profile.json and ssh_config',
                  'Original GitHub proof including qualification_claimed=false'],
    'rejected': ['Unsafe relative names', 'Selected symlinks/hardlinks/special files',
                 'ELF/PE/Mach-O content', 'Suspected credentials', 'Concurrent changes'],
    'credential_scan': 'Original bytes, bounded decompressed gzip, and parsed JSON string fields; no redaction.',
    'limits': {'raw_file_bytes': MAX_FILE, 'raw_total_bytes': MAX_TOTAL,
               'decompressed_file_bytes': MAX_FILE, 'decompressed_total_bytes': MAX_TOTAL,
               'file_count': MAX_FILES},
    'output': 'Strictly new R14/evidence-package-* direct child; default evidence-package-01.',
    'determinism': 'Sorted paths; mtime=0; uid/gid=0; empty owner/gzip filename; mode 0644/0755.',
    'verification': 'Readback without extraction; then recheck selected set, identities, and all gate hashes.',
}


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
    raw, ident = read_stable(R14 / rel, rel, cap=4 * 1024 * 1024)
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
    """This is the only gate attempt. It never starts or waits for work."""
    docs, hashes, ids = {}, {}, {}
    for label, rel, field, expected in GATES:
        doc, sha, ident = json_input(rel)
        if doc.get(field) is not True:
            fail('Gate not successful: ' + label)
        if expected is not None or label in ('diagnostic_01', 'diagnostic_02'):
            if not isinstance(doc.get('finished_utc'), str) or not doc['finished_utc'].strip():
                fail('Gate unfinished: ' + label)
        if expected is not None:
            stages = doc.get('stages')
            if not isinstance(stages, list) or not all(isinstance(x, dict) for x in stages):
                fail('Invalid stages: ' + label)
            names = [x.get('name', x.get('stage')) for x in stages]
            if names != expected:
                fail('Wrong or incomplete stage order: ' + label)
            if any(type(x.get('returncode')) is not int or x['returncode'] != 0 for x in stages):
                fail('Nonzero or incomplete stage: ' + label)
        docs[label], hashes[rel], ids[rel] = doc, sha, ident
    ready, sha, ident = json_input('implementation-ready.json')
    if sha != READY_SHA:
        fail('Implementation-ready digest differs from pinned R14 identity')
    hashes['implementation-ready.json'], ids['implementation-ready.json'] = sha, ident
    # The exact pinned ready bytes attest the complete 219-file snapshot. Compare
    # that entire object; do not guess its schema or reread the source tree.
    source = ready.get('source_after')
    q = docs['qualification']
    if (ready.get('ready') is not True or ready.get('source_frozen') is not True
            or ready.get('source_count') != 219 or not isinstance(source, dict) or len(source) != 219
            or q.get('source_tested') != source or q.get('source_after') != source):
        fail('Qualification source snapshot does not equal pinned ready snapshot')
    qrel, lrel = 'qualification-01/report.json', 'local-campaigns-01/report.json'
    if not binds_path_hash(docs['local'].get('bound_inputs'), {str(R14 / qrel), qrel}, hashes[qrel]):
        fail('Local qualification path/hash binding is missing')
    remote = docs['remote']
    if remote.get('qualification_report_sha256') != hashes[qrel] or remote.get('local_gate_sha256') != hashes[lrel]:
        fail('Remote qualification/local report binding differs')
    report_data, sha, ident = json_input('report-data.json')
    if sha != REPORT_SHA:
        fail('Report-data digest differs from the prepared identity')
    hashes['report-data.json'], ids['report-data.json'] = sha, ident
    source_map, sha, ident = json_input('qualification-01/source-map.json')
    if source_map != source:
        fail('Qualification source map differs from the frozen 219-file snapshot')
    hashes['qualification-01/source-map.json'], ids['qualification-01/source-map.json'] = sha, ident
    qa = docs['qualification_audit']
    if (qa.get('qualification_report_sha256') != hashes[qrel]
            or qa.get('implementation_ready_sha256') != READY_SHA
            or qa.get('source_map_sha256') != sha or qa.get('source_input_count') != 219
            or qa.get('source_tested_after_current_equal') is not True
            or qa.get('source_matches_frozen_implementation') is not True):
        fail('Qualification audit is not bound to this frozen candidate')
    qa_hash = hashes['qualification-audit-summary.json']
    if any(docs[label].get('qualification_audit_sha256') != qa_hash
           for label in ('performance_audit', 'recovery_audit')):
        fail('Independent performance/recovery audits reference a different qualification audit')
    if report_data.get('success') is not True:
        fail('Report-data is not successful')
    for label, rel in [('qualification', 'qualification-audit-summary.json'),
                       ('performance', 'independent-performance-audit.json'),
                       ('recovery', 'independent-recovery-audit.json')]:
        binding = report_data.get('source_audits', {}).get(label, {})
        if binding.get('path') != str(R14 / rel) or binding.get('sha256') != hashes[rel]:
            fail('Report-data audit binding differs: ' + label)
    for rel, expected_sha in sorted(PINNED_INPUTS.items()):
        if rel not in hashes:
            raw, ident = read_stable(R14 / rel, rel, cap=4 * 1024 * 1024)
            hashes[rel], ids[rel] = digest(raw), ident
        if hashes[rel] != expected_sha:
            fail('Frozen evidence digest differs: ' + rel)
    summary = docs['diagnostic_summary']
    if summary.get('analysis_script_sha256') != PINNED_INPUTS['diagnostic-tools/summarize_arena_diagnostics.py']:
        fail('Diagnostic summary analysis source binding differs')
    inputs = summary.get('inputs')
    if not isinstance(inputs, list) or len(inputs) != 2 or not all(isinstance(x, dict) for x in inputs):
        fail('Diagnostic summary must bind exactly two raw reports')
    by_path = {x.get('path'): x for x in inputs}
    if len(by_path) != 2:
        fail('Duplicate diagnostic summary raw-report binding')
    for label, rel, tool in [
            ('diagnostic_01', 'thread-arena-diagnostic-01/report.json', 'diagnostic-tools/probe_cancel_threads.py'),
            ('diagnostic_02', 'thread-arena-diagnostic-02/report.json', 'diagnostic-tools/probe_cancel_arenas_1_4.py')]:
        row = by_path.get(str(R14 / rel), {})
        if (row.get('sha256') != hashes[rel] or row.get('bytes') != ids[rel][4]
                or row.get('script_sha256') != PINNED_INPUTS[tool]
                or docs[label].get('diagnostic_script_sha256') != PINNED_INPUTS[tool]):
            fail('Diagnostic raw report/source binding differs: ' + rel)
    return hashes, ids


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
        root = R14 if alias == 'r14' else R12
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

    for rel in R14_FILES + R14_TREES:
        select('r14', R14, rel)
    for pattern in R14_GLOBS:
        select_glob('r14', R14, pattern)
    for rel in POLICY['scope']['r12']['required_trees']:
        select('r12', R12, rel)
    for pattern in POLICY['scope']['r12']['required_globs']:
        select_glob('r12', R12, pattern, True)
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
        'gate_hashes': {'r14/' + k: v for k, v in sorted(gate_hashes.items())},
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
        raw, _ = read_stable(R14 / rel, rel, gate_ids[rel], cap=4 * 1024 * 1024)
        if digest(raw) != sha:
            fail('Gate content changed during packaging: ' + rel)


def output_path(value):
    p = Path(value)
    if not p.is_absolute():
        p = R14 / p
    if p.parent != R14 or not re.fullmatch(r'evidence-package-[A-Za-z0-9][A-Za-z0-9._-]*', p.name):
        fail('Output must be a new evidence-package-* direct child of R14')
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


def package(value):
    destination = output_path(value)  # Lexical only; no directory or gate read.
    gate_hashes, gate_ids = check_gates()
    rules, _ = read_stable(R14 / 'archive-tools/selection-rules-v2.json', 'selection-rules-v2.json', cap=1024 * 1024)
    if rules != encoded(POLICY):
        fail('Selection rules differ from this packager policy')
    selected, excluded = collect()
    scan_and_hash(selected)
    manifest_bytes = encoded(manifest(selected, excluded, gate_hashes))
    destination.mkdir(mode=0o700, exist_ok=False)
    partial = destination / 'evidence.tar.gz.partial'
    write_archive(partial, selected, manifest_bytes)
    verify_archive(partial, selected, manifest_bytes)
    recheck(selected, excluded, gate_hashes, gate_ids)
    archive = destination / 'r14-original-evidence-01.tar.gz'
    os.link(partial, archive)  # Exclusive publication: never overwrite a target.
    partial.unlink()
    selection = destination / 'selection-manifest.json'
    write_new(selection, manifest_bytes)
    selection_gz = destination / 'archive-selection-01.json.gz'
    write_new(selection_gz, gzip.compress(manifest_bytes, compresslevel=6, mtime=0))
    result = {'schema': 'hepta-r14-evidence-archive/v2', 'success': True,
              'candidate_adoption_claimed': False,
              'archive': file_meta(archive), 'selection_index': file_meta(selection_gz),
              'uncompressed_selection': file_meta(selection),
              'selected_file_count': len(selected), 'tar_member_count': len(selected) + 1,
              'selected_bytes': sum(e['size'] for e in selected.values()),
              'excluded_path_count': len(excluded),
              'gate_hashes': {'r14/' + k: v for k, v in sorted(gate_hashes.items())},
              'archive_member_hashes_verified': True, 'selected_set_rechecked': True,
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
    args = parser.parse_args()
    if not args.package:
        print(encoded(POLICY).decode(), end='')
        return 0
    try:
        package(args.output)
    except (OSError, RuntimeError, ValueError, tarfile.TarError) as error:
        print('Evidence packaging stopped: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
