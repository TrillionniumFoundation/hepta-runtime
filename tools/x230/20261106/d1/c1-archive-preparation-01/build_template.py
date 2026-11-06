#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pure source assembly and AST checks; no imported target definitions execute."""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path('/tmp/hepta-runtime-recovery-20261106')
OUT = BASE / 'd1-c1-archive-preparation-01'
REFERENCE = BASE / 'd1-ordinary-archive-independent-review-01/archive_d1_ordinary.unsealed.py'
TRANSPORT = BASE / 'd1-c1-mac-transport-01/import_sealed_payloads_01.py'
REFERENCE_SHA = '88926948ee409d9cb15e3013243a486eca522aefc27b03da56dee28f6dab0009'
TRANSPORT_SHA = 'deb82a9c072729208c1dc6ba1a2a009ad2faa78ea08fdb9ebff3ec72ec8a850e'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def literal(source, name):
    rows = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    assert len(rows) == 1
    return ast.literal_eval(rows[0].value)

raw = REFERENCE.read_bytes()
transport = TRANSPORT.read_bytes()
assert sha(raw) == REFERENCE_SHA and sha(transport) == TRANSPORT_SHA
source = raw.decode()
lines = source.splitlines(keepends=True)
functions = {node.name: ''.join(lines[node.lineno - 1:node.end_lineno]) + '\n\n'
             for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
pinmap = {name.removeprefix('x230/'): pin
          for name, pin in literal(transport, 'EXPECTED').items() if name.startswith('x230/')}
assert len(pinmap) == 18
core = [
    'c1-holder-native-01.json', 'c1-holder-report-01.json', 'c1-holder-start-01.json',
    'c1-parent-install-01.json',
    'c1-campaign-01/report.json', 'c1-campaign-01/summary.json',
    'c1-campaign-01/source-inputs.json', 'c1-campaign-01/baseline-source-inputs.json',
    'c1-campaign-01/compiler-monitor.json', 'c1-campaign-01/compiler-monitor.audit.json',
    'c1-observation-01/report.json', 'c1-observation-01/independent-summary.json',
    'c1-adapter-evidence-01/adapter-report.json',
]
external = literal(source, 'EXTERNAL_EVIDENCE_REFERENCES')
external['ordinary_archive'] = {
    'kind': 'tar.gz',
    'path': '/home/qian/hepta-runtime-phase-cost-20261106-d1/ordinary-evidence-02-01.tar.gz',
    'bytes': 1455951, 'sha256': '3a99b65020e6823b60b87700d50e430c1def76c15fe387beb4a9032e7294fffe',
    'provenance': 'Root supplied completed original collector/transfer identity; this collector does not reread or execute that archive.'}
header = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve one original D1 C1 diagnostic capture with bounded zero-extraction verification.

No original auditor, trace parser, monitor validator, runtime, or archived source
is executed. Failed/partial results retain their original bytes and statements.
ACTUAL is deliberately unsealed until the original holder terminal exists.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
MAC_HOLDER = Path('/Users/qianqi/work/hepta-runtime-d1-c1-holder-01')
MAX_TOTAL = 384 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
STAGES = ['native-observation', 'native-audit']
COUNTS = ('measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')
COLLECT_DIRS = ('c1-campaign-01', 'c1-observation-01', 'c1-adapter-evidence-01', 'c1-holder-originals-01')
'''
header += 'SKIP_DIRS = ' + repr(literal(source, 'SKIP_DIRS')) + '\n'
header += 'SKIP_FILES = ' + repr(literal(source, 'SKIP_FILES')) + '\n'
header += 'PINNED = ' + repr(dict(sorted(pinmap.items()))) + '\nREQUIRED = sorted(PINNED)\n'
header += 'CORE_PATHS = ' + repr(core) + '\n'
header += 'SOURCE_REFERENCE_SHA256 = ' + repr(REFERENCE_SHA) + '\nVERIFY_REFERENCE_SHA256 = SOURCE_REFERENCE_SHA256\n'
header += 'EXTERNAL_EVIDENCE_REFERENCES = ' + repr(external) + '\nACTUAL = None\n\n\n'
preserved = ['need', 'sha', 'encoded', 'stamp', 'tool_sha256', 'native_terminal', 'original_streams',
             'native_stream_pages', 'captured_native']
logic = (OUT / 'receipt_logic.py').read_text()
ast.parse(logic)

collect = functions['collect']
collect = collect.replace("kind == 'ordinary'", "kind == 'c1'")
collect = collect.replace('the captured original ordinary02 supplement', 'the captured original C1 diagnostic')
collect = collect.replace('file exceeds 8 MiB:', 'file exceeds 32 MiB:')
old = """        elif not name.startswith('ordinary-02/'):
            file(root / name, required=True)
    if os.path.lexists(root / 'ordinary-02'):
        directory(root / 'ordinary-02')
"""
new = """        elif not any(name.startswith(prefix + '/') for prefix in COLLECT_DIRS):
            file(root / name, required=True)
    for prefix in COLLECT_DIRS:
        if os.path.lexists(root / prefix):
            directory(root / prefix)
"""
assert old in collect
collect = collect.replace(old, new)
create = functions['create_archive']
verify = functions['verify_archive']
for old, new in (
    ("kind == 'ordinary'", "kind == 'c1'"),
    ("manifest['kind'] == 'ordinary'", "manifest['kind'] == 'c1'"),
    ('the captured original ordinary02 supplement', 'the captured original C1 diagnostic'),
    ('ordinary-evidence-02-01', 'c1-evidence-01'),
    ('hepta-d1-ordinary-evidence-archive/v1', 'hepta-d1-c1-evidence-archive/v1'),
    ('exceed 32 MiB', 'exceed 384 MiB'),
    ('exceeded 32 MiB', 'exceeded 384 MiB'),
    ('exceeds 32 MiB', 'exceeds 384 MiB'),
    ("'ordinary_binary_sha256': compact['ordinary_binary_sha256']",
     "'raw_trace_file_count': compact['raw_trace_file_count'], 'receipt_binding_errors': compact['receipt_binding_errors']"),
):
    create = create.replace(old, new)
    verify = verify.replace(old, new)
main = functions['main'].replace("choices=('ordinary',)", "choices=('c1',)")
footer = source[source.index("if __name__ == '__main__':"):]
result = (header + ''.join(functions[name] for name in preserved) + logic + '\n\n' + collect
          + create + verify + main + footer).encode()
tree = ast.parse(result)
assert literal(result, 'ACTUAL') is None
assert len({node.name for node in tree.body if isinstance(node, ast.FunctionDef)}) == sum(
    isinstance(node, ast.FunctionDef) for node in tree.body)
with (OUT / 'archive_d1_c1.py').open('xb') as stream:
    stream.write(result)
result_lines = result.decode().splitlines(keepends=True)
new_functions = {node.name: ''.join(result_lines[node.lineno - 1:node.end_lineno]) + '\n\n'
                 for node in tree.body if isinstance(node, ast.FunctionDef)}
assert all(new_functions[name] == functions[name] for name in preserved)
for name in ('collect', 'create_archive', 'verify_archive', 'summary'):
    node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    statement = node.body[0]
    called = statement.value if isinstance(statement, ast.Expr) else statement.value
    assert isinstance(called, ast.Call) and isinstance(called.func, ast.Name) and called.func.id == 'require_sealed'
identity = {'bytes': len(result), 'sha256': sha(result), 'git_blob': hashlib.sha1(
    b'blob ' + str(len(result)).encode() + b'\0' + result).hexdigest()}
proof = {'schema': 'hepta-d1-c1-archive-static-construction/v1', 'collector': identity,
    'reference': {'path': str(REFERENCE), 'bytes': len(raw), 'sha256': sha(raw)},
    'actual_installed_source_pin_provenance': {'path': str(TRANSPORT), 'bytes': len(transport), 'sha256': sha(transport)},
    'preserved_helper_functions': preserved, 'helper_source_bytes_equal': True,
    'static_pinned_sources_and_inputs': len(pinmap), 'future_core_receipts': len(core),
    'future_ACTUAL_is_None': True, 'four_entry_guards': True,
    'scanner_conditions_unchanged': True, 'no_filesystem_extraction': True,
    'fixed_caps': {'selected_and_archive_total_bytes': 384 * 1024 * 1024, 'single_file_bytes': 32 * 1024 * 1024,
                   'manifest_bytes': 2 * 1024 * 1024, 'files': 8192},
    'target_imports_or_functions_executed': 0, 'host_requests': 0}
with (OUT / 'STATIC_CONSTRUCTION.json').open('xb') as stream:
    stream.write((json.dumps(proof, sort_keys=True, indent=2) + '\n').encode())
example = {'schema': 'hepta-d1-c1-archive-actual-pins/v1', 'sealed': False,
    'holder_original_job_id': None, 'outcome': None, 'native_read_paths': None,
    'counts': None, 'files': dict.fromkeys(core)}
with (OUT / 'actual-pins.unsealed.json').open('xb') as stream:
    stream.write((json.dumps(example, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps(proof, sort_keys=True))
