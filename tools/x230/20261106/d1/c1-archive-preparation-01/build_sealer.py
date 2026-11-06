#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Assemble the C1 local source sealer without importing or executing targets."""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path('/tmp/hepta-runtime-recovery-20261106')
OUT = BASE / 'd1-c1-archive-preparation-01'
refpath = BASE / 'd1-ordinary-archive-independent-review-01/seal_ordinary_archive.py'
raw = refpath.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '1e6eae1ca85513164e7c92dd68d62ffa8a8cb8c69bebba2eab406cff91843cf9'
source = raw.decode()
lines = source.splitlines(keepends=True)
func = {node.name: ''.join(lines[node.lineno - 1:node.end_lineno]) + '\n\n'
        for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}
template = (OUT / 'archive_d1_c1.py').read_bytes()
tree = ast.parse(template)
core = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'CORE_PATHS' for target in node.targets))
names = ['need', 'sha', 'encoded', 'stamp', 'native_terminal', 'native_stream_pages',
         'read_original', 'load_pages', 'original_object', 'with_actual', 'write_new']
header = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal the C1 collector using actual local original bytes only.

No collector, original auditor/parser/validator, runtime, compiler or host is
called. Missing or failed originals remain accurately missing or failed.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 384 * 1024 * 1024
COUNTS = ('measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')
'''
header += 'TEMPLATE_SHA256 = ' + repr(hashlib.sha256(template).hexdigest()) + '\n'
header += 'CORE_PATHS = ' + repr(core) + '\n\n'
main = func['main']
main = main.replace("    args = parser.parse_args()", "    parser.add_argument('--holder-job-id', required=True)\n    args = parser.parse_args()")
main = main.replace('actual_from_originals(originals, snapshots)',
                    'actual_from_originals(originals, snapshots, args.holder_job_id)')
main = main.replace('hepta-d1-ordinary-archive-seal/v1', 'hepta-d1-c1-archive-seal/v1')
main = main.replace("'actual_original_job_id': EXPECTED_JOB_ID,\n        'actual_postflight_job_id': actual['postflight_original_job_id'],",
                    "'actual_original_job_id': actual['holder_original_job_id'],")
main = main.replace('archive_d1_ordinary.py', 'archive_d1_c1.py')
body = header + ''.join(func[name] for name in names) + (OUT / 'actual_from_originals.py').read_text() + '\n\n' + main
body += "if __name__ == '__main__':\n    main()\n"
result = body.encode()
parsed = ast.parse(result)
assert 'EXPECTED_JOB_ID' not in body
with (OUT / 'seal_c1_archive.py').open('xb') as stream:
    stream.write(result)
newlines = body.splitlines(keepends=True)
outfunc = {node.name: ''.join(newlines[node.lineno - 1:node.end_lineno]) + '\n\n'
           for node in parsed.body if isinstance(node, ast.FunctionDef)}
assert all(outfunc[name] == func[name] for name in names)
report = {'schema': 'hepta-d1-c1-archive-sealer-static-construction/v1',
    'bytes': len(result), 'sha256': hashlib.sha256(result).hexdigest(),
    'git_blob': hashlib.sha1(b'blob ' + str(len(result)).encode() + b'\0' + result).hexdigest(),
    'template_sha256': hashlib.sha256(template).hexdigest(), 'helper_functions_exact': names,
    'future_holder_job_id': None, 'future_result': None, 'target_imports_or_functions_executed': 0,
    'host_requests': 0, 'original_bytes_reencoded_or_modified': False}
with (OUT / 'SEALER_STATIC_CONSTRUCTION.json').open('xb') as stream:
    stream.write((json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
print(json.dumps(report, sort_keys=True))
