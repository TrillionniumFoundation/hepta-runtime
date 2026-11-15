#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the unsealed CI collector from pinned original stable-I/O helpers; no entrypoint runs."""
import ast
import hashlib
import json
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def function(source, name):
    nodes = [node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == name]
    assert len(nodes) == 1, name
    lines = source.splitlines(keepends=True)
    return ''.join(lines[nodes[0].lineno - 1:nodes[0].end_lineno])


def create(name, raw):
    with (HERE / name).open('xb') as stream:
        stream.write(raw)


def main():
    config = json.loads((HERE / 'generation-input.json').read_bytes())
    reference_raw = (HERE / 'reference/archive_d1_qualification.py').read_bytes()
    binder_raw = (HERE / 'reference/d2-prerequisites.py').read_bytes()
    assert digest(reference_raw) == config['reference_sha256']
    assert digest(binder_raw) == config['binder_sha256']
    reference, binder = reference_raw.decode(), binder_raw.decode()
    nodes = {node.targets[0].id: node.value for node in ast.parse(reference).body
             if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    header = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve one completed native D2 exact-CI attempt. Zero-extract verification rechecks retained bytes only.

No source, ELF, cache, runtime, benchmark, CI or auditor is executed or modified.
The collector source is published separately; its own credential-scanner literals are not tar members.
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

MAX_TOTAL = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
'''
    header += 'ROOT = Path(' + repr(config['root']) + ')\n'
    header += 'SOURCE_REFERENCE_SHA256 = ' + repr(config['reference_sha256']) + '\n'
    header += 'VERIFY_REFERENCE_SHA256 = ' + repr(digest(function(reference, 'verify_archive').encode())) + '\n'
    for name in ('SKIP_DIRS', 'SKIP_FILES'):
        header += name + ' = ' + pprint.pformat(ast.literal_eval(nodes[name]), sort_dicts=True) + '\n'
    header += 'PINNED = ' + pprint.pformat(config['fixed'], sort_dicts=True, width=110) + '\n'
    header += 'CI_COMMANDS = ' + pprint.pformat(config['ci_commands'], sort_dicts=False, width=110) + '\n'
    header += 'CI_ENVIRONMENT = ' + pprint.pformat(config['ci_environment'], sort_dicts=True, width=110) + '\n'
    header += '''COUNT_KEYS = ('passed', 'failed', 'ignored', 'selected', 'retries')
FUTURE_PATHS = ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-01/nextest-output-audit.json',
                'rust-ci-native-01.json', 'rust-ci-installation-started-01.json', 'rust-ci-installation-01.json')
ACTUAL = None
'''
    unchanged = ('need', 'sha', 'encoded', 'stamp', 'tool_sha256', 'native_terminal')
    body = '\n\n'.join(function(reference, name) for name in unchanged)
    body += '\n\n' + function(binder, 'native_stream_pages')
    body += '\n\n' + (HERE / 'ci_summary.py').read_text()
    collect = function(reference, 'collect')
    collect = collect.replace("kind == 'qualification', 'this script archives only completed D1 qualification'",
                              "kind == 'ci', 'this script archives only completed D2 exact-CI'")
    begin = collect.index('    for name in REQUIRED:\n')
    end = collect.index('    need(all(stamp(path.lstat())', begin)
    selection = '''    for name in PINNED:
        file(root / name, required=True)
    for name, pin in actual['files'].items():
        if pin is None:
            need(not os.path.lexists(root / name), 'receipt declared absent now exists: ' + name)
        elif not name.startswith('rust-ci-01/'):
            file(root / name, required=True)
    if os.path.lexists(root / 'rust-ci-01'):
        directory(root / 'rust-ci-01')
'''
    collect = collect[:begin] + selection + collect[end:]
    create_function = function(reference, 'create_archive')
    create_function = create_function.replace("kind == 'qualification', 'this script archives only completed D1 qualification'",
                                              "kind == 'ci', 'this script archives only completed D2 exact-CI'")
    create_function = create_function.replace("'qualification-evidence-03'", "'rust-ci-evidence-01'")
    create_function = create_function.replace('hepta-d1-qualification-evidence-archive/v1', 'hepta-d2-exact-ci-evidence-archive/v1')
    verify = function(reference, 'verify_archive').replace('hepta-d1-qualification-evidence-archive/v1',
                                                         'hepta-d2-exact-ci-evidence-archive/v1')
    verify = verify.replace("manifest['kind'] == 'qualification'", "manifest['kind'] == 'ci'")
    main_function = function(reference, 'main').replace("choices=('qualification',)", "choices=('ci',)")
    source = header + '\n\n' + body + '\n\n' + '\n\n'.join((collect, create_function, verify, main_function))
    source += '''\n\nif __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AssertionError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
'''
    ast.parse(source)
    for name in unchanged + ('file', 'directory'):
        assert function(source, name) == function(reference, name), name
    assert function(source, 'native_stream_pages') == function(binder, 'native_stream_pages')
    raw = source.encode()
    create('archive_d2_ci.unsealed.py', raw)
    report = {'schema': 'hepta-d2-exact-ci-archive-generation/v1', 'collector': {'bytes': len(raw), 'sha256': digest(raw)},
              'reference_sha256': digest(reference_raw), 'pinned_members': len(config['fixed']),
              'unchanged_reference_functions': list(unchanged) + ['collect.file', 'collect.directory'],
              'unchanged_native_pages_function': digest(function(binder, 'native_stream_pages').encode()),
              'create_verify_changes': 'namespace, kind and output basename only; bounded I/O/scanner/tar/write logic unchanged',
              'ast_parse_only': True, 'collector_or_auditor_executed': False, 'actual': None}
    create('generation-report.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    request = {'schema': 'hepta-d2-exact-ci-archive-seal-request/v1',
               'collector': {'local_path': str(HERE / 'archive_d2_ci.unsealed.py'), 'bytes': len(raw), 'sha256': digest(raw)},
               'original_job_id': None, 'read_pages': None,
               'originals': {name: None for name in
                             ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-01/nextest-output-audit.json',
                              'rust-ci-native-01.json', 'rust-ci-installation-started-01.json', 'rust-ci-installation-01.json')}}
    create('actual-seal-request.unsealed.json', (json.dumps(request, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
