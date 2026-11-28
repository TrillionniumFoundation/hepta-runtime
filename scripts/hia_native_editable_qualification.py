"""Admit complete native EditableContent captures before original Rust replay."""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path

FOLDER = 'editable-rust-oracle'
CORPUS_FILES = ('native-corpus.json', 'requests.hex', 'native-output.txt')
COUNTS = {'capacity': 4, 'empty_unterminated_line': 80, 'exact_output': 1, 'exact_elf_image_binding': 1,
    'full_file_domain': 3, 'full_u64_error': 368, 'insert_preserve': 4564, 'invalid': 65,
    'ordered_random': 1400, 'replace_preserve': 2242, 'roundtrip': 92, 'standalone_elf': 4}
CASES = 8749
WIRE_BYTES = 33628041
WIRE_SHA256 = '22882cf8843fc5f63c9456ab41bfc2e98662d37dd93f460de8128d6f75f25d09'
OUTPUT_BYTES = 33372572
OUTPUT_SHA256 = '0fb989170d57877d131dd2a7fe91d7e33456bfaa5c7afe8d0d38024764dc5c52'
ORIGINAL_SOURCE = 'src/mcp/fs/text_editing.rs'
ORIGINAL_SHA256 = 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590'
FILTER_PREFIX_BYTES = 489
FILTER_CALL_HOLE = 338
FILTER_TEMPLATE_SHA256 = 'f2a70a50a426de5834e00336e2fa05bb98e0e1c3f9615cabd51e9a87e923b9b5'


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError('editable evidence must be an owned regular file: ' + str(path))
    return path.read_bytes()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_counts(actual):
    if (type(actual) is not dict or set(actual) != set(COUNTS)
            or any(type(actual[key]) is not int or actual[key] != value for key, value in COUNTS.items())):
        raise ValueError('editable native request/control accounting differs')


def exact_filter_image(executable, image):
    if len(executable) != FILTER_PREFIX_BYTES + len(image) or executable[FILTER_PREFIX_BYTES:] != image:
        raise ValueError('editable ELF does not embed the exact admitted native image')
    prefix = bytearray(executable[:FILTER_PREFIX_BYTES])
    for offset in (96, 104):
        if int.from_bytes(prefix[offset:offset + 8], 'little') != len(executable):
            raise ValueError('editable ELF file span differs')
        prefix[offset:offset + 8] = bytes(8)
    if int.from_bytes(prefix[FILTER_CALL_HOLE:FILTER_CALL_HOLE + 4], 'little') != FILTER_PREFIX_BYTES - FILTER_CALL_HOLE - 4:
        raise ValueError('editable ELF native entry displacement differs')
    prefix[FILTER_CALL_HOLE:FILTER_CALL_HOLE + 4] = bytes(4)
    if digest(prefix) != FILTER_TEMPLATE_SHA256:
        raise ValueError('editable ELF transport differs from the pinned standard filter')


def editable_evidence(root, output, report, completed):
    check, summary = completed(output, report, 'test_editable_content.py')
    if (set(summary) != {'status', 'counts', 'source_sha256', 'elapsed_seconds', 'imported_helper_functions'}
            or summary['status'] != 'passed' or type(summary['imported_helper_functions']) is not int
            or summary['imported_helper_functions'] != 4
            or type(summary['elapsed_seconds']) not in (int, float)
            or not math.isfinite(summary['elapsed_seconds']) or summary['elapsed_seconds'] <= 0):
        raise ValueError('editable native suite did not complete its exact source/capture controls')
    exact_counts(summary['counts'])
    folder = output / FOLDER
    metadata_raw = regular(folder / 'native-corpus.json')
    corpus = json.loads(metadata_raw)
    exact_counts(corpus.get('counts'))
    if (corpus.get('schema') != 'hepta.runtime.native-corpus.v1' or corpus.get('component') != 'editable_content'
            or type(corpus.get('cases')) is not int or corpus['cases'] != CASES
            or corpus.get('requests_file') != 'requests.hex' or corpus.get('native_output_file') != 'native-output.txt'
            or type(corpus.get('imported_helper_functions')) is not int or corpus['imported_helper_functions'] != 4):
        raise ValueError('editable native corpus schema or original-domain accounting differs')
    wire, expected = (regular(folder / name) for name in CORPUS_FILES[1:])
    if ((len(wire), digest(wire), len(expected), digest(expected)) != (WIRE_BYTES, WIRE_SHA256, OUTPUT_BYTES, OUTPUT_SHA256)
            or corpus.get('requests_bytes') != WIRE_BYTES or corpus.get('requests_sha256') != WIRE_SHA256
            or corpus.get('native_output_bytes') != OUTPUT_BYTES or corpus.get('native_output_sha256') != OUTPUT_SHA256
            or wire.count(b'\n') != CASES or expected.count(b'\n') != CASES
            or not wire.endswith(b'\n') or not expected.endswith(b'\n')):
        raise ValueError('editable complete original-domain request/output bytes differ')
    owner = report['modules']['editable_content']
    relative = Path(owner['manifest'])
    if relative.is_absolute() or '..' in relative.parts or owner.get('builder') != 'borrowed_bytes':
        raise ValueError('editable native module path or builder differs')
    manifest = output / relative
    module_raw = regular(manifest)
    module = json.loads(module_raw)
    source_sha = digest(regular(root / 'native/editable_content.hepta'))
    composition_sha = digest(regular(root / 'native/editable_content_composition.json'))
    if (digest(module_raw) != owner['sha256'] or module.get('source_sha256') != source_sha
            or corpus.get('source_sha256') != source_sha or summary['source_sha256'] != source_sha
            or corpus.get('image_sha256') != module.get('image_sha256')
            or corpus.get('composition_sha256') != composition_sha
            or module.get('compiler_sha256') != report['compiler_image_sha256']
            or module.get('compiler_commit') != 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
            or module.get('input_capacity') != 8 << 20 or module.get('output_capacity') != 8 << 20
            or module.get('workspace_capacity') != 32 << 20):
        raise ValueError('editable native module/compiler/composition identity differs')
    for kind in ('source', 'image'):
        name = Path(module[kind])
        if (name.is_absolute() or len(name.parts) != 1
                or digest(regular(manifest.parent / name)) != module[kind + '_sha256']):
            raise ValueError('editable compiled artifact differs')
    standalone = module.get('standalone', {})
    executable = Path(standalone.get('path', ''))
    if (standalone.get('transport') != 'filter' or len(executable.parts) != 1 or executable.is_absolute()
            or digest(regular(manifest.parent / executable)) != standalone.get('sha256')
            or standalone.get('runtime_python_required') is not False
            or standalone.get('runtime_libc_required') is not False):
        raise ValueError('editable static filter artifact differs')
    exact_filter_image(regular(manifest.parent / executable), regular(manifest.parent / module['image']))
    original_raw = regular(root / ORIGINAL_SOURCE)
    if digest(original_raw) != ORIGINAL_SHA256 or corpus.get('original_text_editing_sha256') != ORIGINAL_SHA256:
        raise ValueError('editable original source owner differs')
    original = original_raw.decode()
    begin = original.index('const LF_ENDING:')
    end = original.index('\nfn sanitize_incoming_content(', begin)
    transport = regular(root / 'tests/hia_native/editable_oracle_transport.rs')
    wanted_oracle = (b'// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\n'
                     b'use anyhow::{anyhow, bail, Result};\n' + original[begin:end].encode() + transport)
    oracle_name = 'tests/hia_native/oracle_editable_content.rs'
    if (corpus.get('oracle') != oracle_name or regular(root / oracle_name) != wanted_oracle
            or corpus.get('oracle_sha256') != digest(wanted_oracle)):
        raise ValueError('editable oracle does not retain the complete unchanged original methods')
    oracle_files = [oracle_name, 'tests/hia_native/editable_oracle_transport.rs',
        'tests/hia_native/editable_oracle/Cargo.toml', 'tests/hia_native/editable_oracle/Cargo.lock']
    return {'status': 'PASS', 'counts': COUNTS, 'captured_native_cases': CASES,
        'direct_native_calls': CASES + COUNTS['invalid'] + COUNTS['capacity'] + COUNTS['exact_output'],
        'actual_elf_calls': COUNTS['standalone_elf'], 'native_cases_added_by_replay': 0,
        'exact_elf_image_binding': True, 'filter_template_sha256': FILTER_TEMPLATE_SHA256,
        'source_sha256': source_sha, 'image_sha256': module['image_sha256'],
        'module_manifest_sha256': owner['sha256'], 'composition_sha256': composition_sha,
        'executable_sha256': standalone['sha256'], 'original_source_sha256': ORIGINAL_SHA256,
        'input_sha256': WIRE_SHA256, 'native_output_sha256': OUTPUT_SHA256,
        'corpus_metadata_sha256': digest(metadata_raw),
        'oracle_sources_sha256': {name: digest(regular(root / name)) for name in oracle_files},
        'test_stdout_sha256': check['stdout_sha256'], 'test_stderr_sha256': check['stderr_sha256'],
        'scope': 'Internal EditableContent methods, ordered state and byte preservation; no file effects or production handler replacement',
        'complete_original_tool_parity': False, 'production_activated': False}
