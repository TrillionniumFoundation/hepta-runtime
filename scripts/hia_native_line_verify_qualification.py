"""Bind complete native line-ID/diagnostic captures to their original owners."""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import json
import math
from pathlib import Path

FOLDER = 'line-verify-rust-oracle'
CORPUS_FILES = ('native-corpus.json', 'requests.hex.gz', 'native-output.txt.gz')
CASES = 4346
COUNTS = {'all_expected_hashes': 1536, 'capacity': 4, 'context_and_relocation': 702,
    'exact_elf_image_binding': 1, 'exact_output': 1, 'full_lp64_index_domain': 480,
    'invalid': 92, 'line_encoding_boundaries': 16, 'maximum_empty_lines': 2,
    'maximum_utf8_line': 1, 'ordered_random': 1600, 'stable_collision_order': 9,
    'standalone_elf': 3, 'standalone_invalid': 1}
WIRE_BYTES = 32613558
WIRE_SHA256 = 'eee9afc2715ae13a6a8d06bc5e0e7855c18ad99df9079aaaf3b9e4214588af37'
OUTPUT_BYTES = 12105180
OUTPUT_SHA256 = 'b4eebfc47fe61a9928261e5eecebc212b13511e95b3511e6186c3d7de285108b'
ORIGINAL_SOURCE = 'src/utils/line_hash.rs'
ORIGINAL_SHA256 = '904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57'
ORIGINAL_BLOB = '0e521656ba24869dbc05afc51d62aa4af79b5e44'
FILTER_TEMPLATE_SHA256 = 'f2a70a50a426de5834e00336e2fa05bb98e0e1c3f9615cabd51e9a87e923b9b5'


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError('line verification evidence must be a regular unsymlinked file')
    return path.read_bytes()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_counts(actual):
    if (type(actual) is not dict or set(actual) != set(COUNTS)
            or any(type(actual[key]) is not int or actual[key] != value for key, value in COUNTS.items())):
        raise ValueError('line verification complete request/control accounting differs')


def stream_identity(path, maximum):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError('line verification compressed corpus must be a regular unsymlinked file')
    sha, size, lines, last = hashlib.sha256(), 0, 0, b''
    with gzip.open(path, 'rb') as source:
        while chunk := source.read(1 << 20):
            size += len(chunk)
            if size > maximum:
                raise ValueError('line verification decompressed corpus exceeds its captured domain')
            sha.update(chunk)
            lines += chunk.count(b'\n')
            last = chunk[-1:]
    if lines != CASES or last != b'\n':
        raise ValueError('line verification compressed corpus row accounting differs')
    return size, sha.hexdigest()


def exact_filter_image(executable, image):
    if len(executable) != 489 + len(image) or executable[489:] != image:
        raise ValueError('line verification ELF does not embed the exact admitted native image')
    prefix = bytearray(executable[:489])
    for offset in (96, 104):
        if int.from_bytes(prefix[offset:offset + 8], 'little') != len(executable):
            raise ValueError('line verification ELF file span differs')
        prefix[offset:offset + 8] = bytes(8)
    if int.from_bytes(prefix[338:342], 'little') != 147:
        raise ValueError('line verification ELF native entry displacement differs')
    prefix[338:342] = bytes(4)
    if digest(prefix) != FILTER_TEMPLATE_SHA256:
        raise ValueError('line verification ELF transport differs from the pinned standard filter')


def line_verify_evidence(root, output, report, completed):
    check, summary = completed(output, report, 'test_line_verify.py')
    exact_counts(summary.get('counts'))
    if (summary.get('status') != 'passed' or type(summary.get('captured_cases')) is not int
            or summary['captured_cases'] != CASES or type(summary.get('imported_helper_functions')) is not int
            or summary['imported_helper_functions'] != 5 or type(summary.get('elapsed_seconds')) not in (int, float)
            or not math.isfinite(summary['elapsed_seconds']) or summary['elapsed_seconds'] <= 0):
        raise ValueError('line verification native suite did not finish the complete declared domain')
    owner = report['modules']['line_verify']
    relative = Path(owner['manifest'])
    if relative.is_absolute() or '..' in relative.parts or owner.get('builder') != 'borrowed_bytes':
        raise ValueError('line verification native module path or builder differs')
    manifest = output / relative
    module_raw = regular(manifest)
    module = json.loads(module_raw)
    source_sha = digest(regular(root / 'native/line_verify.hepta'))
    composition_raw = regular(root / 'native/line_verify_composition.json')
    composition_sha = digest(composition_raw)
    if (digest(module_raw) != owner['sha256'] or module.get('source_sha256') != source_sha
            or module.get('compiler_sha256') != report['compiler_image_sha256']
            or module.get('compiler_commit') != 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
            or module.get('input_capacity') != 8 << 20 or module.get('output_capacity') != 8 << 20
            or module.get('workspace_capacity') != 32 << 20):
        raise ValueError('line verification source/compiler/capacity identity differs')
    artifacts = {}
    for kind in ('source', 'image'):
        name = Path(module[kind])
        if name.is_absolute() or len(name.parts) != 1:
            raise ValueError('line verification compiled artifact path differs')
        artifacts[kind] = regular(manifest.parent / name)
        if digest(artifacts[kind]) != module[kind + '_sha256']:
            raise ValueError('line verification compiled artifact bytes differ')
    standalone = module.get('standalone', {})
    executable = Path(standalone.get('path', ''))
    if (standalone.get('transport') != 'filter' or len(executable.parts) != 1 or executable.is_absolute()
            or standalone.get('runtime_python_required') is not False
            or standalone.get('runtime_libc_required') is not False
            or standalone.get('packer_source_sha256') != digest(regular(root / 'native/filter_packer.hepta'))):
        raise ValueError('line verification static filter identity differs')
    elf = regular(manifest.parent / executable)
    if digest(elf) != standalone.get('sha256'):
        raise ValueError('line verification static filter bytes differ')
    exact_filter_image(elf, artifacts['image'])
    expected_summary = {'source_sha256': source_sha, 'manifest_sha256': owner['sha256'],
        'image_sha256': module['image_sha256'], 'composition_sha256': composition_sha,
        'test_sha256': digest(regular(root / 'tests/hia_native/test_line_verify.py')),
        'loader_sha256': digest(regular(root / 'scripts/hia_native_loader.py'))}
    if any(summary.get(key) != expected for key, expected in expected_summary.items()):
        raise ValueError('line verification completed source/test/loader/artifact identity differs')
    original = regular(root / ORIGINAL_SOURCE)
    original_blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
    composition = json.loads(composition_raw)
    if (digest(original) != ORIGINAL_SHA256 or original_blob != ORIGINAL_BLOB
            or composition.get('original_runtime_commit') != 'a0dcdda1991ec536d5e2d252c006a778993fa566'
            or composition.get('source_sha256') != source_sha
            or composition.get('original_sources') != {ORIGINAL_SOURCE: {'sha256': ORIGINAL_SHA256, 'blob': ORIGINAL_BLOB}}):
        raise ValueError('line verification original source owner differs')
    generator = root / 'tests/hia_native/test_line_verify.py'
    spec = importlib.util.spec_from_file_location('qualified_line_verify_owner', generator)
    original_owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original_owner)
    oracle_name = 'tests/hia_native/oracle_line_verify.rs'
    oracle = regular(root / oracle_name)
    if oracle != original_owner.oracle_source(root).encode() or summary.get('oracle_sha256') != digest(oracle):
        raise ValueError('line verification oracle does not retain the unchanged original functions')
    folder = output / FOLDER
    metadata_raw = regular(folder / 'native-corpus.json')
    corpus = json.loads(metadata_raw)
    exact_counts(corpus.get('counts'))
    if (corpus.get('schema') != 'hepta.runtime.native-corpus.v1' or corpus.get('component') != 'line_verify'
            or type(corpus.get('cases')) is not int or corpus['cases'] != CASES
            or corpus.get('requests_file') != CORPUS_FILES[1] or corpus.get('native_output_file') != CORPUS_FILES[2]
            or corpus.get('requests_bytes') != WIRE_BYTES or corpus.get('requests_sha256') != WIRE_SHA256
            or corpus.get('native_output_bytes') != OUTPUT_BYTES or corpus.get('native_output_sha256') != OUTPUT_SHA256
            or corpus.get('source_sha256') != source_sha or corpus.get('image_sha256') != module['image_sha256']
            or corpus.get('composition_sha256') != composition_sha or corpus.get('original_line_hash_sha256') != ORIGINAL_SHA256
            or corpus.get('oracle') != oracle_name or corpus.get('oracle_sha256') != digest(oracle)
            or type(corpus.get('imported_helper_functions')) is not int or corpus['imported_helper_functions'] != 5):
        raise ValueError('line verification captured corpus identity or complete domain differs')
    if (stream_identity(folder / CORPUS_FILES[1], WIRE_BYTES) != (WIRE_BYTES, WIRE_SHA256)
            or stream_identity(folder / CORPUS_FILES[2], OUTPUT_BYTES) != (OUTPUT_BYTES, OUTPUT_SHA256)):
        raise ValueError('line verification complete captured native bytes differ')
    return {'status': 'PASS', 'captured_native_cases': CASES, 'counts': COUNTS,
        'direct_native_calls': CASES + COUNTS['invalid'] + COUNTS['capacity'] + COUNTS['exact_output'],
        'actual_elf_calls': COUNTS['standalone_elf'] + COUNTS['standalone_invalid'],
        'native_cases_added_by_replay': 0, 'source_sha256': source_sha, 'image_sha256': module['image_sha256'],
        'module_manifest_sha256': owner['sha256'], 'composition_sha256': composition_sha,
        'executable_sha256': standalone['sha256'], 'exact_elf_image_binding': True,
        'filter_template_sha256': FILTER_TEMPLATE_SHA256, 'original_source_sha256': ORIGINAL_SHA256,
        'oracle_sources_sha256': {name: digest(regular(root / name)) for name in (
            oracle_name, 'tests/hia_native/line_verify_oracle_transport.rs')},
        'input_bytes': WIRE_BYTES, 'input_sha256': WIRE_SHA256,
        'native_output_bytes': OUTPUT_BYTES, 'native_output_sha256': OUTPUT_SHA256,
        'corpus_metadata_sha256': digest(metadata_raw),
        'test_stdout_sha256': check['stdout_sha256'], 'test_stderr_sha256': check['stderr_sha256'],
        'scope': 'Internal stale-line-ID verification, complete diagnostics and strict/clamped LP64 index resolution',
        'complete_original_tool_parity': False, 'production_activated': False}
