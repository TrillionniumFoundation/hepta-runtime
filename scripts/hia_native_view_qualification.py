"""Admit full view-render bytes, original owners and named transport evidence."""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import json
import math
from pathlib import Path

FOLDER = 'view-rust-oracle'
CORPUS_FILES = ('native-corpus.json', 'requests.hex.gz', 'native-output.txt.gz')
CASES = 3125
WIRE_BYTES = 237318931
WIRE_SHA256 = '25ee9795db24913b4d2bb717711f613242b51b629203a1588e79bc7dba71a8db'
OUTPUT_BYTES = 139202296
OUTPUT_SHA256 = '3d432e0350eb351df875bcc8fa7d195fbefe2e64460a117a6e3c92c601417c17'
FILTER_TEMPLATE_SHA256 = '5238cf8933ab4e8bc1ab9945de84b5f2da54b8ae8af3b37d393fa11a52c5c6cb'
NATIVE_COUNTS = {'body_budget': 3, 'cache_after_oversize': 1, 'cache_byte_cap': 3, 'cache_byte_cap_with_previous': 3, 'cache_delta': 225, 'capacity': 6, 'declared_input_capacity': 1, 'endpoint_bounds': 1008, 'exact_myers_ceiling': 6, 'exact_output_capacity': 1, 'file_byte_cap': 2, 'file_stat_refusal': 1, 'full_refresh': 225, 'hints_after_body_budget': 1, 'independent_large_snapshots': 1, 'invalid_abi': 135, 'maximum_line_workspace': 1, 'metadata_order': 72, 'normalization_and_terminators': 7, 'normalization_at_cache_cap': 1, 'prepare': 404, 'random_snapshots': 900, 'separate_read_snapshots': 200, 'standalone_elf': 3, 'standalone_frame_capacity': 1, 'whole': 60, 'workspace_refusal_is_not_semantic_none': 1}
TRANSPORT_COUNTS = {'exact_profile_template_and_image_binding': 1, 'loader_frame_refusal': 1, 'native_vm_original_reference': 6, 'profile_admission_refusal': 11, 'standalone_output_io_error': 1, 'standalone_refusal': 3, 'unsupported_transport_before_build': 2}


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError('view evidence must be a regular unsymlinked file: ' + str(path))
    return path.read_bytes()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_counts(actual, expected):
    if (type(actual) is not dict or set(actual) != set(expected)
            or any(type(actual[key]) is not int or actual[key] != value for key, value in expected.items())):
        raise ValueError('view complete request/control accounting differs')


def stream_identity(path, maximum):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError('view compressed corpus must be a regular unsymlinked file')
    sha, size, lines, last = hashlib.sha256(), 0, 0, b''
    with gzip.open(path, 'rb') as source:
        while chunk := source.read(1 << 20):
            size += len(chunk)
            if size > maximum:
                raise ValueError('view decompressed corpus exceeds the exact captured domain')
            sha.update(chunk)
            lines += chunk.count(b'\n')
            last = chunk[-1:]
    if lines != CASES or last != b'\n':
        raise ValueError('view compressed corpus row accounting differs')
    return size, sha.hexdigest()


def exact_filter_image(executable, image):
    if len(executable) != 489 + len(image) or executable[489:] != image:
        raise ValueError('view ELF does not embed the exact admitted native image')
    prefix = bytearray(executable[:489])
    for offset in (96, 104):
        if int.from_bytes(prefix[offset:offset + 8], 'little') != len(executable):
            raise ValueError('view ELF file span differs')
        prefix[offset:offset + 8] = bytes(8)
    if int.from_bytes(prefix[338:342], 'little') != 147:
        raise ValueError('view ELF native entry displacement differs')
    prefix[338:342] = bytes(4)
    if digest(prefix) != FILTER_TEMPLATE_SHA256:
        raise ValueError('view ELF does not match the pinned wide transport')


def view_evidence(root, output, report, completed):
    check, summary = completed(output, report, 'test_view_render.py')
    transport_check, transport = completed(output, report, 'test_view_transport.py')
    exact_counts(summary.get('counts'), NATIVE_COUNTS)
    exact_counts(transport.get('counts'), TRANSPORT_COUNTS)
    if (summary.get('status') != 'PASS' or summary.get('complete_byte_bounds') is not True
            or summary.get('whole_view_migrated') is not False or type(summary.get('functions')) is not int
            or summary['functions'] != 70 or type(summary.get('seconds')) not in (int, float)
            or not math.isfinite(summary['seconds']) or summary['seconds'] <= 0
            or transport.get('status') != 'PASS'):
        raise ValueError('view full byte-domain and transport suites did not complete')
    owner = report['modules']['view_render']
    relative = Path(owner['manifest'])
    if relative.is_absolute() or '..' in relative.parts or owner.get('builder') != 'borrowed_bytes':
        raise ValueError('view native module path or builder differs')
    manifest = output / relative
    module_raw = regular(manifest)
    module = json.loads(module_raw)
    source_sha = digest(regular(root / 'native/view_render.hepta'))
    composition_raw = regular(root / 'native/view_render_composition.json')
    composition_sha = digest(composition_raw)
    if (digest(module_raw) != owner['sha256'] or module.get('source_sha256') != source_sha
            or module.get('compiler_sha256') != report['compiler_image_sha256']
            or module.get('compiler_commit') != 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
            or module.get('buffer_profile') != 'view-render.v1'
            or module.get('input_capacity') != 16 << 20 or module.get('output_capacity') != 16 << 20
            or module.get('workspace_capacity') != 256 << 20):
        raise ValueError('view native module/compiler/named capacity identity differs')
    artifacts = {}
    for kind in ('source', 'image'):
        name = Path(module[kind])
        if name.is_absolute() or len(name.parts) != 1:
            raise ValueError('view compiled artifact path differs')
        artifacts[kind] = regular(manifest.parent / name)
        if digest(artifacts[kind]) != module[kind + '_sha256']:
            raise ValueError('view compiled artifact bytes differ')
    standalone = module.get('standalone', {})
    executable = Path(standalone.get('path', ''))
    if (standalone.get('transport') != 'filter' or len(executable.parts) != 1 or executable.is_absolute()
            or standalone.get('runtime_python_required') is not False
            or standalone.get('runtime_libc_required') is not False
            or standalone.get('packer_source_sha256') != digest(regular(root / 'native/view_filter_packer.hepta'))):
        raise ValueError('view named static filter identity differs')
    elf = regular(manifest.parent / executable)
    if digest(elf) != standalone.get('sha256'):
        raise ValueError('view static filter bytes differ')
    exact_filter_image(elf, artifacts['image'])
    for observed in (summary, transport):
        for key, expected in [('source_sha256', source_sha), ('manifest_sha256', owner['sha256']),
                              ('image_sha256', module['image_sha256'])]:
            if observed.get(key) != expected:
                raise ValueError('view completed suite was run against different native bytes')
    source_checks = {
        'test_sha256': 'tests/hia_native/test_view_transport.py',
        'builder_sha256': 'scripts/hia_native_build.py', 'loader_sha256': 'scripts/hia_native_loader.py',
        'packer_sha256': 'native/view_filter_packer.hepta'}
    if (transport.get('elf_sha256') != standalone['sha256']
            or any(transport.get(key) != digest(regular(root / name)) for key, name in source_checks.items())
            or summary.get('test_sha256') != digest(regular(root / 'tests/hia_native/test_view_render.py'))
            or summary.get('composition_sha256') != composition_sha):
        raise ValueError('view completed test/source/transport implementation differs')
    composition = json.loads(composition_raw)
    if (composition.get('original_runtime_commit') != 'a0dcdda1991ec536d5e2d252c006a778993fa566'
            or composition.get('source_sha256') != source_sha):
        raise ValueError('view source-composition owner differs')
    originals = {}
    for name, expected in composition['original_sources'].items():
        raw = regular(root / name)
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if digest(raw) != expected['sha256'] or blob != expected['blob']:
            raise ValueError('view complete original source differs: ' + name)
        originals[name] = digest(raw)
    oracle_path = root / 'tests/hia_native/oracle_view_render.rs'
    generator_path = root / 'tests/hia_native/view_oracle_source.py'
    spec = importlib.util.spec_from_file_location('qualified_original_view_owner', generator_path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    oracle = regular(oracle_path)
    if oracle != generator.oracle_source(root).encode() or summary.get('oracle_sha256') != digest(oracle):
        raise ValueError('view oracle does not retain the unchanged original methods')
    folder = output / FOLDER
    metadata_raw = regular(folder / 'native-corpus.json')
    corpus = json.loads(metadata_raw)
    if (corpus.get('schema') != 'hepta.runtime.view-render-native-corpus.v1'
            or type(corpus.get('cases')) is not int or corpus['cases'] != CASES
            or corpus.get('source_sha256') != source_sha or corpus.get('manifest_sha256') != owner['sha256']
            or corpus.get('image_sha256') != module['image_sha256'] or corpus.get('oracle_sha256') != digest(oracle)
            or corpus.get('requests_file') != CORPUS_FILES[1] or corpus.get('native_output_file') != CORPUS_FILES[2]
            or corpus.get('requests_bytes') != WIRE_BYTES or corpus.get('requests_sha256') != WIRE_SHA256
            or corpus.get('native_output_bytes') != OUTPUT_BYTES or corpus.get('native_output_sha256') != OUTPUT_SHA256):
        raise ValueError('view captured native corpus identity or complete domain differs')
    if (stream_identity(folder / CORPUS_FILES[1], WIRE_BYTES) != (WIRE_BYTES, WIRE_SHA256)
            or stream_identity(folder / CORPUS_FILES[2], OUTPUT_BYTES) != (OUTPUT_BYTES, OUTPUT_SHA256)):
        raise ValueError('view complete captured native bytes differ')
    return {'status': 'PASS', 'captured_native_cases': CASES, 'native_counts': NATIVE_COUNTS,
        'transport_counts': TRANSPORT_COUNTS, 'native_cases_added_by_replay': 0,
        'source_sha256': source_sha, 'image_sha256': module['image_sha256'],
        'module_manifest_sha256': owner['sha256'], 'composition_sha256': composition_sha,
        'executable_sha256': standalone['sha256'], 'exact_elf_image_binding': True,
        'filter_template_sha256': FILTER_TEMPLATE_SHA256, 'original_sources_sha256': originals,
        'oracle_sources_sha256': {name: digest(regular(root / name)) for name in (
            'tests/hia_native/oracle_view_render.rs', 'tests/hia_native/view_oracle_source.py',
            'tests/hia_native/compare_view_original.py')},
        'input_bytes': WIRE_BYTES, 'input_sha256': WIRE_SHA256,
        'native_output_bytes': OUTPUT_BYTES, 'native_output_sha256': OUTPUT_SHA256,
        'corpus_metadata_sha256': digest(metadata_raw),
        'checks': {row['name']: {field: row[field] for field in ('stdout_sha256', 'stderr_sha256')}
                   for row in (check, transport_check)},
        'scope': 'Typed view rendering and cache plan with independent read snapshots; no file effects or cache storage',
        'complete_original_tool_parity': False, 'production_activated': False}
