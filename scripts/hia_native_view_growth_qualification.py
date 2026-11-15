"""Admit complete wide-render execution and original-reference inputs."""
from __future__ import annotations
import gzip
import hashlib
import math
from pathlib import Path
import sys
from hia_native_build import ABI, HEPTA_COMMIT
from hia_native_result_publication_qualification import Artifacts, decode, exact, owned, require, sha

FOLDER = 'view-render-growth'
SUITE = 'test_view_render_growth.py'
EVIDENCE_SUITE = 'test_view_render_growth_evidence.py'
CORPUS_FILES = ('native-corpus.json', 'requests.hex.gz', 'native-output.txt.gz', 'result.json')
CASES = 2705
INPUT_BYTES = 139170251
INPUT_SHA256 = 'b9185e085ece0a3abc1271ba50979cba00d438051bd6a603413e07b5dbb57ac3'
OUTPUT_BYTES = 1173696
OUTPUT_SHA256 = '6770742d493aa09accb8e3ec9e9696cc6d68e8e0ed02240120ec2b49b7d094b8'
CATEGORIES = {'cache_delta': 225, 'endpoint_bounds': 1008, 'exact_myers_ceiling': 6,
    'full_refresh': 225, 'independent-33MiB-CRLF-snapshots': 1,
    'independent-33MiB-snapshots': 1, 'metadata_order': 72,
    'normalization_and_terminators': 7, 'random_snapshots': 900,
    'separate_read_snapshots': 200, 'whole': 60}
GROWTH_CASES = [
    {'input_bytes': 34603119, 'input_sha256': '32e7fb43146d7ad5b2329fa0be45575bd6fdf5ee37694b05c5fad4feafffa77d',
     'name': 'independent-33MiB-snapshots', 'output_bytes': 167,
     'output_sha256': '6fb7a1520a8b80b8c18eb7fab4578cba6cb8f41cd276173dd4a03021a18e392c',
     'short_output_capacity': 166, 'short_output_return': 4294967294, 'short_output_unchanged': True},
    {'input_bytes': 34603121, 'input_sha256': '2fe37a9c77f0618400d8e40e2cebf8c8e4c949cc9a46824f9798a8f8ff60e9fb',
     'name': 'independent-33MiB-CRLF-snapshots', 'output_bytes': 167,
     'output_sha256': '6fb7a1520a8b80b8c18eb7fab4578cba6cb8f41cd276173dd4a03021a18e392c',
     'short_output_capacity': 166, 'short_output_return': 4294967294, 'short_output_unchanged': True},
]

def completed_suite(root, output, report, name, completed):
    rows = [row for row in report.get('checks', []) if row.get('name') == name]
    require(len(rows) == 1, 'growth suite is missing or duplicated')
    check = rows[0]
    exact(check.get('command'), [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / name)],
          'growth suite command differs')
    exact([check.get('exit_code'), check.get('timed_out'), check.get('timeout_seconds')],
          [0, False, 180], 'growth suite completion or deadline differs')
    elapsed = check.get('elapsed_seconds')
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed < 180,
            'growth suite elapsed time is invalid')
    require(not check.get('start_error'), 'growth suite failed to start')
    for suffix in ('stdout', 'stderr'):
        raw = owned(output, name + '.' + suffix).read_bytes()
        exact([check.get(suffix + '_bytes'), check.get(suffix + '_sha256')],
              [len(raw), sha(raw)], 'growth suite stream bytes differ')
    checked, summary = completed(output, report, name)
    exact(decode(owned(output, name + '.stdout').read_bytes()), summary,
          'growth stdout is not one complete strict JSON result')
    return checked, summary

def stream_identity(path, maximum, *, cases=CASES):
    path = Path(path)
    require(path.resolve() == path.absolute() and path.is_file() and not path.is_symlink(),
            'growth corpus is not a regular unsymlinked file')
    digest, count, lines, last = hashlib.sha256(), 0, 0, b''
    with gzip.open(path, 'rb') as source:
        while chunk := source.read(1 << 20):
            count += len(chunk)
            require(count <= maximum, 'growth corpus exceeds its complete captured extent')
            digest.update(chunk)
            lines += chunk.count(b'\n')
            last = chunk[-1:]
    exact([count, lines, last == b'\n'], [maximum, cases, True], 'growth corpus row/byte extent differs')
    return count, digest.hexdigest()

def source_inputs(root, composition):
    paths = {'native/view_render.hepta', 'native/view_render_composition.json',
        'tests/hia_native/test_view_render_growth.py', 'tests/hia_native/test_view_render.py',
        'tests/hia_native/test_delta.py', 'tests/hia_native/test_text_budget.py',
        'tests/hia_native/oracle_view_render.rs', 'tests/hia_native/view_oracle_source.py',
        'tests/hia_native/compare_view_original.py', 'scripts/hia_native_loader.py'}
    paths.update(row['path'] for row in composition['imports'])
    paths.update(composition['original_sources'])
    return {name: sha(owned(root, name).read_bytes()) for name in sorted(paths)}

def native_evidence(root, output, report, completed, *, include_evidence=False):
    check, summary = completed_suite(root, output, report, SUITE, completed)
    require(summary.get('schema') == 'hepta.runtime.view-render-growth-native.v1', 'growth suite schema differs')
    expected = {'status': 'PASS', 'test_groups': 4, 'skipped': 0, 'errors': 0, 'failures': 0,
        'native_calls': 2707, 'native_semantic_cases': CASES, 'retained_component_cases': 2703,
        'controls': 2, 'source_functions': 72, 'unchanged_functions': 66,
        'fresh_rust_processes': 0, 'rust_replay_required': True, 'actual_elf_processes': 0,
        'public_mcp_route_replaced': False, 'whole_view_replaced': False, 'native_cases_added_by_replay': 0}
    exact({key: summary.get(key) for key in expected}, expected, 'growth semantic/control accounting differs')
    exact(summary.get('categories'), CATEGORIES, 'growth case categories differ')
    exact(summary.get('growth_cases'), GROWTH_CASES, 'growth complete snapshots or refusal controls differ')
    elapsed = summary.get('elapsed_seconds')
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed < 180,
            'growth native execution time differs')
    reader = Artifacts(output)
    owner = report['modules']['view_render_growth']
    exact([owner.get('source'), owner.get('builder')], ['native/view_render.hepta', 'borrowed_bytes'],
          'growth module owner differs')
    manifest = owner['manifest']
    raw_manifest = reader.read(manifest)
    module = decode(raw_manifest)
    require(sha(raw_manifest) == owner['sha256'], 'growth module manifest bytes differ')
    expected_module = {'schema': 'hepta.runtime.native-module.v1', 'abi': ABI, 'target': 'linux-x86_64',
        'name': 'view-render-growth', 'compiler_commit': HEPTA_COMMIT,
        'compiler_sha256': report['compiler_image_sha256'], 'buffer_profile': 'history.v1',
        'input_capacity': 128 << 20, 'output_capacity': 128 << 20, 'workspace_capacity': 256 << 20,
        'standalone': None}
    exact({key: module.get(key) for key in expected_module}, expected_module,
          'growth compiler identity or named borrowed-buffer profile differs')
    source = owned(root, 'native/view_render.hepta').read_bytes()
    require(module.get('source_sha256') == sha(source), 'growth compiled source differs')
    artifacts = {}
    for name in ('source', 'image'):
        relative = module[name]
        require(type(relative) is str and Path(relative).name == relative and relative not in ('', '.', '..'),
                'growth module artifact path differs')
        raw = reader.read((Path(manifest).parent / relative).as_posix())
        require(sha(raw) == module[name + '_sha256'], 'growth compiled artifact bytes differ')
        artifacts[name] = raw
    require(artifacts['source'] == source, 'growth retained compiler input differs')
    exact([summary.get('manifest_sha256'), summary.get('source_sha256'), summary.get('image_sha256')],
          [owner['sha256'], sha(source), module['image_sha256']], 'growth suite used a different native image')
    composition_raw = owned(root, 'native/view_render_composition.json').read_bytes()
    composition = decode(composition_raw)
    require(composition['source_sha256'] == sha(source), 'growth composition source differs')
    revision = composition['growth_revision']
    exact([revision.get('base_source_sha256'), revision.get('changed_functions'), revision.get('added_functions'),
           revision.get('independent_u64_range_and_counts'), revision.get('packed_counter_maximum_removed'),
           revision.get('maximum_frame_bytes'), revision.get('closed_mcp_view_handler')],
          ['d7012a796fd83744bcfb4951d01a95d3bab63f9a7ed185ad035c4665989066a3',
           ['f0', 'f1', 'f2', 'f3'], ['f70', 'f71'], True, True, None, False],
          'growth source revision or scope differs')
    require(set(revision['unchanged_functions']) == {f'f{i}' for i in range(4, 70)},
            'growth unchanged function inventory differs')
    pins = source_inputs(root, composition)
    exact(summary.get('source_inputs'), pins, 'growth native suite source closure differs')
    originals = {}
    for name, expected_source in composition['original_sources'].items():
        raw = owned(root, name).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        exact([sha(raw), blob], [expected_source['sha256'], expected_source['blob']],
              'growth original source changed: ' + name)
        originals[name] = sha(raw)
    result_raw = reader.read(FOLDER + '/result.json')
    exact(decode(result_raw), summary, 'growth retained result differs from actual suite stdout')
    corpus_raw = reader.read(FOLDER + '/native-corpus.json')
    corpus = decode(corpus_raw)
    require(summary.get('corpus_metadata_sha256') == sha(corpus_raw), 'growth corpus metadata differs')
    expected_corpus = {'schema': 'hepta.runtime.view-render-growth-native-corpus.v1', 'cases': CASES,
        'retained_component_cases': 2703, 'growth_cases': 2, 'requests_file': 'requests.hex.gz',
        'requests_bytes': INPUT_BYTES, 'requests_sha256': INPUT_SHA256,
        'native_output_file': 'native-output.txt.gz', 'native_output_bytes': OUTPUT_BYTES,
        'native_output_sha256': OUTPUT_SHA256, 'source_sha256': sha(source),
        'manifest_sha256': owner['sha256'], 'image_sha256': module['image_sha256'],
        'oracle_sha256': pins['tests/hia_native/oracle_view_render.rs'],
        'test_sha256': pins['tests/hia_native/test_view_render_growth.py']}
    exact(corpus, expected_corpus, 'growth fixed complete corpus domain differs')
    for field, name, size, digest in [('requests', 'requests.hex.gz', INPUT_BYTES, INPUT_SHA256),
                                    ('native_output', 'native-output.txt.gz', OUTPUT_BYTES, OUTPUT_SHA256)]:
        compressed = reader.read(FOLDER + '/' + name)
        exact(summary.get(field), {'file': name, 'raw_sha256': digest, 'raw_bytes': size, 'lines': CASES,
                                   'gzip_sha256': sha(compressed), 'gzip_bytes': len(compressed)},
              'growth compressed stream identity differs')
        exact(stream_identity(owned(output, FOLDER + '/' + name), size), (size, digest),
              'growth complete decompressed stream differs')
    for suffix in ('stdout', 'stderr'):
        reader.read(SUITE + '.' + suffix)
    checks = {SUITE: {key: check[key] for key in ('stdout_sha256', 'stderr_sha256')}}
    if include_evidence:
        control_check, controls = completed_suite(root, output, report, EVIDENCE_SUITE, completed)
        expected_controls = {'status': 'PASS', 'test_groups': 5, 'refusal_controls': 30,
            'skipped': 0, 'failures': 0, 'errors': 0, 'native_calls_added': 0, 'rust_processes_added': 0,
            'test_sha256': sha(owned(root, 'tests/hia_native/' + EVIDENCE_SUITE).read_bytes()),
            'reader_sha256': sha(owned(root, 'scripts/hia_native_view_growth_qualification.py').read_bytes())}
        exact({key: controls.get(key) for key in expected_controls}, expected_controls,
              'growth physical evidence refusal suite differs')
        require(len(controls.get('controls', [])) == len(set(controls.get('controls', []))) == 30,
                'growth refusal controls missing or duplicated')
        for suffix in ('stdout', 'stderr'):
            reader.read(EVIDENCE_SUITE + '.' + suffix)
        checks[EVIDENCE_SUITE] = {key: control_check[key] for key in ('stdout_sha256', 'stderr_sha256')}
    return {'status': 'PASS', 'semantic_cases': CASES, 'retained_component_cases': 2703, 'growth_cases': 2,
        'native_calls': 2707, 'native_capacity_controls': 2, 'actual_elf_processes': 0,
        'source_functions': 72, 'unchanged_functions': 66, 'module_manifest_sha256': owner['sha256'],
        'source_sha256': sha(source), 'image_sha256': module['image_sha256'],
        'composition_sha256': sha(composition_raw), 'input_bytes': INPUT_BYTES, 'input_sha256': INPUT_SHA256,
        'native_output_bytes': OUTPUT_BYTES, 'native_output_sha256': OUTPUT_SHA256,
        'corpus_metadata_sha256': sha(corpus_raw), 'original_sources_sha256': originals,
        'oracle_sources_sha256': {name: pins[name] for name in ('tests/hia_native/oracle_view_render.rs',
            'tests/hia_native/view_oracle_source.py', 'tests/hia_native/compare_view_original.py')},
        'artifact_sha256': reader.hashes, 'checks': checks, 'original_rust_replay': False,
        'native_cases_added_by_replay': 0, 'production_activated': False,
        'complete_original_tool_parity': False, 'whole_runtime_replaced': False}
