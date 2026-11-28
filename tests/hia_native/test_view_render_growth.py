#!/usr/bin/env python3
"""Reproducible native render growth controls and complete Rust-replay corpus.

The 2,703 retained vectors overlap the original component qualification. Two
additional complete, independent read snapshots exceed its retained filter
window. This suite executes actual HIA and exports every compared byte; it
does not execute Rust or claim a production MCP route.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_loader import NativeModule


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Transcript:
    def __init__(self, path):
        self.path = path
        self.file = path.open('xb')
        self.stream = gzip.GzipFile(filename='', mode='wb', fileobj=self.file, mtime=0)
        self.hash = hashlib.sha256()
        self.size = 0
        self.lines = 0

    def write(self, raw):
        self.stream.write(raw)
        self.hash.update(raw)
        self.size += len(raw)

    def hex_line(self, raw, prefix=b''):
        self.write(prefix)
        for offset in range(0, len(raw), 1 << 20):
            self.write(raw[offset:offset + (1 << 20)].hex().encode('ascii'))
        self.write(b'\n')
        self.lines += 1

    def close(self):
        self.stream.close()
        self.file.close()
        compressed = self.path.read_bytes()
        return {'file': self.path.name, 'raw_sha256': self.hash.hexdigest(),
                'raw_bytes': self.size, 'lines': self.lines,
                'gzip_sha256': digest(compressed), 'gzip_bytes': len(compressed)}


def growth_cases(view):
    first = b'first\n' + b'x' * (17 << 20) + b'\n'
    current = b'second\n' + b'y' * (16 << 20) + b'\n'
    yield 'independent-33MiB-snapshots', view.packet(current, first=first,
            start=1, end=1, first_stat=0, current_stat=0)
    del current
    current = b'second\r\n' + b'y' * (16 << 20) + b'\r\n'
    yield 'independent-33MiB-CRLF-snapshots', view.packet(current, first=first,
            start=1, end=1, first_stat=0, current_stat=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_VIEW_GROWTH_MANIFEST'))
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--corpus-dir', type=Path, default=os.environ.get('HIA_VIEW_GROWTH_CORPUS_DIR'))
    args = parser.parse_args()
    if not args.manifest or not args.hepta or not args.corpus_dir:
        parser.error('manifest, pinned Hepta checkout and a fresh corpus directory are required')
    manifest = args.manifest.resolve(strict=True)
    target = args.corpus_dir.resolve()
    target.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    view = load('view_growth_original_python_reference', ROOT / 'tests/hia_native/test_view_render.py')
    view.DELTA = load('view_growth_delta_reference', ROOT / 'tests/hia_native/test_delta.py')
    view.TEXT = load('view_growth_text_reference', ROOT / 'tests/hia_native/test_text_budget.py')
    source = ROOT / 'native/view_render.hepta'
    composition_path = ROOT / 'native/view_render_composition.json'
    composition = json.loads(composition_path.read_bytes())
    document = view.check_composition(ROOT, source, composition, args.hepta.resolve(strict=True))
    revision = composition['growth_revision']
    assert revision['base_source_sha256'] == 'd7012a796fd83744bcfb4951d01a95d3bab63f9a7ed185ad035c4665989066a3'
    assert revision['changed_functions'] == ['f0', 'f1', 'f2', 'f3']
    assert revision['added_functions'] == ['f70', 'f71']
    functions = {f['name']: f for f in document['functions']}
    assert len(functions) == 72
    unchanged = {name: digest(json.dumps(functions[name], sort_keys=True,
                    separators=(',', ':')).encode()) for name in functions
                    if name not in {'f0', 'f1', 'f2', 'f3', 'f70', 'f71'}}
    assert len(unchanged) == 66 and unchanged == revision['unchanged_functions']
    assert revision['independent_u64_range_and_counts'] is True
    assert revision['packed_counter_maximum_removed'] is True
    assert revision['maximum_frame_bytes'] is None
    oracle_source = load('view_growth_original_oracle_source', ROOT / 'tests/hia_native/view_oracle_source.py')
    oracle = ROOT / 'tests/hia_native/oracle_view_render.rs'
    assert oracle.read_bytes() == oracle_source.oracle_source(ROOT).encode()
    files = {str(source.relative_to(ROOT)), str(composition_path.relative_to(ROOT)),
             'tests/hia_native/test_view_render_growth.py', 'tests/hia_native/test_view_render.py',
             'tests/hia_native/test_delta.py', 'tests/hia_native/test_text_budget.py',
             'tests/hia_native/oracle_view_render.rs', 'tests/hia_native/view_oracle_source.py',
             'tests/hia_native/compare_view_original.py',
             'scripts/hia_native_loader.py'}
    files.update(row['path'] for row in composition['imports'])
    files.update(composition['original_sources'])
    before = {name: digest((ROOT / name).read_bytes()) for name in sorted(files)}
    raw_manifest = manifest.read_bytes()
    metadata = json.loads(raw_manifest)
    assert metadata['source_sha256'] == before['native/view_render.hepta']
    assert metadata['input_capacity'] >= 35 << 20
    assert metadata['output_capacity'] >= 1 << 20
    assert metadata['workspace_capacity'] >= 8 << 20
    requests = Transcript(target / 'requests.hex.gz')
    outputs = Transcript(target / 'native-output.txt.gz')
    categories = {}
    rows = []
    native_calls = 0
    with NativeModule(manifest, manifest_sha256=digest(raw_manifest)) as module:
        with module.session(output_capacity=1 << 20, workspace_capacity=8 << 20) as session:
            for label, wire in view.cases():
                expected = view.reference(wire)
                actual = session.invoke(wire)
                assert actual == expected, label
                requests.hex_line(wire)
                outputs.hex_line(actual, b'OK ')
                categories[label] = categories.get(label, 0) + 1
                native_calls += 1
            assert native_calls == 2703
            for label, wire in growth_cases(view):
                assert len(wire) > 32 << 20
                expected = view.reference(wire)
                actual = session.invoke(wire)
                assert actual == expected, label
                requests.hex_line(wire)
                outputs.hex_line(actual, b'OK ')
                categories[label] = 1
                native_calls += 1
                code, untouched, _ = module.invoke_raw(wire, output_capacity=len(actual) - 1,
                        workspace_capacity=8 << 20, output_fill=0xA7)
                assert code == 0xFFFFFFFE and untouched == b'\xA7' * (len(actual) - 1)
                native_calls += 1
                rows.append({'name': label, 'input_bytes': len(wire), 'input_sha256': digest(wire),
                             'output_bytes': len(actual), 'output_sha256': digest(actual),
                             'short_output_capacity': len(actual) - 1,
                             'short_output_return': code, 'short_output_unchanged': True})
    artifact_inputs = requests.close()
    artifact_outputs = outputs.close()
    assert artifact_inputs['lines'] == artifact_outputs['lines'] == 2705
    assert before == {name: digest((ROOT / name).read_bytes()) for name in sorted(files)}
    corpus = {'schema': 'hepta.runtime.view-render-growth-native-corpus.v1',
              'cases': 2705, 'retained_component_cases': 2703, 'growth_cases': 2,
              'requests_file': artifact_inputs['file'],
              'requests_bytes': artifact_inputs['raw_bytes'],
              'requests_sha256': artifact_inputs['raw_sha256'],
              'native_output_file': artifact_outputs['file'],
              'native_output_bytes': artifact_outputs['raw_bytes'],
              'native_output_sha256': artifact_outputs['raw_sha256'],
              'source_sha256': metadata['source_sha256'], 'manifest_sha256': digest(raw_manifest),
              'image_sha256': metadata['image_sha256'],
              'oracle_sha256': before['tests/hia_native/oracle_view_render.rs'],
              'test_sha256': before['tests/hia_native/test_view_render_growth.py']}
    corpus_raw = (json.dumps(corpus, sort_keys=True, indent=2) + '\n').encode()
    (target / 'native-corpus.json').write_bytes(corpus_raw)
    result = {'schema': 'hepta.runtime.view-render-growth-native.v1', 'status': 'PASS',
              'test_groups': 4, 'skipped': 0, 'errors': 0, 'failures': 0,
              'native_calls': native_calls, 'native_semantic_cases': 2705,
              'retained_component_cases': 2703, 'growth_cases': rows, 'controls': 2,
              'source_functions': 72, 'unchanged_functions': 66,
              'fresh_rust_processes': 0, 'rust_replay_required': True,
              'actual_elf_processes': 0, 'public_mcp_route_replaced': False,
              'whole_view_replaced': False, 'native_cases_added_by_replay': 0,
              'manifest_sha256': digest(raw_manifest), 'source_sha256': metadata['source_sha256'],
              'image_sha256': metadata['image_sha256'], 'source_inputs': before,
              'requests': artifact_inputs, 'native_output': artifact_outputs,
              'corpus_metadata_sha256': digest(corpus_raw),
              'categories': categories, 'elapsed_seconds': time.monotonic() - started}
    (target / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
