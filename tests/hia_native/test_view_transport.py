#!/usr/bin/env python3
"""Native capacity-profile, HIA VM and standalone image-boundary controls."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_VIEW_MANIFEST'))
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if not args.manifest or not args.hepta:
        parser.error('manifest and pinned compiler directory are required')
    loader = load('view_profile_loader', ROOT / 'scripts/hia_native_loader.py')
    builder = load('view_profile_builder', ROOT / 'scripts/hia_native_build.py')
    reference = load('view_reference', Path(__file__).with_name('test_view_render.py'))
    reference.DELTA = load('view_delta', args.repo / 'tests/hia_native/test_delta.py')
    reference.TEXT = load('view_text', args.repo / 'tests/hia_native/test_text_budget.py')
    packet = reference.packet
    raw = args.manifest.read_bytes()
    metadata = json.loads(raw)
    counts = {}
    assert metadata['buffer_profile'] == 'view-render.v1'
    assert loader.BUFFER_PROFILES == builder.BUFFER_PROFILES
    assert loader.BUFFER_PROFILES['standard'] == (8 << 20, 8 << 20, 32 << 20)
    mutations = [{'buffer_profile': value} for value in [None, False, 1, [], {}, 'unknown', 'standard']]
    mutations += [{'input_capacity': (16 << 20) + 1}, {'output_capacity': (16 << 20) + 1},
                  {'workspace_capacity': (256 << 20) + 1}, {'workspace_capacity': True}]
    for mutation in mutations:
        with tempfile.TemporaryDirectory(prefix='hia-view-profile-') as temporary:
            root = Path(temporary)
            modified = dict(metadata, **mutation)
            for member in ('source', 'image'):
                shutil.copyfile(args.manifest.parent / metadata[member], root / metadata[member])
            manifest = root / 'manifest.json'
            modified_raw = (json.dumps(modified) + '\n').encode()
            manifest.write_bytes(modified_raw)
            try:
                loader.NativeModule(manifest, manifest_sha256=digest(modified_raw))
            except ValueError:
                counts['profile_admission_refusal'] = counts.get('profile_admission_refusal', 0) + 1
            else:
                raise AssertionError(('unexpected profile admission', mutation))
    for options in [{'buffer_profile': 'view-render.v1', 'standalone': 'stdio'},
                    {'buffer_profile': 'unknown', 'standalone': None}]:
        uninitialized = object.__new__(builder.NativeBuild)
        try:
            uninitialized.compile('invalid-profile', ROOT / 'native/view_render.hepta', **options)
        except ValueError:
            counts['unsupported_transport_before_build'] = counts.get('unsupported_transport_before_build', 0) + 1
        else:
            raise AssertionError('an unsupported transport profile reached compilation')

    sys.path.insert(0, str(args.hepta))
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    program = assemble_program((ROOT / 'native/view_render.hepta').read_bytes())
    samples = [packet('a\r\r\n'), packet('a\r\r\n', start=1),
               packet('changed\n', first='one\ntwo\n', start=2),
               packet('漢\n😀\n', previous='é\n😀\n'),
               packet('a\r\r\n', previous='a\r\n'),
               packet('x', start=0, first_stat=reference.FILE_LIMIT + 1)]
    with loader.NativeModule(args.manifest, manifest_sha256=digest(raw)) as native:
        for wire in samples:
            expected = reference.reference(wire)
            owners = [_Owner(-1, bytearray(wire)), _Owner(-2, bytearray(4096)), _Owner(-3, bytearray(16384))]
            machine = _Machine(program, 10_000_000, 1 << 20, None, 128)
            code = machine.invoke(program.as_dict()['functions'][0],
                [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
            actual = bytes(owners[1].data[:code])
            assert code == len(expected) and actual == expected
            assert native.invoke(wire, output_capacity=4096, workspace_capacity=16384) == actual
            counts['native_vm_original_reference'] = counts.get('native_vm_original_reference', 0) + 1
        with native.session(output_capacity=256, workspace_capacity=512) as small:
            try:
                small.invoke(b'x' * ((16 << 20) + 1))
            except ValueError as error:
                assert 'declared byte profile' in str(error)
            else:
                raise AssertionError('host transport admitted an oversized frame')
            counts['loader_frame_refusal'] = 1

    from tools import generate_hia_native_filter as template
    template.WIRE_BYTES = 16 << 20
    template.OUTPUT_OFFSET = template.WIRE_BYTES + 4096
    prefix, hole = template.template(output_bytes=16 << 20, workspace_bytes=256 << 20)
    executable = args.manifest.parent / metadata['standalone']['path']
    image = (args.manifest.parent / metadata['image']).read_bytes()
    elf = executable.read_bytes()
    expected_prefix = bytearray(prefix)
    struct.pack_into('<Q', expected_prefix, 96, len(elf))
    struct.pack_into('<Q', expected_prefix, 104, len(elf))
    struct.pack_into('<I', expected_prefix, hole, len(prefix) - hole - 4)
    assert elf == expected_prefix + image
    assert digest(elf) == metadata['standalone']['sha256']
    assert metadata['standalone']['inspection']['dynamic_loader'] is False
    assert metadata['standalone']['inspection']['libc'] is False
    counts['exact_profile_template_and_image_binding'] = 1
    for arguments, wire, status in [([], b'', 2), ([], b'bad-frame', 2), (['extra'], b'', 64)]:
        result = subprocess.run([str(executable), *arguments], input=wire, capture_output=True,
                                env={'PATH': ''}, timeout=10)
        assert (result.returncode, result.stdout, result.stderr) == (status, b'', b'')
        counts['standalone_refusal'] = counts.get('standalone_refusal', 0) + 1
    with open('/dev/full', 'wb', buffering=0) as full:
        result = subprocess.run([str(executable)], input=packet('abc'), stdout=full,
            stderr=subprocess.PIPE, env={'PATH': ''}, timeout=10)
    assert result.returncode == 4 and result.stderr == b''
    counts['standalone_output_io_error'] = 1
    report = {'status': 'PASS', 'counts': counts, 'manifest_sha256': digest(raw),
              'source_sha256': metadata['source_sha256'], 'image_sha256': metadata['image_sha256'],
              'elf_sha256': digest(elf), 'test_sha256': digest(Path(__file__).read_bytes()),
              'builder_sha256': digest((ROOT / 'scripts/hia_native_build.py').read_bytes()),
              'loader_sha256': digest((ROOT / 'scripts/hia_native_loader.py').read_bytes()),
              'packer_sha256': digest((ROOT / 'native/view_filter_packer.hepta').read_bytes())}
    if args.report:
        args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
