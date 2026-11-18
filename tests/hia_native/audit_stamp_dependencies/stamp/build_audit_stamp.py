# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compile and bind the fixed two-image archive_stamp graph."""
from pathlib import Path
import argparse
import hashlib
import json
import stat
import struct
import sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
COMMIT = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
STDOUT_FIELDS = frozenset(('abi_status', 'core_u32', 'forbidden_compiler_modules_loaded',
    'image_sha256', 'limits', 'loader_operations', 'native_elapsed_ns', 'output_sha256',
    'output_unchanged', 'result_u64', 'return_encoding', 'source_sha256', 'source_unchanged',
    'status', 'workspace_header'))


def raw(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink():
        raise ValueError('nonregular build input: ' + str(path))
    return path.read_bytes()


def pin(path):
    data = raw(path)
    return dict(bytes=len(data), sha256=SHA(data))


def observer(folder, stem, image, incoming, expected):
    folder = Path(folder)
    record = json.loads(raw(folder / (stem + '.receipt.json')))
    stdout = json.loads(raw(folder / (stem + '.stdout.log')))
    request = json.loads(raw(folder / (stem + '.request.json')))
    output = raw(folder / (stem + '.output.bin'))
    assert type(stdout) is dict and set(stdout) == STDOUT_FIELDS
    assert stdout == {key: record[key] for key in STDOUT_FIELDS}
    assert raw(folder / (stem + '.stderr.log')) == b''
    assert raw(folder / (stem + '.input.bin')) == incoming
    fields = dict(status='returned', abi_status=0, core_u32=len(expected), result_u64=len(expected),
        source_unchanged=True, input_bytes=len(incoming), input_sha256=SHA(incoming),
        source_sha256=SHA(incoming), artifact_sha256=SHA(image), image_sha256=SHA(image),
        output_sha256=SHA(output), forbidden_compiler_modules_loaded=[], return_encoding='zero-extended-u32')
    assert all(type(record.get(k)) is type(v) and record[k] == v for k, v in fields.items())
    assert len(output) == 1048576 and 0 < len(expected) <= len(output) and output[:len(expected)] == expected
    wanted = dict(capacity=1048576, format='flat-x86-64', image_sha256=SHA(image),
        source_sha256=SHA(incoming), workspace_fill=0, workspace_size=1048576)
    assert all(request.get(k) == v for k, v in wanted.items())
    assert Path(request['source']).name == stem + '.input.bin'
    assert Path(request['output']).name == stem + '.output.bin'
    return record


def source_map(source, runtime):
    files = {}
    for base in ('native', 'scripts', 'dependencies', 'original', 'reference-v1'):
        for path in sorted((source / base).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts:
                files['owner/' + str(path.relative_to(source))] = pin(path)
    files['owner/dependency-inputs.json'] = pin(source / 'dependency-inputs.json')
    for name in ('scripts/hia_native_build.py', 'scripts/hia_native_loader.py'):
        files['runtime/' + name] = pin(runtime / name)
    return files


def build_audit_stamp(source, runtime, hepta, output):
    source = Path(source).resolve(strict=True)
    runtime = Path(runtime).resolve(strict=True)
    hepta = Path(hepta).resolve(strict=True)
    output = Path(output).resolve()
    sys.path.insert(0, str(runtime / 'scripts'))
    from hia_native_build import NativeBuild
    builder = NativeBuild(hepta, output)
    before = source_map(source, runtime)
    compiler = raw(builder.bootstrap())
    assert builder.identity['commit'] == COMMIT
    layout_path = source / 'native/request_audit_stamp_layout.json'
    layout = json.loads(raw(layout_path))
    proof = json.loads(raw(source / 'native/request_audit_stamp_composition.json'))
    adapter = json.loads(raw(source / 'native/request_audit_stamp_adapter_composition.json'))
    paths = dict(stamp='native/request_audit_stamp.hepta', namespace='dependencies/audit_legacy_namespace.hepta',
        packer='native/request_audit_stamp_packer.hepta')
    sources = {name: raw(source / path) for name, path in paths.items()}
    assert SHA(sources['stamp']) == proof['source_sha256']
    assert SHA(sources['packer']) == layout['packer_source_sha256']
    assert SHA(raw(source / 'scripts/audit_stamp_adapter.S')) == layout['adapter_source_sha256'] == adapter['adapter_source_sha256']
    assert SHA(sources['namespace']) == proof['children']['namespace']['sha256']
    images, records = {}, {}
    for name, path in paths.items():
        module_name = 'audit-stamp-' + name + '-' + SHA(sources[name])[:16]
        manifest = output / 'modules' / module_name / 'manifest.json'
        if not manifest.exists():
            manifest = builder.compile(module_name, source / path, standalone=None)
        module = json.loads(raw(manifest))
        assert module['compiler_commit'] == COMMIT and module['compiler_sha256'] == SHA(compiler)
        assert module['qualification'] == 'development_fixed_point' and module['standalone'] is None
        assert Path(module['source']).name == module['source'] and Path(module['image']).name == module['image']
        assert raw(manifest.parent / module['source']) == sources[name]
        image = raw(manifest.parent / module['image'])
        assert module['source_sha256'] == SHA(sources[name]) and module['image_sha256'] == SHA(image)
        assert not image.startswith(b'\x7fELF')
        compiled = observer(manifest.parent, 'module', compiler, sources[name], image)
        build = json.loads(raw(manifest.parent / 'build.json'))
        assert build['compiler_dependency'] == builder.identity and build['compile_receipt'] == compiled
        images[name] = image
        records[name] = dict(manifest=str(manifest.relative_to(output)), manifest_sha256=SHA(raw(manifest)),
            source_sha256=SHA(sources[name]), image_sha256=SHA(image), image_bytes=len(image))
    prefix = bytes.fromhex(layout['prefix_hex'])
    assert len(prefix) == layout['prefix_bytes'] and SHA(prefix) == layout['prefix_sha256']
    order = ['stamp', 'namespace']
    assert layout['image_order'] == order and set(layout['call_holes']) == set(order)
    payload = b''.join(images[name] for name in order)
    frame = b'HRASelf1' + struct.pack('<2Q', *(len(images[name]) for name in order)) + payload
    expected = bytearray(prefix)
    size = len(prefix) + len(payload)
    struct.pack_into('<QQ', expected, 96, size, size)
    cursor = len(prefix)
    embedded = {}
    for name in order:
        hole = layout['call_holes'][name]
        assert prefix[hole - 1:hole + 4] == b'\xe8\0\0\0\0'
        struct.pack_into('<i', expected, hole, cursor - hole - 4)
        embedded[name] = dict(offset=cursor, bytes=len(images[name]), sha256=SHA(images[name]))
        cursor += len(images[name])
    expected.extend(payload)
    from tools.qualify_hia_selfhost import invoke
    if not (output / 'pack.receipt.json').exists():
        packer_manifest = output / records['packer']['manifest']
        packer_meta = json.loads(raw(packer_manifest))
        invoke(output, 'pack', packer_manifest.parent / packer_meta['image'], frame)
    packed = observer(output, 'pack', images['packer'], frame, bytes(expected))
    from tools.qualify_hia_selfhost_cli import inspect_executable
    inspection = inspect_executable(bytes(expected))
    executable = output / 'audit-stamp.elf'
    if executable.exists():
        assert raw(executable) == expected
    else:
        executable.write_bytes(expected);executable.chmod(0o500)
    builder._recheck()
    assert raw(builder.compiler) == compiler and source_map(source, runtime) == before
    result = dict(schema='hepta.runtime.audit-stamp-native-bundle.v1', modules=records,
        compiler_commit=COMMIT, compiler_sha256=SHA(compiler), source_bindings=before,
        executable=executable.name, executable_bytes=size, executable_sha256=SHA(expected),
        pack_input_sha256=SHA(frame), pack_input_bytes=len(frame), pack_receipt=packed,
        embedded=embedded, layout_sha256=SHA(raw(layout_path)), inspection=inspection,
        source_unchanged=True, runtime_python_required=False, runtime_rust_required=False,
        runtime_libc_required=False, fresh_compiler_cold_replay=False,
        audit_storage_closed=False, production_activated=False, whole_runtime_replaced=False)
    manifest = output / 'manifest.json'
    if manifest.exists():
        assert json.loads(raw(manifest)) == result
    else:
        manifest.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser()
    for key in ('source', 'runtime', 'hepta', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    options = parser.parse_args()
    print(build_audit_stamp(options.source, options.runtime, options.hepta, options.output))


if __name__ == '__main__': main()


