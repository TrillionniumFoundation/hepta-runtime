"""Build the fixed private 12-image Local text-body fixture from pinned sources.

The test-only read candidate is isolated until all shared read descendants are
rebound. No host function implements a body decision or replaces a HIA child.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FOLDER = 'tests/hia_native/local_text_body'
COMPONENT = FOLDER + '/component.json'
COMPONENT_SHA256 = '56f9964bd816ac1b873351fd56f2c128647acf2cf3c7c349f941cb40f0ad99db'
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import ABI, HEPTA_COMMIT, NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule

SCOPE = dict(full_body_async_qualified=False, public_handler_qualified=False,
             whole_runtime_replaced=False, old_stack_removal_qualified=False)
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PIN = lambda raw: dict(bytes=len(raw), sha256=SHA(raw))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def read(path):
    path = Path(path).absolute()
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve() == path,
            'body artifact must be an ordinary unaliased file: ' + str(path))
    return path.read_bytes()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate body evidence field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def relative(root, name):
    require(type(name) is str and name and not Path(name).is_absolute()
            and all(part not in ('', '.', '..') for part in name.split('/')),
            'body artifact path must be relative')
    path = Path(root) / name
    read(path)
    return path


def source_evidence(source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    raw_component = read(root / COMPONENT)
    require(SHA(raw_component) == COMPONENT_SHA256, 'body fixed component binding differs')
    component = decode(raw_component)
    require(component['schema'] == 'hepta.runtime.local-text-body-fixture-source.v1'
            and component['scope'] == SCOPE and component['hepta']['commit'] == HEPTA_COMMIT,
            'body source scope or compiler differs')
    names = ('local_text_body', 'local_read', 'file_lock_key', 'file_lock_state',
             'editable_content', 'text_replace_match', 'history', 'atomic_write',
             'view_cache', 'text_replace_render', 'shell_capture_file', 'view_error')
    require([r['name'] for r in component['members']] == list(names)
            and [r['number'] for r in component['members']] == list(range(12))
            and [r['child'] for r in component['members']] == list(range(10)) + [11, 12],
            'body image order or callback hole differs')
    files = {name: PIN(read(root / name)) for name in (
        COMPONENT, 'scripts/hia_native_local_text_body_build.py',
        'scripts/hia_native_build.py', 'scripts/hia_native_loader.py')}
    for row in [*component['members'], *(component[k] for k in ('packer', 'prefix', 'assembly', 'export'))]:
        raw = read(relative(root, row['source']))
        require(PIN(raw) == {key: row[key] for key in ('bytes', 'sha256')},
                'body fixed source differs: ' + row['source'])
        files[row['source']] = PIN(raw)
    proof_path = FOLDER + '/fixture-proof.json'
    proof = decode(read(root / proof_path))
    files[proof_path] = PIN(read(root / proof_path))
    prefix = read(root / component['prefix']['source'])
    require(len(prefix) == 14448 and proof['table_offset'] == 14352
            and prefix[96:112] == bytes(16) and prefix[14352:] == bytes(96)
            and proof['source_sha256'] == component['assembly']['sha256']
            and proof['export_sha256'] == component['export']['sha256']
            and proof['packer_sha256'] == component['packer']['sha256']
            and proof['prefix_sha256'] == component['prefix']['sha256'],
            'body assembly/packer derivation differs')
    require(read(root / component['assembly']['source']).count(
                read(root / component['export']['source'])) == 1,
            'body fixture must contain the complete callable exactly once')
    return dict(component=component, files=files)


def executable(component, prefix, images):
    require(len(images) == 12, 'body image count differs')
    for expected, raw in zip(component['members'], images, strict=True):
        require(PIN(raw) == dict(bytes=expected['image_bytes'], sha256=expected['image_sha256']),
                'body fixed image differs: ' + expected['name'])
    result = bytearray(prefix)
    size = len(prefix) + sum(map(len, images))
    struct.pack_into('<QQ', result, 96, size, size)
    struct.pack_into('<12Q', result, 14352, *(len(raw) for raw in images))
    result = bytes(result) + b''.join(images)
    require(PIN(result) == component['expected_elf'], 'body complete fixed executable differs')
    return result


def module_expected(name, source_sha, image_sha, compiler):
    return dict(schema='hepta.runtime.native-module.v1', name=name, abi=ABI,
        target='linux-x86_64', compiler_commit=HEPTA_COMMIT, compiler_sha256=compiler,
        source=name + '.hepta', source_sha256=source_sha,
        image=name + '.image.bin', image_sha256=image_sha,
        input_capacity=134217728, output_capacity=134217728, workspace_capacity=268435456,
        qualification='development_fixed_point', standalone=None, buffer_profile='history.v1')


def check_compile(compiled, source, image, compiler):
    require(compiled.get('status') == 'returned' and type(compiled.get('abi_status')) is int
            and compiled['abi_status'] == 0 and type(compiled.get('core_u32')) is int
            and compiled['core_u32'] == len(image) and compiled.get('source_unchanged') is True
            and compiled.get('forbidden_compiler_modules_loaded') == []
            and compiled.get('input_sha256') == SHA(source) and compiled.get('input_bytes') == len(source)
            and compiled.get('artifact_sha256') == compiler and compiled.get('format') == 'flat-x86-64'
            and compiled.get('produced_sha256') == SHA(image) and compiled.get('produced_bytes') == len(image),
            'body actual native compile receipt differs')


def verify_build(manifest_path, *, source_root=ROOT):
    source = source_evidence(source_root)
    component = source['component']
    path = Path(manifest_path).absolute()
    folder = path.parent
    report = decode(read(path))
    require(report['schema'] == 'hepta.runtime.local-text-body-fixture-build.v1'
            and report['status'] == 'PASS' and report['scope'] == SCOPE
            and report['source_inputs'] == source and report['actual_member_compiles'] == 13
            and report['runtime_python_required'] is False and report['runtime_libc_required'] is False,
            'body build source, scope or actual compile count differs')
    artifacts = {path.name: PIN(read(path))}
    def get(name):
        raw = read(relative(folder, name)); artifacts[name] = PIN(raw); return raw
    images = []
    require(len(report['members']) == 12, 'body build member count differs')
    for row, expected in zip(report['members'], component['members'], strict=True):
        name = expected['name']
        require(row['number'] == expected['number'] and row['child'] == expected['child']
                and row['name'] == name and row['manifest'] == name + '.json',
                'body build member order differs')
        raw = get(row['manifest']); child = decode(raw)
        require(SHA(raw) == row['manifest_sha256'] and child == module_expected(name,
                expected['sha256'], expected['image_sha256'], component['hepta']['compiler_sha256']),
                'body compiled member metadata differs')
        require(get(child['source']) == read(Path(source_root) / expected['source']),
                'body retained member source differs')
        image = get(child['image']); images.append(image)
        require(PIN(image) == dict(bytes=expected['image_bytes'], sha256=expected['image_sha256']),
                'body retained fixed image differs')
        compiled = decode(get(name + '.compile.json'))
        check_compile(compiled, get(child['source']), image, component['hepta']['compiler_sha256'])
    packer = decode(get('packer.json'))
    require(packer == module_expected('packer', component['packer']['sha256'],
            report['packer_image_sha256'], component['hepta']['compiler_sha256'])
            and get('packer.hepta') == read(Path(source_root) / component['packer']['source'])
            and SHA(get('packer.image.bin')) == report['packer_image_sha256'],
            'body actual packer source/image differs')
    compiled = decode(get('packer.compile.json'))
    check_compile(compiled, get('packer.hepta'), get('packer.image.bin'), component['hepta']['compiler_sha256'])
    prefix = get('prefix.bin')
    require(prefix == read(Path(source_root) / component['prefix']['source']), 'body retained prefix differs')
    binary = executable(component, prefix, images)
    require(get('local-text-body.elf') == binary, 'body retained executable differs')
    wire = b'HLTBPX01' + struct.pack('<12Q', *(len(raw) for raw in images)) + b''.join(images)
    require(get('pack.input.bin') == wire and get('pack.output.bin') == binary + b'\xb3' * 4096
            and get('pack.workspace.bin') == b'\xc7' * 4096,
            'body complete HIA packer input/output/workspace differs')
    require(report['packer_return'] == len(binary) and report['source_unchanged'] is True,
            'body actual packer result differs')
    assembly = decode(get('assembly.json'))
    require(len(assembly) == 4 and all(row['exit_code'] == 0 and row['timed_out'] is False
            and row['deadline_seconds'] == 30 for row in assembly), 'body assembly processes differ')
    for row in assembly:
        for label in ('stdout', 'stderr'):
            require(PIN(get(row[label]['path'])) == {k: row[label][k] for k in ('bytes', 'sha256')},
                    'body assembly complete stream differs')
    require(b'There are no relocations' in get(assembly[3]['stdout']['path'])
            and get('fixture.bin') == prefix[176:], 'body actual assembly or relocation proof differs')
    return dict(manifest=PIN(read(path)), executable=PIN(binary), source_inputs=source,
                artifact_sha256={key: row['sha256'] for key, row in artifacts.items()}, scope=SCOPE)


def build_local_text_body(hepta, build_root, *, source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    before = source_evidence(root); c = before['component']
    build_root = Path(build_root).resolve()
    builder = NativeBuild(hepta, build_root)
    require(SHA(builder.bootstrap().read_bytes()) == c['hepta']['compiler_sha256'],
            'body pinned compiler generation differs')
    folder = build_root / 'local-text-body'
    folder.mkdir(exist_ok=False)
    report = dict(schema='hepta.runtime.local-text-body-fixture-build.v1', status='BUILDING',
        source_inputs=before, scope=SCOPE, members=[], actual_member_compiles=0,
        runtime_python_required=False, runtime_libc_required=False)
    manifest = folder / 'manifest.json'
    def save(): manifest.write_bytes(json_bytes(report))
    save()
    try:
        for row in [*c['members'], dict(name='packer', **c['packer'])]:
            name = row['name']
            path = builder.compile('local-text-body-' + name, root / row['source'],
                                   standalone=None, buffer_profile='history.v1')
            child = decode(read(path))
            raw = read(path.parent / child['image'])
            require(child['source_sha256'] == row['sha256']
                    and child['compiler_sha256'] == c['hepta']['compiler_sha256'],
                    'body new native compiler input differs')
            if name != 'packer':
                require(PIN(raw) == dict(bytes=row['image_bytes'], sha256=row['image_sha256']),
                        'body new native compilation differs from qualified image: ' + name)
            normalized = module_expected(name, row['sha256'], SHA(raw), c['hepta']['compiler_sha256'])
            write_new(folder / (name + '.json'), json_bytes(normalized))
            write_new(folder / (name + '.hepta'), read(root / row['source']))
            write_new(folder / (name + '.image.bin'), raw)
            compile_receipt = decode(read(path.parent / 'build.json'))['compile_receipt']
            write_new(folder / (name + '.compile.json'), json_bytes(compile_receipt))
            report['actual_member_compiles'] += 1
            if name == 'packer': report['packer_image_sha256'] = SHA(raw)
            else: report['members'].append(dict(number=row['number'], child=row['child'], name=name,
                manifest=name + '.json', manifest_sha256=SHA(read(folder / (name + '.json')))))
            save()
        commands = [
            ['as', '--64', '-o', str(folder / 'fixture.o'), str(root / c['assembly']['source'])],
            ['ld', '-nostdlib', '-Ttext=0', '-e', '_start', '-o', str(folder / 'fixture-code.elf'), str(folder / 'fixture.o')],
            ['objcopy', '-O', 'binary', '--only-section=.text', str(folder / 'fixture-code.elf'), str(folder / 'fixture.bin')],
            ['readelf', '-r', str(folder / 'fixture-code.elf')],
        ]
        records = []
        for index, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, timeout=30)
            row = dict(command=command, exit_code=result.returncode, deadline_seconds=30, timed_out=False)
            for label, raw in (('stdout', result.stdout), ('stderr', result.stderr)):
                name = f'assembly-{index}.{label}'
                write_new(folder / name, raw); row[label] = dict(path=name, **PIN(raw))
            records.append(row); (folder / 'assembly.json').write_bytes(json_bytes(records))
            require(result.returncode == 0, 'body actual assembly failed')
        prefix = read(root / c['prefix']['source'])
        write_new(folder / 'prefix.bin', prefix)
        require(read(folder / 'fixture.bin') == prefix[176:], 'body actual assembled bytes differ')
        images = [read(folder / (row['name'] + '.image.bin')) for row in c['members']]
        elf = executable(c, prefix, images)
        wire = b'HLTBPX01' + struct.pack('<12Q', *(len(raw) for raw in images)) + b''.join(images)
        with NativeModule(folder / 'packer.json', manifest_sha256=SHA(read(folder / 'packer.json'))) as packer:
            code, out, work = packer.invoke_raw(wire, output_capacity=len(elf) + 4096,
                workspace_capacity=4096, output_fill=0xb3, workspace_fill=0xc7)
        require(code == len(elf) and out == elf + b'\xb3' * 4096 and work == b'\xc7' * 4096,
                'body actual HIA packer complete buffers differ')
        for name, raw in (('pack.input.bin', wire), ('pack.output.bin', out), ('pack.workspace.bin', work)):
            write_new(folder / name, raw)
        write_new(folder / 'local-text-body.elf', elf, 0o500)
        require(source_evidence(root) == before, 'body build source changed')
        builder._recheck()
        report.update(status='PASS', packer_return=code, source_unchanged=True)
        save(); verify_build(manifest, source_root=root)
        return manifest
    except BaseException as error:
        report.update(status='FAIL', error=repr(error)); save(); raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(build_local_text_body(args.hepta, args.build_root, source_root=args.source_root))
