"""Build the fixed HIA canonical-key/shared-state Linux lock service.

The native prefix owns a four-thread pool and serializes access to one private
state arena.  All key and lock-state decisions remain in their HIA images.
Build evidence does not qualify an asynchronous waiter or an MCP handler.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'scripts') not in sys.path:
    sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_file_lock_build as locks
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_atomic_write_build import (
    COMMIT, TREE, COMPILER, DEPENDENCY, COMPILE_FILES, PACK_FILES,
    require, exact, sha, canonical, read, obj, file_record, native_receipt,
)

FROZEN = {
    'native/file_lock_service.hepta': 'cb0e14b587c27617991d69a5d47442b7a5cab66edcbbc1897d37dd10717cc459',
    'native/file_lock_service_packer.hepta': '72784c9efdd8486b5249521977a1e464a148fa26cad88babeb55467480916666',
    'native/file_lock_service_composition.json': '0561c291bbd225fc104e75aa5ca0a9c247efe0fdfdce68d2307a3c8c318a3ab6',
    'native/file_lock_service_layout.json': '845b80953e5fa8e988588f34492e35eb31ebd8b64be202817d10ba7df649b7a9',
    'scripts/hia_native_file_lock_build.py': 'b165233b19619d21289fab64fdd08637e704a1317caf699c43ddbaac0a7b13b7',
}
IMAGES = {
    'controller': '1ea13170fde98aeda075315d48b0610d9113f2acf97a15503c7950bbf75a1ca9',
    'key': locks.IMAGES['key'], 'state': locks.IMAGES['state'],
    'packer': '7b7c0b899bf39cbf9a1e73124297f53315eb02f22036610303d0b2ef8dc0ad5b',
}
KINDS = ('controller', 'key', 'state', 'packer')
PREFIX_SIZE, TABLE = 5904, 5872
PREFIX_SHA = 'bd73792790c1a5f564d58030443ca688b9a9450bc5d2010c3cf3e29b7bde5e8f'
EXECUTABLE_SHA = '8ccbab29589810c1ab41f34532c077fb81a0e1ada6f7272e611b716f8ab315d2'


def filename(kind):
    require(kind in KINDS, 'undefined file-lock service image')
    if kind in ('key', 'state'):
        return locks.filename(kind)
    return 'native/file_lock_service' + ('_packer' if kind == 'packer' else '') + '.hepta'


def source_pins(root=ROOT):
    root = Path(root)
    records = locks.source_pins(root)
    for name, wanted in FROZEN.items():
        records[name] = file_record(root / name)
        exact(records[name]['sha256'], wanted, 'file-lock service source differs: ' + name)
    name = 'scripts/hia_native_file_lock_service_build.py'
    exact(read(root / name), read(__file__), 'loaded file-lock service builder differs')
    exact(sha(read(locks.__file__)), FROZEN['scripts/hia_native_file_lock_build.py'], 'loaded lock builder differs')
    records[name] = file_record(root / name)
    return records


def source_contract(hepta, root=ROOT):
    root = Path(root)
    child = locks.source_contract(hepta, root)
    source_pins(root)
    sys.path.insert(0, str(Path(hepta)))
    from hepta.hia_agent_assembly import assemble_program
    def functions(path):
        return {f['name']: f for f in assemble_program(read(path)).as_dict()['functions']}
    proof = obj(root / 'native/file_lock_service_composition.json')
    exact(proof['source_sha256'], FROZEN[filename('controller')], 'service composition source differs')
    exact(proof['fixed_children'], {
        '1': {'source': locks.filename('key'), 'sha256': locks.FROZEN[locks.filename('key')]},
        '2': {'source': locks.filename('state'), 'sha256': locks.FROZEN[locks.filename('state')]},
    }, 'service fixed children differ')
    actual = functions(root / filename('controller'))
    exact(len(actual), 8, 'service controller function closure differs')
    item = proof['import']
    exact(item['path'], 'native/text_budget.hepta', 'service helper origin differs')
    exact(sha(read(root / item['path'])), item['sha256'], 'service helper source differs')
    old = functions(root / item['path'])
    reverse = {new: before for before, new in item['function_relocation'].items()}
    exact(len(reverse), 4, 'service imported helper count differs')
    exact(set(item['functions']), set(reverse.values()), 'service helper closure differs')
    for before, new in item['function_relocation'].items():
        observed = copy.deepcopy(actual[new]); observed['name'] = before
        for block in observed['blocks']:
            for operation in block['ops']:
                if operation['op'] == 'call':
                    target = operation['attrs']['function']
                    require(target in reverse, 'service helper escapes its complete closure')
                    operation['attrs']['function'] = reverse[target]
        exact(observed, old[before], 'service imported helper body differs')
        exact(sha(canonical(observed)), item['functions'][before], 'service helper proof differs')
    return {'controller_imported_functions': 4, 'child_imported_functions': child['imported_functions'],
        'source_files': source_pins(root)}


def inspect_elf(raw, images):
    require(set(images) == {'controller', 'key', 'state'}, 'service embedded image set differs')
    ordered = [images[kind] for kind in ('controller', 'key', 'state')]
    exact(len(raw), PREFIX_SIZE + sum(map(len, ordered)), 'service ELF extent differs')
    exact(raw[:16], b'\x7fELF\x02\x01\x01' + bytes(9), 'service ELF identity differs')
    exact(struct.unpack_from('<HHIQQQIHHHHHH', raw, 16),
        (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), 'service ELF header differs')
    exact(struct.unpack_from('<IIQQQQQQ', raw, 64),
        (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), 'service RX segment differs')
    exact(struct.unpack_from('<IIQQQQQQ', raw, 120),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16), 'service nonexecutable stack differs')
    exact(struct.unpack_from('<4Q', raw, TABLE),
        (*map(len, ordered), int.from_bytes(b'HFLKSIM1', 'little')), 'service fixed image table differs')
    prefix = bytearray(raw[:PREFIX_SIZE]); prefix[96:112] = bytes(16); prefix[TABLE:TABLE + 24] = bytes(24)
    exact(sha(prefix), PREFIX_SHA, 'service fixed thread/syscall boundary differs')
    at = PREFIX_SIZE
    for kind, image in zip(('controller', 'key', 'state'), ordered):
        exact(sha(image), IMAGES[kind], 'service expected actual leaf image differs')
        exact(raw[at:at + len(image)], image, 'service actual embedded leaf image differs')
        at += len(image)
    exact(sha(raw), EXECUTABLE_SHA, 'service complete executable differs')
    return {'bytes': len(raw), 'sha256': sha(raw), 'prefix_bytes': PREFIX_SIZE, 'prefix_sha256': PREFIX_SHA,
        'table_offset': TABLE, 'image_order': ['controller', 'key', 'state'],
        'image_sha256': {kind: sha(images[kind]) for kind in ('controller', 'key', 'state')},
        'native_threads': 4, 'interpreter': None, 'libc': False, 'dynamic_memory': True}


def inspect_module(folder, kind, root=ROOT, dependency=None):
    if kind in ('key', 'state'):
        return locks.inspect_module(folder, kind, root, dependency)
    folder, root = Path(folder), Path(root)
    metadata = obj(folder / (kind + '.json'))
    source, image = read(root / filename(kind)), read(folder / (kind + '.image.bin'))
    caps = (128 << 20, 128 << 20, 256 << 20) if kind == 'controller' else (8 << 20, 8 << 20, 32 << 20)
    expected = {'schema': 'hepta.runtime.native-module.v1', 'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
        'target': 'linux-x86_64', 'compiler_commit': COMMIT, 'compiler_sha256': COMPILER,
        'source': kind + '.hepta', 'image': kind + '.image.bin', 'source_sha256': sha(source),
        'image_sha256': IMAGES[kind], 'input_capacity': caps[0], 'output_capacity': caps[1],
        'workspace_capacity': caps[2], 'standalone': None, 'qualification': 'development_fixed_point'}
    for key, wanted in expected.items():
        exact(metadata.get(key), wanted, 'service module differs: ' + kind + '/' + key)
    if kind == 'controller':
        exact(metadata.get('buffer_profile'), 'history.v1', 'service direct image profile differs')
    else:
        require('buffer_profile' not in metadata, 'service packer profile differs')
    exact(read(folder / (kind + '.hepta')), source, 'service packaged source differs')
    exact(sha(image), IMAGES[kind], 'service actual flat image differs')
    compiled = folder / (kind + '-build')
    receipt = native_receipt(compiled, 'module', source=source, produced=image, producer=COMPILER)
    exact(receipt.get('produced_bytes'), len(image), 'service compiled size differs')
    exact(receipt.get('produced_sha256'), sha(image), 'service compiled digest differs')
    exact(read(compiled / 'module.image.bin'), image, 'service compiled image differs')
    built = obj(compiled / 'build.json')
    exact(built.get('compile_receipt'), receipt, 'service complete compile receipt differs')
    exact(built.get('whole_runtime_replaced'), False, 'service build cannot qualify the runtime')
    observed = built.get('compiler_dependency')
    exact(sha(canonical(observed)), DEPENDENCY, 'service complete compiler dependency differs')
    if dependency is not None:
        exact(observed, dependency, 'service fresh compiler checkout differs')
    origin = obj(compiled / 'manifest.json')
    exact(dict(origin, source=kind + '.hepta', image=kind + '.image.bin'), metadata, 'service packaged manifest differs')
    return {'source_sha256': sha(source), 'image_sha256': sha(image), 'manifest': file_record(folder / (kind + '.json')),
        'compilation': {name: file_record(compiled / name) for name in COMPILE_FILES}}, image


def metadata_contract(pins):
    return {'schema': 'hepta.runtime.native-file-lock-service.v1', 'compiler_commit': COMMIT,
        'compiler_tree': TREE, 'compiler_sha256': COMPILER, 'target': 'linux-x86_64',
        'transport': 'u64-length-u64-tag-requests-u64-tag-u64-tid-u32-results',
        'fixed_images': ['controller', 'key', 'state'], 'native_threads': 4,
        'dynamic_memory': True, 'canonical_to_state_composed': True, 'shared_state_serialized': True,
        'runtime_python_required': False, 'runtime_libc_required': False, 'registered_mcp_tool': False,
        'production_activated': False, 'whole_runtime_replaced': False,
        'asynchronous_wait_scheduler_closed': False, 'upper_file_io_closed': False, 'source_files': pins}


def inspect_bundle(manifest_path, *, source_root=ROOT, dependency=None):
    path = Path(manifest_path).resolve(strict=True)
    folder, root = path.parent, Path(source_root)
    pins = source_pins(root); metadata = obj(path)
    for key, wanted in metadata_contract(pins).items():
        exact(metadata.get(key), wanted, 'service bundle contract differs: ' + key)
    exact(set(metadata.get('modules', {})), set(KINDS), 'service module set differs')
    images, modules = {}, {}
    for kind in KINDS:
        record, image = inspect_module(folder, kind, root, dependency)
        exact(metadata['modules'][kind], record, 'service bundle module evidence differs')
        images[kind], modules[kind] = image, record
    exact(read(folder / 'layout.json'), read(root / 'native/file_lock_service_layout.json'), 'service layout copy differs')
    raw = read(folder / 'file-lock-service.elf')
    inspection = inspect_elf(raw, {kind: images[kind] for kind in ('controller', 'key', 'state')})
    frame = b'HFLKSPK1' + struct.pack('<3Q', *(len(images[kind]) for kind in ('controller', 'key', 'state')))
    frame += b''.join(images[kind] for kind in ('controller', 'key', 'state'))
    packed = folder / 'pack'
    receipt = native_receipt(packed, 'pack', source=frame, produced=raw, producer=IMAGES['packer'])
    executable = {'file': 'file-lock-service.elf', 'inspection': inspection, 'pack_receipt': receipt,
        'pack_files': {name: file_record(packed / name) for name in PACK_FILES}, 'layout': file_record(folder / 'layout.json')}
    exact(metadata['executable'], executable, 'service actual packed artifact evidence differs')
    exact(source_pins(root), pins, 'service sources changed during inspection')
    return {'schema': 'hepta.runtime.file-lock-service-artifact-evidence.v1', 'status': 'PASS',
        'manifest': file_record(path), 'source_files': pins, 'modules': modules, 'executable': executable,
        'compiler_dependency_sha256': DEPENDENCY, 'actual_semantic_calls': 0}


def build_file_lock_service(hepta, build_root, *, source_root=ROOT):
    root = Path(source_root).resolve(strict=True); build_root = Path(build_root).resolve()
    pins = source_pins(root); build = NativeBuild(hepta, build_root)
    exact(sha(build.bootstrap().read_bytes()), COMPILER, 'service compiler image differs')
    exact(sha(canonical(build.identity)), DEPENDENCY, 'service compiler source closure differs')
    source_contract(hepta, root)
    folder = build_root / 'file-lock-service' / sha(canonical(pins)); manifest = folder / 'manifest.json'
    if manifest.exists():
        inspect_bundle(manifest, source_root=root, dependency=build.identity); build._recheck()
        return manifest
    modules = {}
    for kind in KINDS:
        digest = sha(read(root / filename(kind)))
        name = ('file-lock-' if kind in ('key', 'state') else 'file-lock-service-') + kind + '-' + digest[:16]
        path = build_root / 'modules' / name / 'manifest.json'
        if not path.exists():
            path = build.compile(name, root / filename(kind), standalone=None,
                buffer_profile='standard' if kind == 'packer' else 'history.v1')
        modules[kind] = path
    folder.mkdir(parents=True, mode=0o700)
    for kind, path in modules.items():
        original = obj(path)
        write_new(folder / (kind + '.hepta'), read(root / filename(kind)))
        write_new(folder / (kind + '.image.bin'), read(path.parent / original['image']))
        write_new(folder / (kind + '.json'), json_bytes(dict(original, source=kind + '.hepta', image=kind + '.image.bin')))
        compiled = folder / (kind + '-build'); compiled.mkdir(mode=0o700)
        for name in COMPILE_FILES:
            write_new(compiled / name, read(path.parent / name))
        inspect_module(folder, kind, root, build.identity)
    metadata = dict(metadata_contract(pins), modules={})
    images = {}
    for kind in KINDS:
        metadata['modules'][kind], images[kind] = inspect_module(folder, kind, root, build.identity)
    frame = b'HFLKSPK1' + struct.pack('<3Q', *(len(images[kind]) for kind in ('controller', 'key', 'state')))
    frame += b''.join(images[kind] for kind in ('controller', 'key', 'state'))
    from tools.qualify_hia_selfhost import invoke
    packed = folder / 'pack'; packed.mkdir(mode=0o700)
    receipt, output = invoke(packed, 'pack', folder / 'packer.image.bin', frame)
    count = receipt.get('core_u32')
    require(type(count) is int and 0 < count <= 1 << 20, 'service HIA packer rejected its image set')
    raw = output[:count]
    inspection = inspect_elf(raw, {kind: images[kind] for kind in ('controller', 'key', 'state')})
    native_receipt(packed, 'pack', source=frame, produced=raw, producer=IMAGES['packer'])
    write_new(folder / 'file-lock-service.elf', raw, 0o500)
    write_new(folder / 'layout.json', read(root / 'native/file_lock_service_layout.json'))
    metadata['executable'] = {'file': 'file-lock-service.elf', 'inspection': inspection, 'pack_receipt': receipt,
        'pack_files': {name: file_record(packed / name) for name in PACK_FILES}, 'layout': file_record(folder / 'layout.json')}
    exact(source_pins(root), pins, 'service sources changed during build')
    write_new(manifest, json_bytes(metadata)); inspect_bundle(manifest, source_root=root, dependency=build.identity)
    build._recheck()
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    args = parser.parse_args()
    if args.hepta is None or args.build_root is None:
        parser.error('compiler and build-root paths are required')
    print(json.dumps({'manifest': str(build_file_lock_service(args.hepta, args.build_root))}))
