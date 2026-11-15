"""Build source-bound HIA lock state and canonical-key static Linux components.

These are internal components. Separate ELF fixtures prove their persistent
state and syscall boundaries; they do not establish a concurrent public service.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'scripts') not in sys.path:
    sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_atomic_write_build import (
    COMMIT, TREE, COMPILER, DEPENDENCY, COMPILE_FILES, PACK_FILES,
    require, exact, sha, canonical, read, obj, file_record, native_receipt,
)

FROZEN = {
    'native/file_lock_state.hepta': 'dd6d1e9938767ae6333af5267efbc684e23fd87d3def4e095ac914c80bbbcaa8',
    'native/file_lock_state_composition.json': '720cd7929707e6e7f6837f0999e1b2796db10904c9e3f8dd96fc3e527eb7c318',
    'native/file_lock_state_packer.hepta': '50b3b1dae1b9489500e5c291bb9f85d5788ac6c5d33a0eab8d5d66cc007e9078',
    'native/file_lock_state_layout.json': '741f4f1563da01d09dc73d4b8692210999fc94618b1b260e46a052814b36bcc5',
    'native/file_lock_key.hepta': '99174dd26e97882b65489e9f913a2a22663546dcc783a678c9f571458841ddce',
    'native/file_lock_key_composition.json': '89c567eb1633ec3669c6ddd7036d6d75a376370eb8aa4f6abd716404a9ab81be',
    'native/file_lock_key_packer.hepta': 'd1e18d570dc79cc387ba5ad08e61a0b53e95fa3ec903238aa2ea26c984900f8c',
    'native/file_lock_key_layout.json': '2a063ce82e685912415043fc8c7454d1b8921ddbcd032228690f217c38b06115',
    'native/text_budget.hepta': '89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9',
    'native/atomic_write.hepta': 'bedb27429d970833db4800436511788eaae2bfaa5487b4c751a94f8e7cbe410b',
    'scripts/hia_native_build.py': '7b01d602d50835f2b73a2b7b39761c0cef08a372493985161d59184d52c0dcb2',
    'scripts/hia_native_loader.py': '331b1fdc693df44847723f7171a1338918d1558f1cdc48f558cd29b32f2971e2',
    'scripts/hia_native_atomic_write_build.py': '6f1ee87583efbce022efd37bffd7579604d4d7048d4aaa7cd0e27c16591389d1',
    'src/mcp/fs/text_editing.rs': 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590',
    'src/mcp/fs/remote.rs': 'd87cae1d18cfaf3479cc94e0df8c8c6eefe5d2eec34f62b7ba0f0c4693704d8c',
}
IMAGES = {
    'state': 'c44d7ec46d095f77dcf889181853d87da337cca47b59f2ee0925d1a306d62193',
    'key': '79f1c1241f0a8856ffe99aaf3b66bc37716c75bbb4500b3a5b30dc8b7bdf201c',
    'state-packer': 'ba2b40ad5b287b29f66e5c2e86d9a18959f533a20ccd66295037d1e6a043141e',
    'key-packer': 'a3ea6a88e4fe65195472ccb3afdefc0e75ed92c656f6576605551a85086328ae',
}
PREFIX = {
    'state': (1136, '10ce3d8b2ea2f21ff25d8c9cb4b8016d76c46b413be07123cc0c29f4a03b8c95', b'HFLSPK01'),
    'key': (3488, '064ca413cc5bda471d335457e86057fd8ca651acb68ea9f3628b81f5a4a327b5', b'HFLKPK01'),
}
KINDS = ('state', 'key', 'state-packer', 'key-packer')

def filename(kind):
    require(kind in KINDS, 'unknown lock component')
    return 'native/file_lock_' + kind.replace('-', '_') + '.hepta'

def source_pins(root=ROOT):
    root = Path(root)
    records = {name: file_record(root / name) for name in (*FROZEN, 'scripts/hia_native_file_lock_build.py')}
    for name, value in FROZEN.items():
        exact(records[name]['sha256'], value, 'file-lock source differs: ' + name)
    exact(read(root / 'scripts/hia_native_file_lock_build.py'), read(__file__), 'loaded file-lock builder differs')
    import hia_native_build, hia_native_atomic_write_build
    for module in (hia_native_build, hia_native_atomic_write_build):
        name = 'scripts/' + Path(module.__file__).name
        exact(sha(read(module.__file__)), FROZEN[name], 'loaded file-lock build dependency differs')
    return records

def source_contract(hepta, root=ROOT):
    """Recheck complete, relocated helper bodies, not only their declarations."""
    root = Path(root)
    source_pins(root)
    sys.path.insert(0, str(Path(hepta)))
    from hepta.hia_agent_assembly import assemble_program
    def functions(path):
        return {f['name']: f for f in assemble_program(read(path)).as_dict()['functions']}
    total = 0
    for kind, count in (('state', 18), ('key', 33)):
        proof = obj(root / ('native/file_lock_' + kind + '_composition.json'))
        actual = functions(root / filename(kind))
        exact(len(actual), count, 'file-lock function closure differs')
        exact(proof['source_sha256'], FROZEN[filename(kind)], 'file-lock source proof differs')
        for item in proof['imports']:
            exact(sha(read(root / item['path'])), item['sha256'], 'file-lock imported source differs')
            old = functions(root / item['path'])
            reverse = {new: before for before, new in item['function_relocation'].items()}
            exact(set(item['functions']), set(reverse.values()), 'file-lock imported function set differs')
            for before, new in item['function_relocation'].items():
                observed = copy.deepcopy(actual[new])
                observed['name'] = before
                for block in observed['blocks']:
                    for operation in block['ops']:
                        if operation['op'] == 'call':
                            target = operation['attrs']['function']
                            require(target in reverse, 'file-lock helper calls outside its complete closure')
                            operation['attrs']['function'] = reverse[target]
                exact(observed, old[before], 'file-lock imported helper body differs')
                exact(sha(canonical(observed)), item['functions'][before], 'file-lock helper proof differs')
                total += 1
    exact(total, 13, 'file-lock helper count differs')
    return {'imported_functions': total, 'source_files': source_pins(root)}

def inspect_elf(raw, image, kind):
    size, digest, _ = PREFIX[kind]
    exact(len(raw), size + len(image), 'file-lock ELF extent differs')
    exact(raw[:16], b'\x7fELF\x02\x01\x01' + bytes(9), 'file-lock ELF identity differs')
    exact(struct.unpack_from('<HHIQQQIHHHHHH', raw, 16),
        (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), 'file-lock ELF header differs')
    exact(struct.unpack_from('<IIQQQQQQ', raw, 64),
        (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), 'file-lock RX segment differs')
    exact(struct.unpack_from('<IIQQQQQQ', raw, 120),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16), 'file-lock nonexecutable stack differs')
    prefix = bytearray(raw[:size])
    prefix[96:112] = bytes(16)
    exact(sha(prefix), digest, 'file-lock fixed native boundary differs')
    exact(raw[size:], image, 'file-lock embedded HIA image differs')
    return {'bytes': len(raw), 'sha256': sha(raw), 'prefix_bytes': size, 'prefix_sha256': digest,
        'embedded_image_sha256': sha(image), 'interpreter': None, 'libc': False, 'dynamic_memory': True}

def inspect_module(folder, kind, root=ROOT, dependency=None):
    folder, root = Path(folder), Path(root)
    metadata = obj(folder / (kind + '.json'))
    source, image = read(root / filename(kind)), read(folder / (kind + '.image.bin'))
    caps = (128 << 20, 128 << 20, 256 << 20) if kind in ('state', 'key') else (8 << 20, 8 << 20, 32 << 20)
    expected = {'schema': 'hepta.runtime.native-module.v1', 'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
        'target': 'linux-x86_64', 'compiler_commit': COMMIT, 'compiler_sha256': COMPILER,
        'source': kind + '.hepta', 'image': kind + '.image.bin', 'source_sha256': sha(source),
        'image_sha256': IMAGES[kind], 'input_capacity': caps[0], 'output_capacity': caps[1],
        'workspace_capacity': caps[2], 'standalone': None, 'qualification': 'development_fixed_point'}
    for key, wanted in expected.items():
        exact(metadata.get(key), wanted, 'file-lock module differs: ' + kind + '/' + key)
    if kind in ('state', 'key'):
        exact(metadata.get('buffer_profile'), 'history.v1', 'file-lock direct image profile differs')
    else:
        require('buffer_profile' not in metadata, 'file-lock packer profile differs')
    exact(read(folder / (kind + '.hepta')), source, 'file-lock packaged source differs')
    exact(sha(image), IMAGES[kind], 'file-lock actual flat image differs')
    compiled = folder / (kind + '-build')
    receipt = native_receipt(compiled, 'module', source=source, produced=image, producer=COMPILER)
    exact(receipt.get('produced_bytes'), len(image), 'file-lock compiled size differs')
    exact(receipt.get('produced_sha256'), sha(image), 'file-lock compiled digest differs')
    exact(read(compiled / 'module.image.bin'), image, 'file-lock compiled image differs')
    built = obj(compiled / 'build.json')
    exact(built.get('compile_receipt'), receipt, 'file-lock complete compile receipt differs')
    exact(built.get('whole_runtime_replaced'), False, 'file-lock compilation cannot qualify the runtime')
    observed = built.get('compiler_dependency')
    exact(sha(canonical(observed)), DEPENDENCY, 'file-lock complete compiler dependency differs')
    if dependency is not None:
        exact(observed, dependency, 'file-lock fresh compiler checkout differs')
    origin = obj(compiled / 'manifest.json')
    exact(dict(origin, source=kind + '.hepta', image=kind + '.image.bin'), metadata, 'file-lock packaged manifest differs')
    return {'source_sha256': sha(source), 'image_sha256': sha(image), 'manifest': file_record(folder / (kind + '.json')),
        'compilation': {name: file_record(compiled / name) for name in COMPILE_FILES}}, image

def inspect_bundle(manifest_path, *, source_root=ROOT, dependency=None):
    path = Path(manifest_path).resolve(strict=True)
    folder, root = path.parent, Path(source_root)
    pins = source_pins(root)
    metadata = obj(path)
    expected = {'schema': 'hepta.runtime.native-file-locks.v1', 'compiler_commit': COMMIT,
        'compiler_tree': TREE, 'compiler_sha256': COMPILER, 'target': 'linux-x86_64',
        'transport': 'u64-length-binary-requests-u32-results', 'dynamic_memory': True,
        'runtime_python_required': False, 'runtime_libc_required': False, 'registered_mcp_tool': False,
        'production_activated': False, 'whole_runtime_replaced': False,
        'concurrent_shared_owner_closed': False, 'canonical_to_state_composition_closed': False,
        'source_files': pins}
    for key, wanted in expected.items():
        exact(metadata.get(key), wanted, 'file-lock bundle contract differs: ' + key)
    exact(set(metadata.get('modules', {})), set(KINDS), 'file-lock module set differs')
    exact(set(metadata.get('executables', {})), {'state', 'key'}, 'file-lock executable set differs')
    images, evidence = {}, {}
    for kind in KINDS:
        record, image = inspect_module(folder, kind, root, dependency)
        exact(metadata['modules'][kind], record, 'file-lock bundle module evidence differs')
        images[kind], evidence[kind] = image, record
    executables = {}
    for kind in ('state', 'key'):
        layout = 'native/file_lock_' + kind + '_layout.json'
        exact(read(folder / (kind + '-layout.json')), read(root / layout), 'file-lock layout copy differs')
        raw = read(folder / ('file-lock-' + kind + '.elf'))
        inspection = inspect_elf(raw, images[kind], kind)
        frame = PREFIX[kind][2] + struct.pack('<Q', len(images[kind])) + images[kind]
        packed = folder / (kind + '-pack')
        receipt = native_receipt(packed, 'pack', source=frame, produced=raw, producer=IMAGES[kind + '-packer'])
        record = {'file': 'file-lock-' + kind + '.elf', 'inspection': inspection, 'pack_receipt': receipt,
            'pack_files': {name: file_record(packed / name) for name in PACK_FILES},
            'layout': file_record(folder / (kind + '-layout.json'))}
        exact(metadata['executables'][kind], record, 'file-lock actual packed artifact evidence differs')
        executables[kind] = record
    exact(source_pins(root), pins, 'file-lock sources changed during inspection')
    return {'schema': 'hepta.runtime.file-lock-artifact-evidence.v1', 'status': 'PASS',
        'manifest': file_record(path), 'source_files': pins, 'modules': evidence, 'executables': executables,
        'compiler_dependency_sha256': DEPENDENCY, 'actual_semantic_calls': 0}

def build_file_locks(hepta, build_root, *, source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    build_root = Path(build_root).resolve()
    pins = source_pins(root)
    build = NativeBuild(hepta, build_root)
    exact(sha(build.bootstrap().read_bytes()), COMPILER, 'file-lock compiler image differs')
    exact(sha(canonical(build.identity)), DEPENDENCY, 'file-lock compiler source closure differs')
    source_contract(hepta, root)
    folder = build_root / 'file-locks' / sha(canonical(pins))
    manifest = folder / 'manifest.json'
    if manifest.exists():
        inspect_bundle(manifest, source_root=root, dependency=build.identity)
        build._recheck()
        return manifest
    modules = {}
    for kind in KINDS:
        name = 'file-lock-' + kind + '-' + FROZEN[filename(kind)][:16]
        path = build_root / 'modules' / name / 'manifest.json'
        if not path.exists():
            path = build.compile(name, root / filename(kind), standalone=None,
                buffer_profile='history.v1' if kind in ('state', 'key') else 'standard')
        modules[kind] = path
    folder.mkdir(parents=True, mode=0o700)
    for kind, path in modules.items():
        original = obj(path)
        write_new(folder / (kind + '.hepta'), read(root / filename(kind)))
        write_new(folder / (kind + '.image.bin'), read(path.parent / original['image']))
        write_new(folder / (kind + '.json'), json_bytes(dict(original, source=kind + '.hepta', image=kind + '.image.bin')))
        compiled = folder / (kind + '-build')
        compiled.mkdir(mode=0o700)
        for name in COMPILE_FILES:
            write_new(compiled / name, read(path.parent / name))
        inspect_module(folder, kind, root, build.identity)
    metadata = {'schema': 'hepta.runtime.native-file-locks.v1', 'compiler_commit': COMMIT,
        'compiler_tree': TREE, 'compiler_sha256': COMPILER, 'target': 'linux-x86_64',
        'transport': 'u64-length-binary-requests-u32-results', 'dynamic_memory': True,
        'runtime_python_required': False, 'runtime_libc_required': False, 'registered_mcp_tool': False,
        'production_activated': False, 'whole_runtime_replaced': False,
        'concurrent_shared_owner_closed': False, 'canonical_to_state_composition_closed': False,
        'source_files': pins, 'modules': {}, 'executables': {}}
    for kind in KINDS:
        metadata['modules'][kind] = inspect_module(folder, kind, root, build.identity)[0]
    from tools.qualify_hia_selfhost import invoke
    for kind in ('state', 'key'):
        image = read(folder / (kind + '.image.bin'))
        frame = PREFIX[kind][2] + struct.pack('<Q', len(image)) + image
        packed = folder / (kind + '-pack')
        packed.mkdir(mode=0o700)
        receipt, output = invoke(packed, 'pack', folder / (kind + '-packer.image.bin'), frame)
        count = receipt.get('core_u32')
        require(type(count) is int and 0 < count <= 1 << 20, 'file-lock native packer rejected the image')
        elf = output[:count]
        inspection = inspect_elf(elf, image, kind)
        native_receipt(packed, 'pack', source=frame, produced=elf, producer=IMAGES[kind + '-packer'])
        write_new(folder / ('file-lock-' + kind + '.elf'), elf, 0o500)
        write_new(folder / (kind + '-layout.json'), read(root / ('native/file_lock_' + kind + '_layout.json')))
        metadata['executables'][kind] = {'file': 'file-lock-' + kind + '.elf', 'inspection': inspection,
            'pack_receipt': receipt, 'pack_files': {name: file_record(packed / name) for name in PACK_FILES},
            'layout': file_record(folder / (kind + '-layout.json'))}
    exact(source_pins(root), pins, 'file-lock sources changed during build')
    write_new(manifest, json_bytes(metadata))
    inspect_bundle(manifest, source_root=root, dependency=build.identity)
    build._recheck()
    return manifest

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    args = parser.parse_args()
    if args.hepta is None or args.build_root is None:
        parser.error('compiler and build-root paths are required')
    print(json.dumps({'manifest': str(build_file_locks(args.hepta, args.build_root))}))
