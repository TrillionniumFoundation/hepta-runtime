"""Build and inspect the fixed eight-image Local save-history/undo chain.

Every semantic owner is compiled by the pinned HIA compiler. A separate HIA
packer produces the complete static executable; this Python driver verifies
sources, native receipts and bytes and never implements a filesystem request.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'scripts') not in sys.path: sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_build as common
import hia_native_atomic_write_build as atomic
from hia_native_atomic_write_build import (
    COMMIT, TREE, COMPILER, DEPENDENCY, COMPILE_FILES, PACK_FILES,
    require, exact, sha, canonical, read, obj, file_record, native_receipt,
)

PROFILE = '741254c46c225ed9b10d8879c03a95d6f12115da974f06076a7a2e8f0e4616bf'
ORDER = ('write_chain', 'file_lock_service', 'file_lock_key', 'history',
         'atomic_write_shared', 'view_cache', 'local_read', 'file_lock_state')
KINDS = (*ORDER, 'packer')
PREFIX_BYTES, TABLE, ELF_BYTES = 14800, 14720, 1453462
ELF_SHA = 'a0b4148ec247039d357a2fd909c801eb34659a99372aeea2b0f4248ef8e0bbc5'
PREFIX_SHA = '90328b00cd657ef15ea3d174616e6bd62d6790f8a7097fc8fb4692d9e5f181ab'
PACKER_IMAGE = 'f2d3e517a0cb00085c2d2043d5deae83c0947a991b6a9275c044ee91427df579'
FRAME_SHA = 'b92f7a6b05ceda92c06e08f8c167e943f6b6f627bfeb11c896653a6a6bd92244'
CAPACITIES = (512 << 20, 1024 << 20, 1152 << 20)
CHILD = 'scripts/hia_native_write_chain_pack_child.py'
DRIVER = 'scripts/hia_native_write_chain_build.py'
LIMITS = dict(cpu_seconds=10, address_bytes=256 << 20, core_dumpable=False,
    stack_bytes=8 << 20, file_bytes=16 << 20, open_files=32,
    input_capacity=8 << 20, output_capacity=ELF_BYTES + 64, workspace_bytes=4096)


def filename(kind):
    require(kind in KINDS, 'undefined write-chain module')
    return 'native/' + ('write_chain_packer' if kind == 'packer' else kind) + '.hepta'


def source_pins(root=ROOT):
    root = Path(root).resolve(strict=True)
    exact(sha(read(root / 'native/write_chain_profile.json')), PROFILE, 'write-chain profile differs')
    profile = obj(root / 'native/write_chain_profile.json')
    require(type(profile.get('source_files')) is dict and len(profile['source_files']) == 32,
            'write-chain complete source closure differs')
    pins = {}
    for name, wanted in profile['source_files'].items():
        require(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts,
                'write-chain source path escapes the repository')
        pins[name] = file_record(root / name)
        exact(pins[name], wanted, 'write-chain frozen source differs: ' + name)
    exact(read(root / DRIVER), read(__file__), 'loaded write-chain builder differs')
    exact(read(root / 'scripts/hia_native_build.py'), read(common.__file__), 'loaded common builder differs')
    exact(read(root / 'scripts/hia_native_atomic_write_build.py'), read(atomic.__file__), 'loaded receipt inspector differs')
    pins[DRIVER] = file_record(root / DRIVER)
    pins['native/write_chain_profile.json'] = file_record(root / 'native/write_chain_profile.json')
    exact(profile['compiler_commit'], COMMIT, 'write-chain compiler commit differs')
    exact(profile['compiler_tree'], TREE, 'write-chain compiler tree differs')
    exact(profile['compiler_sha256'], COMPILER, 'write-chain compiler image differs')
    exact([row['kind'] for row in profile['images']], list(ORDER), 'write-chain fixed image order differs')
    exact([row['id'] for row in profile['images']], list(range(8)), 'write-chain fixed image IDs differ')
    return pins


def source_contract(hepta, root=ROOT):
    root, hepta = Path(root).resolve(strict=True), Path(hepta).resolve(strict=True)
    pins = source_pins(root)
    sys.path.insert(0, str(hepta))
    import hepta.hia_agent_assembly as assembly
    exact(Path(assembly.__file__).resolve(), hepta / 'hepta/hia_agent_assembly.py', 'loaded source inspector differs')
    cache = {}
    def functions(name):
        if name not in cache:
            cache[name] = {f['name']: f for f in assembly.assemble_program(read(root / name)).as_dict()['functions']}
        return cache[name]
    imported = 0
    for kind in (*ORDER, 'atomic_write'):
        path = 'native/' + kind + '_composition.json'
        proof = obj(root / path)
        actual = functions('native/' + kind + '.hepta')
        if 'source_sha256' in proof:
            exact(proof['source_sha256'], pins['native/' + kind + '.hepta']['sha256'], 'write-chain composed source differs')
        imports = proof.get('imports', [proof['import']] if 'import' in proof else [])
        for item in imports:
            exact(pins[item['path']]['sha256'], item['sha256'], 'write-chain imported source differs')
            old = functions(item['path'])
            reverse = {new: before for before, new in item['function_relocation'].items()}
            exact(len(reverse), len(item['function_relocation']), 'write-chain helper relocation collides')
            exact(set(item['functions']), set(reverse.values()), 'write-chain helper digest closure differs')
            for before, new in item['function_relocation'].items():
                observed = copy.deepcopy(actual[new]); observed['name'] = before
                for block in observed['blocks']:
                    for operation in block['ops']:
                        if operation['op'] == 'call':
                            target = operation['attrs']['function']
                            require(target in reverse, 'write-chain imported function escapes its closure')
                            operation['attrs']['function'] = reverse[target]
                exact(observed, old[before], 'write-chain complete imported body differs')
                exact(sha(canonical(observed)), item['functions'][before], 'write-chain imported body proof differs')
                imported += 1
    proof = obj(root / 'native/write_chain_composition.json')
    exact(proof['fixed_children'], {str(i): filename(name) for i, name in enumerate(ORDER) if i},
          'write-chain controller child identity differs')
    for name, digest in proof['original_source_sha256'].items():
        exact(pins[name]['sha256'], digest, 'write-chain original source differs')
    exact(source_pins(root), pins, 'write-chain sources changed while checking imports')
    return dict(imported_functions=imported, source_files=pins)


def expected_image(kind, root=ROOT):
    if kind == 'packer': return PACKER_IMAGE
    profile = obj(Path(root) / 'native/write_chain_profile.json')
    return profile['images'][ORDER.index(kind)]['image_sha256']


def inspect_module(folder, kind, root=ROOT, dependency=None):
    folder, root = Path(folder), Path(root)
    metadata = obj(folder / (kind + '.json'))
    source = read(root / filename(kind)); image = read(folder / (kind + '.image.bin'))
    caps = (8 << 20, 8 << 20, 32 << 20) if kind == 'packer' else CAPACITIES
    expected = dict(schema='hepta.runtime.native-module.v1', abi='hepta.runtime.borrowed-bytes.linux-x86_64.v1',
        target='linux-x86_64', compiler_commit=COMMIT, compiler_sha256=COMPILER,
        source=kind + '.hepta', image=kind + '.image.bin', source_sha256=sha(source),
        image_sha256=expected_image(kind, root), input_capacity=caps[0], output_capacity=caps[1],
        workspace_capacity=caps[2], standalone=None, qualification='development_fixed_point')
    for key, wanted in expected.items(): exact(metadata.get(key), wanted, 'write-chain module differs: ' + kind + '/' + key)
    if kind == 'packer': require('buffer_profile' not in metadata, 'write-chain packer profile differs')
    else: exact(metadata.get('buffer_profile'), 'batch-plan.v1', 'write-chain borrowed-buffer profile differs')
    exact(read(folder / (kind + '.hepta')), source, 'write-chain packaged source differs')
    exact(sha(image), expected['image_sha256'], 'write-chain actual flat image differs')
    compiled = folder / (kind + '-build')
    receipt = native_receipt(compiled, 'module', source=source, produced=image, producer=COMPILER)
    exact(receipt.get('produced_bytes'), len(image), 'write-chain compiler result size differs')
    exact(receipt.get('produced_sha256'), sha(image), 'write-chain compiler result digest differs')
    exact(read(compiled / 'module.image.bin'), image, 'write-chain retained compiler image differs')
    built = obj(compiled / 'build.json')
    exact(built.get('compile_receipt'), receipt, 'write-chain complete compiler receipt differs')
    exact(built.get('whole_runtime_replaced'), False, 'write-chain compiler receipt overclaims scope')
    observed = built.get('compiler_dependency')
    exact(sha(canonical(observed)), DEPENDENCY, 'write-chain complete compiler source closure differs')
    exact(receipt.get('runner_sha256'), observed['files']['tools/hia_selfhost_child.py'], 'write-chain native compiler observer differs')
    exact(receipt.get('limits'), dict(address_bytes=256 << 20, core_dumpable=False, cpu_seconds=10,
        output_capacity=1 << 20, stack_bytes=8 << 20, workspace_bytes=1 << 20), 'write-chain compiler limits differ')
    if dependency is not None: exact(observed, dependency, 'write-chain compiler checkout differs')
    origin = obj(compiled / 'manifest.json')
    exact(dict(origin, source=kind + '.hepta', image=kind + '.image.bin'), metadata, 'write-chain packaged manifest differs')
    return dict(source_sha256=sha(source), image_sha256=sha(image), manifest=file_record(folder / (kind + '.json')),
        compilation={name: file_record(compiled / name) for name in COMPILE_FILES}), image


def inspect_elf(raw, images, root=ROOT):
    exact(set(images), set(ORDER), 'write-chain actual embedded image set differs')
    ordered = [images[name] for name in ORDER]
    exact(len(raw), ELF_BYTES, 'write-chain executable extent differs')
    exact(len(raw), PREFIX_BYTES + sum(map(len, ordered)), 'write-chain image lengths differ')
    exact(raw[:16], b'\x7fELF\x02\x01\x01' + bytes(9), 'write-chain ELF identity differs')
    exact(struct.unpack_from('<HHIQQQIHHHHHH', raw, 16),
        (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0), 'write-chain ELF header differs')
    exact(struct.unpack_from('<IIQQQQQQ', raw, 64),
        (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096), 'write-chain RX segment differs')
    exact(struct.unpack_from('<IIQQQQQQ', raw, 120),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16), 'write-chain nonexecutable stack differs')
    exact(struct.unpack_from('<9Q', raw, TABLE),
        (*map(len, ordered), int.from_bytes(b'HFWCHN01', 'little')), 'write-chain fixed image table differs')
    prefix = bytearray(raw[:PREFIX_BYTES]); prefix[96:112] = bytes(16); prefix[TABLE:TABLE + 64] = bytes(64)
    exact(sha(prefix), PREFIX_SHA, 'write-chain fixed syscall/thread boundary differs')
    at = PREFIX_BYTES
    for name, image in zip(ORDER, ordered):
        exact(sha(image), expected_image(name, root), 'write-chain expected leaf image differs')
        exact(raw[at:at + len(image)], image, 'write-chain actual embedded image differs')
        at += len(image)
    exact(sha(raw), ELF_SHA, 'write-chain complete executable differs')
    return dict(bytes=len(raw), sha256=sha(raw), prefix_bytes=PREFIX_BYTES, prefix_sha256=PREFIX_SHA,
        table_offset=TABLE, image_order=list(ORDER), image_sha256={name: sha(images[name]) for name in ORDER},
        native_threads=4, interpreter=None, libc=False, dynamic_memory=True)


def pack_frame(images):
    raw = b'HFWCPK01' + struct.pack('<8Q', *(len(images[name]) for name in ORDER))
    raw += b''.join(images[name] for name in ORDER)
    exact(len(raw), 1438734, 'write-chain complete pack input size differs')
    exact(sha(raw), FRAME_SHA, 'write-chain complete pack input differs')
    return raw


def inspect_pack(folder, frame, executable, root=ROOT):
    folder, root = Path(folder), Path(root)
    report = obj(folder / 'pack.receipt.json'); stdout = obj(folder / 'pack.stdout.log')
    request = obj(folder / 'pack.request.json'); output = read(folder / 'pack.output.bin')
    exact(read(folder / 'pack.input.bin'), frame, 'write-chain actual pack input differs')
    exact(read(folder / 'pack.stderr.log'), b'', 'write-chain pack observer emitted stderr')
    exact(output, executable + b'\xa5' * 64, 'write-chain actual pack output or untouched tail differs')
    fields = {'status', 'result_u64', 'abi_status', 'return_encoding', 'core_u32', 'source_sha256', 'image_sha256',
        'output_sha256', 'source_unchanged', 'output_unchanged', 'workspace_sha256', 'native_elapsed_ns',
        'forbidden_compiler_modules_loaded', 'loader_operations', 'manifest_sha256', 'loader_sha256',
        'borrowed_buffer_canaries_unchanged', 'native_profile', 'limits'}
    exact(set(stdout), fields, 'write-chain complete actual pack stdout differs')
    expected = dict(status='returned', result_u64=ELF_BYTES, abi_status=0, return_encoding='zero-extended-u32',
        core_u32=ELF_BYTES, source_sha256=sha(frame), image_sha256=PACKER_IMAGE, output_sha256=sha(output),
        source_unchanged=True, output_unchanged=False, forbidden_compiler_modules_loaded=[],
        loader_operations='copy; sealed RX native runtime module; fixed ABI call',
        manifest_sha256=sha(read(folder / 'packer.json')), loader_sha256=sha(read(root / 'scripts/hia_native_loader.py')),
        borrowed_buffer_canaries_unchanged=True, native_profile='standard', limits=LIMITS,
        workspace_sha256=sha(bytes(4096)))
    for key, wanted in expected.items(): exact(stdout.get(key), wanted, 'write-chain actual pack stdout field differs: ' + key)
    require(type(stdout['native_elapsed_ns']) is int and stdout['native_elapsed_ns'] >= 0, 'write-chain pack native timing differs')
    for key, value in stdout.items(): exact(report.get(key), value, 'write-chain pack receipt differs from actual stdout')
    exact(set(report), fields | {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
        'runner_sha256', 'wall_elapsed_ns', 'completed_process'}, 'write-chain pack receipt field set differs')
    for key, wanted in dict(case='pack', input_sha256=sha(frame), input_bytes=len(frame), artifact_sha256=PACKER_IMAGE,
            format='flat-x86-64', runner_sha256=sha(read(root / CHILD))).items():
        exact(report.get(key), wanted, 'write-chain completed pack receipt differs')
    process = report['completed_process']
    exact(set(process), {'pid', 'exit_code', 'reaped', 'timed_out', 'timeout_seconds'}, 'write-chain pack process shape differs')
    require(type(process['pid']) is int and process['pid'] > 0, 'write-chain pack process identity differs')
    for key, wanted in dict(exit_code=0, reaped=True, timed_out=False, timeout_seconds=20).items():
        exact(process[key], wanted, 'write-chain native pack did not complete')
    require(type(report['wall_elapsed_ns']) is int and report['wall_elapsed_ns'] >= stdout['native_elapsed_ns'], 'write-chain pack wall timing differs')
    exact(set(request), {'format', 'manifest', 'manifest_sha256', 'image_sha256', 'source', 'source_sha256',
        'capacity', 'workspace_size', 'output', 'loader_sha256'}, 'write-chain pack request shape differs')
    for key, wanted in dict(format='flat-x86-64', manifest_sha256=expected['manifest_sha256'], image_sha256=PACKER_IMAGE,
            source_sha256=sha(frame), capacity=ELF_BYTES + 64, workspace_size=4096, loader_sha256=expected['loader_sha256']).items():
        exact(request[key], wanted, 'write-chain pack actual request differs')
    for key, name in [('manifest', 'packer.json'), ('source', 'pack.input.bin'), ('output', 'pack.output.bin')]:
        require(type(request[key]) is str and Path(request[key]).is_absolute() and Path(request[key]).name == name,
                'write-chain pack request path differs')
    return dict(receipt=report, files={name: file_record(folder / name) for name in PACK_FILES})


def runtime_pack(folder, frame, root):
    child = root / CHILD
    request = dict(format='flat-x86-64', manifest=str(folder / 'packer.json'),
        manifest_sha256=sha(read(folder / 'packer.json')), image_sha256=PACKER_IMAGE,
        source=str(folder / 'pack.input.bin'), source_sha256=sha(frame), capacity=ELF_BYTES + 64,
        workspace_size=4096, output=str(folder / 'pack.output.bin'), loader_sha256=sha(read(root / 'scripts/hia_native_loader.py')))
    common.write_new(folder / 'pack.input.bin', frame)
    common.write_new(folder / 'pack.request.json', common.json_bytes(request))
    started = time.monotonic_ns()
    process = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(child), str(folder / 'pack.request.json')],
        cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try: stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        timed_out = True; process.kill(); stdout, stderr = process.communicate()
    common.write_new(folder / 'pack.stdout.log', stdout); common.write_new(folder / 'pack.stderr.log', stderr)
    report = (dict(status='timeout') if timed_out else dict(status='child_failed') if process.returncode else
              json.loads(stdout, object_pairs_hook=atomic.pairs))
    report.update(case='pack', input_sha256=sha(frame), input_bytes=len(frame), artifact_sha256=PACKER_IMAGE,
        format='flat-x86-64', runner_sha256=sha(read(child)), wall_elapsed_ns=time.monotonic_ns() - started,
        completed_process=dict(pid=process.pid, exit_code=process.returncode, reaped=True,
            timed_out=timed_out, timeout_seconds=20))
    common.write_new(folder / 'pack.receipt.json', common.json_bytes(report))
    require(not timed_out and process.returncode == 0, 'write-chain actual HIA packing failed')
    return read(folder / 'pack.output.bin')[:ELF_BYTES]


def metadata_contract(pins):
    return dict(schema='hepta.runtime.native-write-chain.v1', compiler_commit=COMMIT, compiler_tree=TREE,
        compiler_sha256=COMPILER, target='linux-x86_64', fixed_images=list(ORDER), native_threads=4,
        transport='u64-length-u64-tag-requests-u64-tag-u64-tid-u32-results', trusted_maximum_in_flight=4,
        shared_state_serialized=True, history_shared=True, session_view_cache_shared=True,
        statx_availability_shared=True, cancellation_transport=True, interpreter=None,
        runtime_python_required=False, runtime_libc_required=False, registered_mcp_tool=False,
        production_activated=False, whole_runtime_replaced=False, remote_sftp_closed=False,
        new_edit_create_delete_callers_closed=False, source_files=pins)


def inspect_bundle(manifest_path, *, source_root=ROOT, dependency=None):
    path = Path(manifest_path).resolve(strict=True)
    folder, root = path.parent, Path(source_root).resolve(strict=True)
    pins = source_pins(root); metadata = obj(path)
    exact(set(metadata), set(metadata_contract(pins)) | {'modules', 'executable', 'registry', 'layout'},
          'write-chain complete bundle shape differs')
    for key, wanted in metadata_contract(pins).items(): exact(metadata.get(key), wanted, 'write-chain bundle contract differs: ' + key)
    exact(set(metadata['modules']), set(KINDS), 'write-chain complete module set differs')
    images, modules, registry = {}, {}, {}
    for kind in KINDS:
        record, image = inspect_module(folder, kind, root, dependency)
        exact(metadata['modules'][kind], record, 'write-chain bundle compilation evidence differs')
        images[kind], modules[kind] = image, record
        if kind != 'packer': registry[kind] = dict(manifest=kind + '.json', source_sha256=record['source_sha256'], image_sha256=record['image_sha256'])
    exact(obj(folder / 'registry.json'), registry, 'write-chain relative image registry differs')
    exact(metadata['registry'], file_record(folder / 'registry.json'), 'write-chain retained registry differs')
    exact(read(folder / 'layout.json'), read(root / 'native/write_chain_native_layout.json'), 'write-chain retained boundary layout differs')
    exact(metadata['layout'], file_record(folder / 'layout.json'), 'write-chain layout evidence differs')
    raw = read(folder / 'write-chain.elf')
    inspection = inspect_elf(raw, {name: images[name] for name in ORDER}, root)
    packed = inspect_pack(folder, pack_frame(images), raw, root)
    executable = dict(file='write-chain.elf', inspection=inspection, pack=packed)
    exact(metadata['executable'], executable, 'write-chain complete native packing evidence differs')
    exact(source_pins(root), pins, 'write-chain sources changed during inspection')
    return dict(schema='hepta.runtime.write-chain-artifact-evidence.v1', status='PASS', manifest=file_record(path),
        source_files=pins, modules=modules, executable=executable, compiler_dependency_sha256=DEPENDENCY,
        actual_semantic_calls=0)


def build_write_chain(hepta, build_root, *, source_root=ROOT):
    root, build_root = Path(source_root).resolve(strict=True), Path(build_root).resolve()
    pins = source_pins(root); build = common.NativeBuild(hepta, build_root)
    exact(sha(build.bootstrap().read_bytes()), COMPILER, 'write-chain compiler fixed point differs')
    exact(sha(canonical(build.identity)), DEPENDENCY, 'write-chain compiler complete dependency differs')
    source_contract(hepta, root)
    folder = build_root / 'write-chain' / sha(canonical(pins)); manifest = folder / 'manifest.json'
    if manifest.exists():
        inspect_bundle(manifest, source_root=root, dependency=build.identity); build._recheck(); return manifest
    compiled = {}
    for kind in KINDS:
        name = 'write-chain-' + kind.replace('_', '-') + '-' + sha(read(root / filename(kind)))[:16]
        path = build_root / 'modules' / name / 'manifest.json'
        if not path.exists():
            path = build.compile(name, root / filename(kind), standalone=None,
                buffer_profile='standard' if kind == 'packer' else 'batch-plan.v1')
        compiled[kind] = path
    folder.mkdir(parents=True, mode=0o700)
    for kind, path in compiled.items():
        origin = obj(path)
        common.write_new(folder / (kind + '.hepta'), read(root / filename(kind)))
        common.write_new(folder / (kind + '.image.bin'), read(path.parent / origin['image']))
        common.write_new(folder / (kind + '.json'), common.json_bytes(dict(origin, source=kind + '.hepta', image=kind + '.image.bin')))
        directory = folder / (kind + '-build'); directory.mkdir(mode=0o700)
        for name in COMPILE_FILES: common.write_new(directory / name, read(path.parent / name))
        inspect_module(folder, kind, root, build.identity)
    metadata = dict(metadata_contract(pins), modules={})
    images, registry = {}, {}
    for kind in KINDS:
        metadata['modules'][kind], images[kind] = inspect_module(folder, kind, root, build.identity)
        if kind != 'packer': registry[kind] = dict(manifest=kind + '.json',
            source_sha256=metadata['modules'][kind]['source_sha256'], image_sha256=sha(images[kind]))
    raw = runtime_pack(folder, pack_frame(images), root)
    inspection = inspect_elf(raw, {name: images[name] for name in ORDER}, root)
    packed = inspect_pack(folder, pack_frame(images), raw, root)
    common.write_new(folder / 'write-chain.elf', raw, 0o500)
    common.write_new(folder / 'registry.json', common.json_bytes(registry))
    common.write_new(folder / 'layout.json', read(root / 'native/write_chain_native_layout.json'))
    metadata.update(executable=dict(file='write-chain.elf', inspection=inspection, pack=packed),
        registry=file_record(folder / 'registry.json'), layout=file_record(folder / 'layout.json'))
    exact(source_pins(root), pins, 'write-chain source changed during build')
    common.write_new(manifest, common.json_bytes(metadata))
    inspect_bundle(manifest, source_root=root, dependency=build.identity); build._recheck()
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root', type=Path, default=os.environ.get('HIA_BUILD_ROOT'))
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    if args.verify:
        result = inspect_bundle(args.verify, source_root=args.source_root)
        print(json.dumps(dict(status='PASS', manifest=str(args.verify), elf_sha256=result['executable']['inspection']['sha256'])))
    else:
        if not args.hepta or not args.build_root: parser.error('--hepta and --build-root or HIA environment are required')
        result = build_write_chain(args.hepta, args.build_root, source_root=args.source_root)
        print(json.dumps(dict(status='NATIVE_BUILD_READY', manifest=str(result), elf_sha256=ELF_SHA)))


if __name__ == '__main__': main()
