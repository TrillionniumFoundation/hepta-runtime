"""Pure complete-byte checks for fresh HIA build and synchronization emission."""
from common import ROOT, COMPILER, HEPTA_COMMIT, HEPTA_TREE, files, loads, pin, read, require, sha
SYNC_SOURCE = 'e780e46fcdb3278b6b4e87b56da79397dc6f8abbb741e7260e7e71ac4bab07a5'
MODULE_SOURCES = {
    'audit-lifetime': 'native/audit_lifetime.hepta',
    'audit-refs': 'native/audit_refs_emitter.hepta',
    'audit-native-sync': 'native/audit_sync_boundary.hepta',
    'audit-lifetime-callable': 'native/audit_lifetime_callable.hepta',
}

def check_build(root, identity):
    build = root / 'build'
    report = loads(read(build / 'BUILD.json'))
    require(report['schema'] == 'hepta.audit-lifetime.build.v1'
            and report['source_manifest_sha256'] == identity and report['compiler_sha256'] == COMPILER
            and report['compiler_bootstrap'] == 'fresh pinned B1=B2=B3'
            and report['sync_source_manifest_sha256'] == SYNC_SOURCE
            and set(report['modules']) == set(MODULE_SOURCES), 'fresh composed B3 build binding')
    sync = build / 'sync-source'
    sync_manifest = read(sync / 'SOURCE_MANIFEST.json')
    require(sha(sync_manifest) == SYNC_SOURCE, 'qualified synchronization source identity')
    sync_files = files(sync, ('SOURCE_MANIFEST.json',))
    require({name: {key: row[key] for key in ('bytes', 'sha256')} for name, row in sync_files.items()}
            == loads(sync_manifest)['files'] and all(row['mode'] == 0o644 for row in sync_files.values()),
            'complete qualified synchronization source bytes and modes')
    dependency = loads(read(sync / 'COMPILER_FILES.json'))
    require(dependency['commit'] == HEPTA_COMMIT and dependency['tree'] == HEPTA_TREE
            and len(dependency['files']) == report['compiler_files'] == 1080, 'complete pinned compiler closure')
    retained = files(build / 'compiler-source')
    require(set(retained) == set(dependency['files']), 'complete retained compiler source set')
    for name, row in retained.items():
        require(row['sha256'] == dependency['files'][name], 'retained compiler source: ' + name)
    bootstrap = loads(read(build / 'bootstrap/bootstrap.json'))
    require(bootstrap['dependency'] == dependency and bootstrap['generation_sha256'] == COMPILER,
            'bootstrap compiler/source identity')
    compiler_source = read(build / 'compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(bootstrap['compiler_source_sha256'] == sha(compiler_source), 'bootstrap source bytes')
    for stage in ('B1', 'B2', 'B3'):
        folder = build / 'bootstrap'
        image = read(folder / (stage + '.image.bin'))
        complete = read(folder / (stage + '.output.bin'))
        receipt = loads(read(folder / (stage + '.receipt.json')))
        require(pin(image) == dict(bytes=673413, sha256=COMPILER), 'fixed-point compiler generation')
        require(read(folder / (stage + '.input.bin')) == compiler_source, 'full compiler input')
        require(len(complete) == 1048576 and complete[:len(image)] == image
                and complete[len(image):] == b'\xa5' * (len(complete) - len(image)), 'full compiler output tail')
        require(receipt['status'] == 'returned' and receipt['source_unchanged'] is True
                and receipt['produced_sha256'] == COMPILER and receipt['output_sha256'] == sha(complete)
                and receipt['result_u64'] == receipt['core_u32'] == len(image)
                and receipt['forbidden_compiler_modules_loaded'] == [], 'actual bootstrap receipt')
    modules = {}
    for name in MODULE_SOURCES:
        folder = build / 'modules' / name
        manifest = loads(read(folder / 'manifest.json'))
        source_path = (sync / MODULE_SOURCES[name] if name == 'audit-native-sync' else ROOT / MODULE_SOURCES[name])
        raw_source = read(source_path)
        image = read(folder / 'module.image.bin')
        output = read(folder / 'module.output.bin')
        receipt = loads(read(folder / 'module.receipt.json'))
        expected = report['modules'][name]
        require(expected == dict(manifest='modules/' + name + '/manifest.json',
                                 manifest_pin=pin(read(folder / 'manifest.json')), image=pin(image)),
                'complete composed module binding')
        require(manifest['schema'] == 'hepta.runtime.native-module.v1' and manifest['name'] == name
                and manifest['target'] == 'linux-x86_64'
                and manifest['abi'] == 'hepta.runtime.borrowed-bytes.linux-x86_64.v1'
                and manifest['compiler_commit'] == HEPTA_COMMIT and manifest['compiler_sha256'] == COMPILER
                and manifest['source'] == name + '.hepta' and manifest['image'] == 'module.image.bin'
                and manifest['source_sha256'] == sha(raw_source) and manifest['image_sha256'] == sha(image)
                and manifest['standalone'] is None and manifest['buffer_profile'] == 'history.v1',
                'native module identity')
        require(read(folder / (name + '.hepta')) == read(folder / 'module.input.bin') == raw_source,
                'exact compiler module source')
        require(0 < len(image) < 1048576 and len(output) == 1048576 and output[:len(image)] == image
                and output[len(image):] == b'\xa5' * (len(output) - len(image)), 'complete module output and tail')
        require(receipt['status'] == 'returned' and receipt['source_unchanged'] is True
                and receipt['artifact_sha256'] == receipt['image_sha256'] == COMPILER
                and receipt['input_sha256'] == receipt['source_sha256'] == sha(raw_source)
                and receipt['output_sha256'] == sha(output) and receipt['produced_sha256'] == sha(image)
                and receipt['result_u64'] == receipt['core_u32'] == receipt['produced_bytes'] == len(image)
                and receipt['forbidden_compiler_modules_loaded'] == [], 'actual B3 compilation')
        build_receipt = loads(read(folder / 'build.json'))
        require(build_receipt['compile_receipt'] == receipt and build_receipt['compiler_dependency'] == dependency,
                'complete module build receipt')
        if name == 'audit-native-sync':
            require(sha(image) == '3f680858821d674511aba0a59df606bc03bc9384216e6e4fa88b1a01c7bbeae5', 'unchanged compiled sync emitter')
        modules[name] = pin(image)
    return dict(modules=modules, compiler_files=len(retained), sync_source_manifest_sha256=SYNC_SOURCE)



def check_emission(root, identity):
    folder = root / 'sync-emission'
    report = loads(read(folder / 'EMISSION.json'))
    composition = loads(read(root / 'build/sync-source/native/audit_sync_boundary.composition.json'))
    expected_image = composition['emitted_instructions']
    count = expected_image['bytes']
    image = read(folder / 'boundary.bin')
    require(pin(image) == expected_image and report['boundary'] == expected_image, 'exact emitted instruction bytes')
    require(report['schema'] == 'hepta.audit-native-sync.emission.v1'
            and report['source_manifest_sha256'] == SYNC_SOURCE and report['native_calls'] == 7
            and report['refusals'] == 6 and report['whole_runtime_replaced'] is False, 'emission binding')
    require(report['module_manifest'] == pin(read(root / 'build/modules/audit-native-sync/manifest.json')),
            'actual emitter module binding')
    good = b'HASYPK01' + (1).to_bytes(8, 'little')
    expected = [('valid', good, count + 64, count), ('empty', b'', count + 64, 0xffffffff),
                ('short', good[:-1], count + 64, 0xffffffff), ('long', good + b'\0', count + 64, 0xffffffff),
                ('magic', b'X' + good[1:], count + 64, 0xffffffff),
                ('version', good[:8] + (2).to_bytes(8, 'little'), count + 64, 0xffffffff),
                ('capacity', good, count - 1, 0xfffffffe)]
    require(len(report['calls']) == 7, 'all emitter calls retained')
    physical = 0
    for row, (name, wire, capacity, result) in zip(report['calls'], expected, strict=True):
        require(row['name'] == name and row['returned'] == result and row['output_capacity'] == capacity
                and row['workspace_capacity'] == 64, 'emitter case domain')
        require(set(row['buffers']) == {'input', 'output-before', 'output-after', 'workspace-before', 'workspace-after'},
                'complete physical emitter buffer set')
        raw = {}
        for label, member in row['buffers'].items():
            require(member['file'] == name + '.' + label + '.bin', 'emitter buffer path')
            raw[label] = read(folder / member['file'])
            require(pin(raw[label]) == {k: member[k] for k in ('bytes', 'sha256')}, 'emitter physical buffer identity')
            physical += len(raw[label])
        require(raw['input'] == wire and raw['output-before'] == b'\xa5' * (capacity + 16)
                and raw['workspace-before'] == raw['workspace-after'] == b'\xa5' * 64 + b'\x5a' * 16,
                'emitter input, guards and untouched workspace')
        require(raw['output-after'] == (image + b'\xa5' * (capacity + 16 - count) if name == 'valid'
                                        else raw['output-before']), 'full emitted output or refusal')
    return dict(image=expected_image, calls=7, refusals=6, physical_bytes=physical)

