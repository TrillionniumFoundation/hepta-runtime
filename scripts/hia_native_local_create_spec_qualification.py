"""Complete evidence for the fixed Local create_file_spec scheduling profile.

Native suites execute the HIA composition before the original phase. The
original recipe freshly builds byte-exact target functions with the target
dependency lock. Admission only rereads retained artifacts and actual process
receipts; it never executes either implementation.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tomllib

import hia_native_local_create_qualification as base
import hia_native_local_create_async_qualification as async_base
from hia_native_local_create_spec_build import MEMBERS, SOURCE_FILES as BUILD_FILES
from hia_native_local_create_spec_build import source_evidence as build_sources, verify_build

ROOT = Path(__file__).resolve().parents[1]
FOLDER = 'local-create-spec'
DRIVERS = 'tests/hia_native/local_create/spec'
REFERENCE = DRIVERS + '/reference'
LEAF = 'tests/hia_native/local_create/async/owned_trace.py'
TESTS = ('test_local_create_spec_semantics.py', 'test_local_create_spec_held.py',
         'test_local_create_spec_evidence.py')
STATE_HELPER = 'scripts/hia_native_local_create_spec_state_qualification.py'
PROCESS_NAMES = ('local-create-spec-rust-version', 'local-create-spec-cargo-version',
                 'local-create-spec-cargo-metadata', 'local-create-spec-rust-build',
                 'local-create-spec-ordinary-original', 'local-create-spec-held-original')
MODULE = dict(key='local_create_spec', name='local-create-spec', source='native/local_create_spec.hepta',
              builder='local_create_spec', manifest_env='HIA_LOCAL_CREATE_SPEC_MANIFEST',
              test='test_local_create_spec_build.py',
              additional_tests=('test_local_create_spec_state.py', *TESTS),
              companion_sources=('native/local_create_spec_packer.hepta',), buffer_profile='history.v1')
SCOPE = dict(local_serial_profile_only=True, target_tokio='1.53.3',
             public_handler_qualified=False, full_create_file_spec_qualified=False,
             runtime_shutdown_qualified=False, arbitrary_tokio_budget_qualified=False,
             production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
COUNTS = dict(ordinary_cases=38, held_cases=15, actual_native_root_processes=53,
              process_deadline_seconds=60, suite_deadline_seconds=180)
CONTROL_COUNTS = dict(actual_captures=2, process_refusals=10, source_refusals=8,
                      artifact_refusals=30, journal_admissions=3, journal_refusals=5)
ORIGINAL_CONTROL_COUNTS = dict(actual_captures=2, process_refusals=10, source_refusals=4,
                               reference_refusals=10, stream_refusals=6)
REFERENCE_PINS = {'Cargo.lock': {'bytes': 1046, 'sha256': 'deafc2a8a70209d87444e82c048323b0b78fa2e4bff03ea4591ab8f5ffc68834'}, 'Cargo.toml': {'bytes': 260, 'sha256': '7e16e8f974708e4e4a8525a10a212f66cdf5bd6df5de7ffff41569fa9bbf24d0'}, 'src/cache_observer.rs': {'bytes': 2737, 'sha256': 'ae23ec2af9dd310cf029799ecbbb7e48fc584ad4a1ec807a81a4b91ec3f0159e'}, 'src/main.rs': {'bytes': 10750, 'sha256': '9ca73685d8cd35917d54615518d6cfb5dc2df152701e0005e30f5dafcdc97ba4'}, 'src/original_delta.rs': {'bytes': 1906, 'sha256': 'fb62d17d7e76a592d3d80e8b8f4ecc0fc17d0bfd41c38621bd74dae73729f186'}, 'src/original_file_ops.rs': {'bytes': 1709, 'sha256': 'ec19e5dec1ebcfacfd6ecbbf71faa6f7880d8ab86bc6b1dc002f725577743bd2'}, 'src/original_remote.rs': {'bytes': 4350, 'sha256': '1e1d7ab1376173d9cc6160f67a97297ff39550298f8c63c0edb1fce9e7681898'}, 'src/original_request_ctx.rs': {'bytes': 752, 'sha256': '56260e882ca74ede4615e2ba9a045b06a78f3dad539bc66aac9608f14407b486'}, 'src/original_sftp_unavailable.rs': {'bytes': 638, 'sha256': '96c84b247978001d91b351d912585160fc34a3f5feb0186a4f72ac824f25296c'}, 'src/original_text_editing.rs': {'bytes': 968, 'sha256': '986d87ebcc43029ffc6e8177cccb55154bbb2539a866c18abbcfbe4d57d6343d'}, 'target/Cargo.lock': {'bytes': 90188, 'sha256': '1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631'}, 'target/Cargo.toml': {'bytes': 4259, 'sha256': 'bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f'}, 'target/src/mcp/fs/delta.rs': {'bytes': 9765, 'sha256': 'a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1'}, 'target/src/mcp/fs/file_ops.rs': {'bytes': 6557, 'sha256': '487524ea40ebc2fd7ddec1676d927237127b768804a73bddeff0d4dc510d206a'}, 'target/src/mcp/fs/remote.rs': {'bytes': 48236, 'sha256': 'a23f810f20d684b2a72cdf40e6fa4f4c3186237fa281ea3a8dcbeeed5039d888'}, 'target/src/mcp/fs/remote_unavailable.rs': {'bytes': 1431, 'sha256': '727d612dfccd5a7ecd83258f14507f0c97a3d7640c6f7706d5e33a38c4566ad5'}, 'target/src/mcp/fs/text_editing.rs': {'bytes': 63372, 'sha256': 'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590'}, 'target/src/mcp/request_ctx.rs': {'bytes': 2860, 'sha256': '81ebf6e68bcf8c119c83274a090b5e4796d00b3ca6d889c92e9922be0612e943'}}
DRIVER_FILES = ('cases.py', 'observations.py', 'owned_trace.py', 'run_ordinary.py',
                'run_held.py', 'native_suite.py', 'evidence.py', 'controls.py', 'original_controls.py',
                'verify_reference.py', 'source-extraction.json', 'PROTOCOL.md')
SOURCE_FILES = tuple(sorted(set((
    *BUILD_FILES, 'native/migration_target.json',
    'scripts/hia_native_local_create_spec_build.py',
    'scripts/hia_native_local_create_spec_qualification.py',
    'scripts/hia_native_local_create_qualification.py',
    'scripts/hia_native_local_create_async_qualification.py',
    'scripts/hia_native_local_create_build.py',
    'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
    'tests/hia_native/evidence_snapshot.py',
    LEAF, 'tests/hia_native/local_create/async/held_evidence.py',
    *('tests/hia_native/' + name for name in TESTS),
    *(DRIVERS + '/' + name for name in DRIVER_FILES),
    *(REFERENCE + '/' + name for name in REFERENCE_PINS),
))))
sha = base.sha; pin = base.pin; compact = base.compact; exact = base.exact
require = base.require; owned = base.owned; decode = base.decode; finite = base.finite
_READER = None


def driver(name, source_root=ROOT):
    path = owned(source_root, DRIVERS + '/' + name)
    sys.path.insert(0, str(path.parent))
    specification = importlib.util.spec_from_file_location('_local_spec_' + path.stem, path)
    module = importlib.util.module_from_spec(specification); specification.loader.exec_module(module)
    return module


def reader():
    global _READER
    if _READER is None: _READER = driver('evidence.py')
    return _READER


def source_evidence(source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    component = build_sources(root)
    files = {name: pin(owned(root, name).read_bytes()) for name in SOURCE_FILES}
    for name, identity in REFERENCE_PINS.items():
        exact(files[REFERENCE + '/' + name], identity, 'fixed full Local reference changed: ' + name)
    verified = driver('verify_reference.py', root).verify(root / DRIVERS)
    identity = decode(owned(root, DRIVERS + '/source-extraction.json').read_bytes())
    target = decode(owned(root, 'native/migration_target.json').read_bytes())
    require(identity['target_commit'] == component['target_commit']
            == '737acf6f901e46c57b0b4374e323e0d1132e0d49', 'full Local reference provenance differs')
    require(all(type(target.get(key)) is str and re.fullmatch(r'[0-9a-f]{40}', target[key])
                for key in ('target_commit', 'target_tree')), 'full Local migration target identity differs')
    inventory = {row['path']: row for row in target['source_files']}
    require(len(inventory) == len(target['source_files']), 'target source inventory is duplicated')
    for name, row in identity['source_files'].items():
        require(inventory[name]['git_blob'] == row['git_blob'] and inventory[name]['bytes'] == row['bytes'],
                'full Local reference is not the registered target file: ' + name)
    require(files[LEAF]['sha256'] == 'd40af1d2b8dee7990b19669e8dd32db72b6cf146277c2f937e91830a62562b42',
            'the frozen owned-child tracer changed')
    target_binding = dict(target_commit=target['target_commit'], target_tree=target['target_tree'],
        reference_commit=identity['target_commit'], reference_tree=identity['target_tree'],
        complete_selected_files_equal=True, selected_files={name: dict(bytes=row['bytes'], git_blob=row['git_blob'])
            for name, row in identity['source_files'].items()})
    return dict(component=component, files=files, reference_registry=identity['registry'],
                migration_target_binding=target_binding,
                target_reference=identity, exact_source_verification=verified, scope=SCOPE)


def execution(output, manifest_path, source_root=ROOT):
    return dict(source_root=str(Path(source_root).resolve()), output=str(Path(output).resolve()),
                manifest=str(Path(manifest_path).resolve()))


def capture_origin(origin, mode, binary):
    return dict(source=origin['source_root'] + '/' + DRIVERS,
                output=origin['output'] + '/' + FOLDER + '/' + mode,
                fixtures=origin['output'] + '/' + FOLDER + '/fixtures',
                binary=str(binary), leaf_source=origin['source_root'] + '/' + LEAF)


def native_capture(output, manifest_path, *, source_root=ROOT, origin=None, domain=None):
    output = Path(output).resolve(strict=True); root = Path(source_root).resolve(strict=True)
    manifest = Path(manifest_path).resolve(strict=True)
    verify_build(manifest, source_root=root)
    origin = origin or execution(output, manifest, root)
    require(set(origin) == {'source_root', 'output', 'manifest'} and
            all(reader().absolute(value) for value in origin.values()), 'full Local native process origin differs')
    binary = manifest.parent / 'local-create-spec.elf'
    binding = dict(manifest=str(manifest.relative_to(output)), manifest_sha256=sha(manifest.read_bytes()),
                   executable=str(binary.relative_to(output)), executable_identity=pin(binary.read_bytes()))
    invocation = capture_origin(origin, 'native', Path(origin['manifest']).parent / 'local-create-spec.elf')
    if domain is None:
        captured = reader().capture(output / FOLDER / 'native', root / DRIVERS, 'native',
            binary_identity=binding['executable_identity'], execution=invocation, fixtures=output / FOLDER / 'fixtures')
    else:
        require(domain in ('ordinary', 'held'), 'unknown full Local capture domain')
        invocation.update(output=invocation['output'] + '/' + domain, fixtures=invocation['fixtures'] + '/' + domain)
        if domain == 'ordinary': invocation.pop('leaf_source')
        function = reader().ordinary_capture if domain == 'ordinary' else reader().held_capture
        captured = function(output / FOLDER / 'native' / domain, root / DRIVERS, 'native',
            binary_identity=binding['executable_identity'], execution=invocation,
            fixtures=output / FOLDER / 'fixtures' / domain)
    return dict(schema='hepta.runtime.local-create-spec-native-admission.v1', status='PASS',
                source_inputs=source_evidence(root), execution=origin, module=binding, capture=captured, scope=SCOPE)


def module_evidence(evidence, report, root):
    row = report['modules']['local_create_spec']; relative = row['manifest']
    raw = evidence.read(relative)
    exact({key: row.get(key) for key in ('source', 'builder', 'sha256')},
          dict(source=MODULE['source'], builder=MODULE['builder'], sha256=sha(raw)),
          'registered full Local native build differs')
    metadata = verify_build(owned(evidence.output, relative), source_root=root)
    folder = PurePosixPath(relative).parent
    for role in MEMBERS:
        for suffix in ('.json', '.hepta', '.image.bin'): evidence.read(str(folder / (role + suffix)))
    for name in ('pack.input.bin', 'pack.output.bin', 'pack.workspace.bin', 'pack.receipt.json', 'local-create-spec.elf'):
        evidence.read(str(folder / name))
    image = evidence.read('build/bootstrap/B3.image.bin'); evidence.read('build/bootstrap/bootstrap.json')
    require(sha(image) == metadata['compiler_sha256'] == report['compiler_image_sha256'] and
            metadata['compiler_commit'] == report['compiler_commit'], 'aggregate compiler does not own the full Local build')
    return dict(manifest=relative, manifest_sha256=sha(raw), executable=str(folder / 'local-create-spec.elf'),
                executable_identity=pin(evidence.read(str(folder / 'local-create-spec.elf'))))


def progress(raw, captured, domain, mode):
    lines = raw.splitlines()
    definitions = reader().cases.CASES if domain == 'ordinary' else reader().run_held.CASES
    require(len(lines) == len(definitions) + 1, 'full Local actual progress omitted a fixed case')
    for index, (line, case) in enumerate(zip(lines[:-1], definitions, strict=True)):
        exact(decode(line), dict(case=index + 1, name=case['name'], mode=mode, status='PASS'),
              'full Local actual progress changed case order or identity')
    keys = ('status', 'actual_root_processes', 'actual_owned_processes', 'elapsed_seconds') if domain == 'held' else (
            'status', 'actual_root_processes', 'elapsed_seconds')
    expected = {key: captured[key] for key in keys}
    if domain == 'ordinary': expected['cases'] = 38
    exact(decode(lines[-1]), expected, 'full Local actual progress summary differs')


def suite_process(evidence, report, name, origin, groups):
    stdout, stderr, row = base.process(evidence, report, name,
        base.suite_command(report, name, origin), 'native_components')
    text = stderr.decode('utf-8'); noun = 'test' if groups == 1 else 'tests'
    require(len(re.findall(r'\.\.\. ok\n', text)) == groups and re.search(
        r'\nRan ' + str(groups) + ' ' + noun + r' in [0-9.]+s\n\nOK\n\Z', text), 'complete full Local unittest domain did not pass')
    summary = decode(stdout); exact(row.get('summary'), summary, 'full Local outer suite summary differs')
    return summary


def suite_summary(domain, sources, origin, manifest_sha256, admission):
    return dict(schema='hepta.runtime.local-create-spec-' + domain + '-suite.v1', status='PASS',
        tests_run=1, expected_tests=1, failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0,
        counts=dict(cases=38 if domain == 'ordinary' else 15, process_deadline_seconds=60, suite_deadline_seconds=180),
        source_inputs=sources, execution=origin, sources_unchanged=True, manifest_sha256=manifest_sha256,
        capture_sha256=sha(compact(admission)), scope=SCOPE)


def core_native_evidence(output, report, *, source_root=ROOT):
    output = Path(output).resolve(strict=True); root = Path(source_root).resolve(strict=True)
    evidence = base.Evidence(output); module = module_evidence(evidence, report, root)
    source = source_evidence(root); origin = None
    for domain, test in zip(('ordinary', 'held'), TESTS[:2], strict=True):
        summary = evidence.object(FOLDER + '/' + domain + '-suite.json')
        if origin is None: origin = summary.get('execution')
        exact(summary.get('execution'), origin, 'ordinary/held native origins differ')
        admission = native_capture(output, owned(output, module['manifest']), source_root=root, origin=origin, domain=domain)
        exact(admission['module'], module, 'semantic corpus did not execute the registered full Local ELF')
        expected = suite_summary(domain, source, origin, module['manifest_sha256'], admission)
        actual = suite_process(evidence, report, test, origin['source_root'], 1)
        exact(summary, expected, 'full Local semantic suite source/domain/deadline differs')
        exact(actual, summary, 'full Local semantic suite complete stdout differs')
        capture_summary = evidence.object(FOLDER + '/native/' + domain + '/summary.json')
        progress(evidence.read(FOLDER + '/' + domain + '.driver.stdout'), capture_summary, domain, 'native')
    captured = native_capture(output, owned(output, module['manifest']), source_root=root, origin=origin)
    artifacts = dict(evidence.artifact_sha256)
    artifacts.update({FOLDER + '/native/' + name: value for name, value in captured['capture']['artifact_sha256'].items()})
    exact(source_evidence(root), source, 'full Local sources changed during readonly admission')
    return dict(status='PASS', counts=COUNTS, source_inputs=source, module=module, execution=origin,
                capture=captured['capture'], artifact_sha256=dict(sorted(artifacts.items())), scope=SCOPE)


def native_evidence(output, report, *, source_root=ROOT):
    result = core_native_evidence(output, report, source_root=source_root)
    evidence = base.Evidence(output)
    summary = suite_process(evidence, report, TESTS[2], result['execution']['source_root'], 5)
    expected = dict(schema='hepta.runtime.local-create-spec-evidence-controls.v1', status='PASS',
        tests_run=5, expected_tests=5, failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0,
        counts=CONTROL_COUNTS, source_inputs=source_evidence(source_root),
        native_evidence_sha256=sha(compact(result)), new_native_or_rust_processes=0,
        synthetic_receipt_controls=True, scope=SCOPE)
    exact(summary, expected, 'full Local complete evidence refusal domain differs')
    exact(evidence.object(FOLDER + '/evidence-controls.json'), summary, 'full Local refusal retained stdout differs')
    result['evidence_controls'] = CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    # The build/state owner reads all its actual packer calls and borrowed-buffer
    # controls independently. A PASS string alone never admits those domains.
    import hia_native_local_create_spec_state_qualification as state
    typed = state.native_evidence(output, report, source_root=source_root)
    result['build_and_state'] = typed
    result['artifact_sha256'].update(typed['artifact_sha256'])
    result['artifact_sha256'] = dict(sorted(result['artifact_sha256'].items()))
    return result


build_override = async_base.build_override
reference_environment = async_base.reference_environment


def original_commands(output, rustc, *, source_root=ROOT, python=None):
    output = Path(output); folder = output / FOLDER / 'reference'; rustc = Path(rustc)
    cargo = rustc.with_name('cargo'); python = python or sys.executable
    target = 'x86_64-unknown-linux-gnu'; config = ['--config', 'build.rustc=' + json.dumps(str(rustc))]
    binary = folder / 'target' / target / 'release/hepta-local-create-spec-original-oracle'
    commands = {
        PROCESS_NAMES[0]: [str(rustc), '--version', '--verbose'],
        PROCESS_NAMES[1]: [str(cargo), '--version'],
        PROCESS_NAMES[2]: [str(cargo), *config, 'metadata', '--locked', '--format-version=1', '--filter-platform', target,
                           '--manifest-path', str(folder / 'source/Cargo.toml')],
        PROCESS_NAMES[3]: [str(cargo), *config, 'build', '--locked', '--release', '--target', target,
                           '--manifest-path', str(folder / 'source/Cargo.toml'), '--target-dir', str(folder / 'target')],
    }
    for name, domain in zip(PROCESS_NAMES[4:], ('ordinary', 'held'), strict=True):
        command = [python, '-I', '-B', str(Path(source_root) / DRIVERS / ('run_' + domain + '.py')),
                   '--binary', str(binary), '--mode', 'rust', '--output', str(output / FOLDER / 'original' / domain),
                   '--fixtures', str(output / FOLDER / 'fixtures' / domain)]
        if domain == 'held': command += ['--leaf-source', str(Path(source_root) / LEAF)]
        commands[name] = command
    return commands


def metadata_evidence(raw, source):
    metadata = decode(raw); packages = {package['id']: package for package in metadata['packages']}
    require(len(packages) == len(metadata['packages']) == 5, 'full Local actual Cargo package set differs')
    expected = {row['name']: (row['version'], row['source']) for row in source['reference_registry']}
    registry, roots = {}, []
    for node in metadata['resolve']['nodes']:
        package = packages[node['id']]
        if package.get('source') is None:
            require(package['name'] == 'hepta-local-create-spec-original-oracle' and package['version'] == '0.1.0'
                    and node['features'] == [], 'full Local original Cargo workspace/features differ')
            roots.append(package['name'])
            dependencies = {row['name']: row for row in package['dependencies']}
            require(len(dependencies) == len(package['dependencies']) == 2 and set(dependencies) == {'anyhow', 'tokio'},
                    'full Local original gained a dependency')
            require(dependencies['anyhow']['req'] == '=1.0.104' and dependencies['anyhow']['features'] == []
                    and dependencies['tokio']['req'] == '=1.53.3'
                    and set(dependencies['tokio']['features']) == {'rt', 'fs', 'io-util'}, 'target dependency declarations differ')
        else:
            require(package['name'] in expected and (package['version'], package['source']) == expected[package['name']]
                    and package['name'] not in registry, 'full Local actual registry dependency differs')
            registry[package['name']] = node['features']
    exact(roots, ['hepta-local-create-spec-original-oracle'], 'full Local original workspace root differs')
    exact(registry, {'anyhow': ['default', 'std'], 'bytes': ['default', 'std'], 'pin-project-lite': [],
                     'tokio': ['bytes', 'default', 'fs', 'io-util', 'rt']}, 'full Local actual Cargo feature closure differs')
    return registry


def original_capture(output, report, rustc, *, source_root=ROOT):
    output = Path(output).resolve(strict=True); root = Path(source_root).resolve(strict=True)
    evidence = base.Evidence(output); source = source_evidence(root)
    native = native_evidence(output, report, source_root=root)
    receipt = evidence.object(FOLDER + '/reference/reference-build.json')
    require(receipt.get('status') in ('REFERENCE_EXECUTED', 'PASS'), 'fresh full Local original did not complete')
    exact(receipt.get('source_inputs'), source, 'fresh full Local source custody differs')
    exact(receipt.get('scope'), SCOPE, 'full Local original scope differs')
    exact((receipt.get('fresh_target_directory'), receipt.get('fresh_locked_builds')), (True, 1), 'full Local original target was not fresh')
    for name in REFERENCE_PINS:
        require(evidence.read(FOLDER + '/reference/source/' + name) == owned(root, REFERENCE + '/' + name).read_bytes(),
                'fresh full Local original source differs: ' + name)
    origin = receipt['execution']
    require(type(origin) is dict and set(origin) == {'source_root', 'output', 'python'} and
            all(reader().absolute(value) for value in origin.values()), 'full Local original execution origin differs')
    commands = original_commands(origin['output'], rustc, source_root=origin['source_root'], python=origin['python'])
    exact(receipt.get('commands'), commands, 'full Local original actual process inventory differs')
    compilers = {'rustc': base.compiler_identity(rustc), 'cargo': base.compiler_identity(Path(rustc).with_name('cargo'))}
    exact(receipt.get('compiler_before'), compilers, 'full Local original compiler changed before execution')
    exact(receipt.get('compiler_after'), compilers, 'full Local original compiler changed after execution')
    binding = receipt['environment_binding']; removed = binding.get('removed_inherited_variables')
    require(type(removed) is list and removed == sorted(set(removed)) and
            all(type(name) is str and build_override(name) for name in removed), 'full Local compiler environment removal differs')
    _, expected = reference_environment({name: 'removed' for name in removed}, rustc)
    exact(binding, expected, 'full Local controlled compiler configuration differs')
    for name in PROCESS_NAMES:
        stdout, stderr, row = base.process(evidence, report, name, commands[name], 'original_rust_comparison')
        exact(row.get('environment_binding'), binding, 'full Local actual original process environment differs')
        if name == PROCESS_NAMES[0]:
            require(stdout.startswith(b'rustc 1.95.0 ') and b'host: x86_64-unknown-linux-gnu\n' in stdout and not stderr,
                    'full Local original Rust release/platform differs')
        elif name == PROCESS_NAMES[1]: require(stdout.startswith(b'cargo 1.95.0 ') and not stderr, 'full Local original Cargo differs')
        elif name == PROCESS_NAMES[2]: metadata_evidence(stdout, source)
        elif name == PROCESS_NAMES[3]: require(not stdout, 'full Local original build wrote unexpected stdout')
        else:
            require(not stderr, 'full Local original replay leaked diagnostics')
            domain = 'ordinary' if name == PROCESS_NAMES[4] else 'held'
            progress(stdout, evidence.object(FOLDER + '/original/' + domain + '/summary.json'), domain, 'rust')
    binary_relative = FOLDER + '/reference/target/x86_64-unknown-linux-gnu/release/hepta-local-create-spec-original-oracle'
    binary = evidence.read(binary_relative); require(binary.startswith(b'\x7fELF'), 'fresh full Local original executable is absent')
    exact(receipt.get('executable'), dict(path=binary_relative, **pin(binary)), 'full Local fresh executable custody differs')
    pair = reader().compare(output / FOLDER / 'native', output / FOLDER / 'original', root / DRIVERS,
        native_identity=native['module']['executable_identity'], original_identity=pin(binary),
        native_execution=capture_origin(native['execution'], 'native', Path(native['execution']['manifest']).parent / 'local-create-spec.elf'),
        original_execution=capture_origin(origin, 'original', origin['output'] + '/' + binary_relative),
        fixtures=output / FOLDER / 'fixtures')
    exact(pair['native'], native['capture'], 'paired full Local comparison did not consume its admitted native capture')
    artifacts = dict(native['artifact_sha256']); artifacts.update(evidence.artifact_sha256)
    artifacts.update({FOLDER + '/original/' + name: value for name, value in pair['original']['artifact_sha256'].items()})
    return dict(status='PASS', ordinary_cases=38, held_cases=15, actual_native_root_processes=53,
        actual_original_root_processes=53, complete_compared_bytes=pair['complete_compared_bytes'], source_inputs=source,
        native_capture_sha256=sha(compact(pair['native'])), original_capture_sha256=sha(compact(pair['original'])),
        actual_original_processes=list(PROCESS_NAMES), fresh_locked_builds=1,
        artifact_sha256=dict(sorted(artifacts.items())), scope=SCOPE)


def original_evidence(output, report, rustc, *, source_root=ROOT):
    result = original_capture(output, report, rustc, source_root=source_root)
    evidence = base.Evidence(output); summary = evidence.object(FOLDER + '/original-controls.json')
    expected = dict(schema='hepta.runtime.local-create-spec-original-controls.v1', status='PASS',
        counts=ORIGINAL_CONTROL_COUNTS, source_inputs=source_evidence(source_root),
        original_evidence_sha256=sha(compact(result)), new_native_or_rust_processes=0,
        synthetic_receipt_controls=True, scope=SCOPE)
    exact(summary, expected, 'full Local original refusal domain differs')
    result['original_evidence_controls'] = ORIGINAL_CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    result['artifact_sha256'] = dict(sorted(result['artifact_sha256'].items()))
    return result


def compare_original(output, report, rustc):
    import qualify_hia_runtime_native as q
    output = Path(output).resolve(strict=True); rustc = Path(rustc)
    native_evidence(output, report)
    folder = output / FOLDER / 'reference'; folder.mkdir(exist_ok=False)
    (output / FOLDER / 'original').mkdir(exist_ok=False)
    sources = source_evidence()
    before = {'rustc': base.compiler_identity(rustc), 'cargo': base.compiler_identity(rustc.with_name('cargo'))}
    environment, binding = reference_environment(q.qualification_env(), rustc)
    for name in REFERENCE_PINS:
        path = folder / 'source' / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(owned(ROOT, REFERENCE + '/' + name).read_bytes())
    require(not (folder / 'target').exists(), 'full Local original target directory is not fresh')
    commands = original_commands(output, rustc)
    receipt = dict(schema='hepta.runtime.local-create-spec-reference-build.v1', status='BUILDING', source_inputs=sources,
        scope=SCOPE, fresh_target_directory=True, fresh_locked_builds=1, compiler_before=before, compiler_after=None,
        environment_binding=binding, commands=commands,
        execution=dict(source_root=str(ROOT), output=str(output), python=sys.executable))
    def save(): (folder / 'reference-build.json').write_bytes(compact(receipt) + b'\n')
    save()
    try:
        for name in PROCESS_NAMES:
            q.record_check(output, report, name=name, command=commands[name], timeout=180, env=environment)
            report['checks'][-1]['environment_binding'] = binding; q.save_report(output / 'result.json', report)
        receipt['compiler_after'] = {'rustc': base.compiler_identity(rustc), 'cargo': base.compiler_identity(rustc.with_name('cargo'))}
        exact(receipt['compiler_after'], before, 'full Local compiler changed during actual build/replay')
        binary = folder / 'target/x86_64-unknown-linux-gnu/release/hepta-local-create-spec-original-oracle'
        receipt['executable'] = dict(path=str(binary.relative_to(output)), **pin(binary.read_bytes()))
        receipt['status'] = 'REFERENCE_EXECUTED'; save()
        original_capture(output, report, rustc)
        exact(source_evidence(), sources, 'full Local source closure changed during actual original replay')
        receipt['status'] = 'PASS'; save()
        sys.path.insert(0, str(ROOT / 'tests/hia_native'))
        driver('original_controls.py').run(output, report, rustc, sys.modules[__name__], ROOT)
        return original_evidence(output, report, rustc)
    except BaseException as error:
        receipt['status'] = 'FAIL'; receipt['error'] = repr(error); save(); raise
