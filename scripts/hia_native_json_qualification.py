"""Bind JSON qualification to the retained serde lock and exact native owners."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path
import re
import stat
import tomllib

ORACLE = 'tests/hia_native/serde_json_oracle'
COMPOSITION = 'native/serde_json_composition.json'
COMPONENTS = {
    'fence_json': {'source': 'native/fence_json.hepta', 'profile': 'standard',
                   'schema': 'hepta.runtime.fence-json-native-corpus.v1', 'cases': 5087,
                   'folder': 'fence-json-rust-oracle', 'calls': 5124, 'capacities': (8 << 20, 8 << 20, 32 << 20),
                   'template': 'f2a70a50a426de5834e00336e2fa05bb98e0e1c3f9615cabd51e9a87e923b9b5'},
    'serde_json': {'source': 'native/serde_json.hepta', 'profile': 'serde-json.v1',
                   'schema': 'hepta.runtime.serde-json-native-corpus.v1', 'cases': 17778,
                   'folder': 'serde-json-rust-oracle', 'calls': 17794, 'capacities': (16 << 20, 64 << 20, 256 << 20),
                   'template': 'dc11f1d019027e20825ecf6ddd8de64cc643f4ed1fcdacd7020f13bf9cbc756a'},
}

CORPUS_IDENTITIES = {'fence_json': {'categories': {'closed-frame': 34,
                               'decoded-string-at-limit': 2,
                               'decoded-strings': 144,
                               'delete-one-byte': 198,
                               'duplicate-known': 40,
                               'epoch-domain': 15,
                               'escaped-duplicate-known': 10,
                               'field-order': 744,
                               'ignored-depth': 10,
                               'ignored-grammar': 81,
                               'ignored-object-key-unicode': 14,
                               'ignored-string-byte': 256,
                               'insert-one-byte': 812,
                               'known-versus-ignored-string': 28,
                               'missing-field': 10,
                               'raw-byte-limit': 6,
                               'replace-one-byte': 1980,
                               'root-domain': 26,
                               'sequence-length': 16,
                               'trailing-data': 10,
                               'typed-field-domain': 80,
                               'typed-options': 24,
                               'typed-sequence': 12,
                               'unknown-duplicate': 1,
                               'unknown-field-key-byte': 512,
                               'unknown-key-unicode': 14,
                               'whitespace': 8},
                'requests_bytes': 9607703,
                'requests_sha256': 'd279aad1aace9f809d5b0aa8990de8fc1262036b1eacd40be5e3d770080403b4',
                'native_output_bytes': 2715672,
                'native_output_sha256': 'd12faf42fa156b19015456e4e7aabe34a046bccda1264d9838929e1ff1ba762c'},
 'serde_json': {'categories': {'8MiB-exponent-expansion': 1,
                               '8MiB-max-nodes': 1,
                               '8MiB-plus-one-refusal': 1,
                               '8MiB-string': 1,
                               'binary64-format': 12801,
                               'integer-boundary': 655,
                               'integer-unicode-structures': 512,
                               'long-decimal': 960,
                               'numeric-fixed': 40,
                               'object-key-byte': 256,
                               'scalar-reuse-state': 24,
                               'stable-last-wins-btree': 64,
                               'string-byte': 256,
                               'unicode-boundary': 10,
                               'unicode-encoding': 14,
                               'value-byte-deletion': 95,
                               'value-byte-insertion': 400,
                               'value-byte-replacement': 1140,
                               'value-closed-frame': 34,
                               'value-decimal-boundaries': 440,
                               'value-depth': 16,
                               'value-fixed': 29,
                               'value-invalid': 28},
                'requests_bytes': 69565888,
                'requests_sha256': 'f656bcdac70022f54971ee55446b3af8b8119e7061afd8f3bd17f346ccd9c23c',
                'native_output_bytes': 98349056,
                'native_output_sha256': '49bb94f284686a0f65c6b212b83b4223c7d9226289666abde197cb925e017809'}}
TRANSPORT_REPORT = "serde-json-filter-report.json"
EVIDENCE_REPORT = "json-evidence-controls.json"
CORPUS_FILES = ("native-corpus.json", "requests.hex", "native-output.txt")


def regular(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.resolve() != path:
        raise ValueError('JSON qualification input is not a regular, unsymlinked file: ' + str(path))
    return path.read_bytes()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def same_json(left, right) -> bool:
    """Evidence integers and booleans have distinct JSON types."""
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def source_inputs(root: Path, original_root: Path | None = None) -> dict:
    root = root.resolve()
    original_root = (original_root or root).resolve()
    composition_bytes = regular(root / COMPOSITION)
    composition = json.loads(composition_bytes)
    if (composition.get('schema') != 'hepta.runtime.serde-json-source-composition.v1'
            or composition.get('original_runtime_commit') != 'a0dcdda1991ec536d5e2d252c006a778993fa566'
            or composition.get('compiler_commit') != 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
            or composition.get('legacy_call_sites_replaced') is not False
            or composition.get('complete_runtime_replaced') is not False):
        raise ValueError('JSON composition scope or pinned original identity differs')
    files = {COMPOSITION: digest(composition_bytes)}
    original = {}
    for name, expected in composition['original_sources'].items():
        raw = regular(original_root / name)
        actual = {'sha256': digest(raw), 'bytes': len(raw),
                  'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        if actual != expected:
            raise ValueError('JSON retained original source differs: ' + name)
        original[name] = raw
        files[name] = actual['sha256']
    for group in ['native_sources', 'reference_sources']:
        for name, expected in composition[group].items():
            files[name] = digest(regular(root / name))
            if files[name] != expected:
                raise ValueError('JSON native/reference source differs: ' + name)
    baseline_lock = tomllib.loads(original['Cargo.lock'].decode())
    baseline = {(p['name'], p['version']): p for p in baseline_lock['package'] if 'checksum' in p}
    oracle_lock = tomllib.loads(regular(root / ORACLE / 'Cargo.lock').decode())
    packages = []
    for package in oracle_lock['package']:
        if 'checksum' not in package:
            continue
        row = {key: package[key] for key in ['name', 'version', 'source', 'checksum']}
        expected = baseline.get((row['name'], row['version']))
        if expected is None or any(row[k] != expected[k] for k in row):
            raise ValueError('JSON reference dependency differs from original Cargo.lock')
        packages.append(row)
    if len(packages) != 11 or packages != composition['reference_registry_packages']:
        raise ValueError('JSON registry dependency domain differs')
    manifest = tomllib.loads(regular(root / ORACLE / 'Cargo.toml').decode())
    baseline_manifest = tomllib.loads(original['Cargo.toml'].decode())
    for name in ['serde', 'serde_json']:
        actual = manifest['dependencies'][name]
        expected = baseline_manifest['dependencies'][name]
        if actual['version'] != '=' + expected['version'] or actual['features'] != expected['features']:
            raise ValueError('JSON reference feature/version differs: ' + name)
    reference = regular(root / ORACLE / 'oracle.rs').decode()
    original_derive = original['src/mcp/runtime/effect_owner_fence.rs'].decode()
    for name, expected in composition['derived_definitions'].items():
        pattern = r'(?:#\[derive[^\n]+\]\n)(?:#\[serde[^\n]+\]\n)?struct ' + name + r' \{.*?\n\}'
        before = re.search(pattern, original_derive, re.S)
        after = re.search(pattern, reference, re.S)
        if (before is None or after is None or before.group() != after.group()
                or digest(after.group().encode()) != expected):
            raise ValueError('JSON original derived definition differs: ' + name)
    for name in ['native/filter_packer.hepta', 'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
                 'scripts/hia_native_json_qualification.py', 'tests/hia_native/json_native_cases.py',
                 'tests/hia_native/test_fence_json.py', 'tests/hia_native/test_serde_json.py',
                 'tests/hia_native/test_serde_json_transport.py', 'tests/hia_native/test_json_evidence.py']:
        files[name] = digest(regular(root / name))
    return {'schema': 'hepta.runtime.json-source-inputs.v1', 'files': files}


def check_module(root: Path, component: str, manifest_path: Path) -> dict:
    config = COMPONENTS[component]
    manifest = json.loads(regular(manifest_path.resolve()))
    if (manifest.get('schema') != 'hepta.runtime.native-module.v1'
            or manifest.get('abi') != 'hepta.runtime.borrowed-bytes.linux-x86_64.v1'
            or manifest.get('target') != 'linux-x86_64'
            or manifest['source_sha256'] != digest(regular(root.resolve() / config['source']))
            or manifest.get('buffer_profile', 'standard') != config['profile']
            or tuple(manifest.get(k) for k in ('input_capacity', 'output_capacity', 'workspace_capacity')) != config['capacities']
            or manifest['compiler_commit'] != 'd3e2c90173cf733e42b299d0c4274df4b593a12f'):
        raise ValueError('JSON tested native module differs from current source/profile')
    standalone = manifest.get('standalone')
    packer = 'native/filter_packer.hepta' if component == 'fence_json' else 'native/serde_filter_packer.hepta'
    if (not standalone or standalone.get('transport') != 'filter'
            or standalone.get('runtime_python_required') is not False
            or standalone.get('runtime_libc_required') is not False
            or standalone.get('packer_source_sha256') != digest(regular(root.resolve() / packer))):
        raise ValueError('JSON filter ELF is not bound to its actual HIA packer')
    for name in (manifest['source'], manifest['image'], standalone['path']):
        if Path(name).is_absolute() or len(Path(name).parts) != 1 or name in ('.', '..'):
            raise ValueError('JSON module artifact path escaped its directory')
    elf = regular(manifest_path.resolve().parent / standalone['path'])
    image = regular(manifest_path.resolve().parent / manifest['image'])
    source = regular(manifest_path.resolve().parent / manifest['source'])
    if (digest(image) != manifest['image_sha256'] or digest(elf) != standalone['sha256']
            or source != regular(root.resolve() / config['source'])):
        raise ValueError('JSON actual native image/ELF bytes differ')
    exact_filter(component, elf, image)
    from hia_native_entropy_qualification import inspect_elf
    if standalone.get('inspection') != inspect_elf(elf):
        raise ValueError('JSON actual ELF inspection differs')
    return manifest


def check_corpus(root: Path, component: str, manifest_path: Path, folder: Path,
                 original_root: Path | None = None) -> dict:
    config = COMPONENTS[component]
    metadata = json.loads(regular(folder.resolve() / 'native-corpus.json'))
    manifest = check_module(root, component, manifest_path)
    if (metadata.get('schema') != config['schema'] or metadata.get('cases') != config['cases']
            or type(metadata.get('cases')) is not int
            or metadata.get('status') != 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED'
            or metadata.get('actual_native_calls') != config['calls']
            or type(metadata.get('actual_native_calls')) is not int
            or metadata.get('standalone_runs') != 3 or type(metadata.get('standalone_runs')) is not int
            or metadata.get('qualification_inputs') != source_inputs(root, original_root)
            or metadata.get('source_sha256') != manifest['source_sha256']
            or metadata.get('image_sha256') != manifest['image_sha256']
            or metadata.get('oracle_sha256') != digest(regular(root.resolve() / ORACLE / 'oracle.rs'))):
        raise ValueError('JSON exported native corpus is not bound to current complete sources')
    expected = CORPUS_IDENTITIES[component]
    if any(not same_json(metadata.get(k), v) for k, v in expected.items()):
        raise ValueError('JSON complete original-reference corpus identity differs')
    if (type(metadata.get('native_seconds')) not in (float, int)
            or not math.isfinite(metadata['native_seconds']) or metadata['native_seconds'] <= 0):
        raise ValueError('JSON actual native elapsed time is invalid')
    for prefix, name in [('requests', 'requests.hex'), ('native_output', 'native-output.txt')]:
        path = folder.resolve() / name
        if metadata.get(prefix + '_file') != name:
            raise ValueError('JSON corpus member differs')
        actual_hash, size, count = stream_identity(path)
        if metadata.get(prefix + '_sha256') != actual_hash or metadata.get(prefix + '_bytes') != size:
            raise ValueError('JSON exported corpus bytes changed')
        if count != config['cases']:
            raise ValueError('JSON exported corpus case count differs')
    return metadata


def stream_identity(path: Path) -> tuple[str, int, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.resolve() != path:
        raise ValueError('JSON corpus must be a regular unsymlinked file')
    sha, size, lines, last = hashlib.sha256(), 0, 0, b''
    with path.open('rb') as stream:
        while chunk := stream.read(1 << 20):
            sha.update(chunk)
            size += len(chunk)
            lines += chunk.count(b'\n')
            last = chunk[-1:]
    if last != b'\n':
        raise ValueError('JSON corpus final row is incomplete')
    return sha.hexdigest(), size, lines


def exact_filter(component: str, executable: bytes, image: bytes) -> None:
    if len(executable) != 489 + len(image) or executable[489:] != image:
        raise ValueError('JSON ELF does not embed the exact admitted image')
    prefix = bytearray(executable[:489])
    for offset in (96, 104):
        if int.from_bytes(prefix[offset:offset + 8], 'little') != len(executable):
            raise ValueError('JSON ELF declared file span differs')
        prefix[offset:offset + 8] = bytes(8)
    if int.from_bytes(prefix[338:342], 'little') != 147:
        raise ValueError('JSON ELF native entry displacement differs')
    prefix[338:342] = bytes(4)
    if digest(prefix) != COMPONENTS[component]['template']:
        raise ValueError('JSON ELF differs from its fixed capacity/transport template')


def relative(root: Path, name: str) -> Path:
    value = Path(name)
    if value.is_absolute() or not value.parts or '..' in value.parts:
        raise ValueError('JSON evidence artifact escaped its output directory')
    return root / value


def completed_suite(root: Path, output: Path, report: dict, completed, name: str, groups: int):
    check, summary = completed(output, report, name)
    command = check.get('command', [])
    stderr = regular(output / (name + '.stderr')).decode('utf-8')
    if (len(command) != 4 or command[1:] != ['-I', '-B', str(root / 'tests/hia_native' / name)]
            or type(check.get('exit_code')) is not int
            or check.get('timeout_seconds') != 180 or type(check.get('timeout_seconds')) is not int
            or check.get('stdout_bytes') != len(regular(output / (name + '.stdout')))
            or check.get('stderr_bytes') != len(stderr.encode())
            or len(re.findall(r'\.\.\. ok\n', stderr)) != groups
            or not re.search(r'\nRan ' + str(groups) + r' tests in [0-9.]+s\n\nOK\n\Z', stderr)):
        raise ValueError('JSON actual executable suite did not finish its declared groups: ' + name)
    return check, summary


def build_evidence(root: Path, output: Path, report: dict, component: str) -> dict:
    from hia_native_entropy_qualification import native_receipt
    from hia_native_view_cache_qualification import _compiled
    config = COMPONENTS[component]
    owner = report['modules'][component]
    path = relative(output, owner['manifest'])
    raw = regular(path)
    module = check_module(root, component, path)
    compiler = regular(output / 'build/bootstrap/B3.image.bin')
    if (owner.get('source') != config['source'] or owner.get('builder') != 'borrowed_bytes'
            or owner.get('sha256') != digest(raw)
            or module.get('compiler_commit') != report['compiler_commit']
            or module.get('compiler_sha256') != report['compiler_image_sha256']
            or digest(compiler) != report['compiler_image_sha256']):
        raise ValueError('JSON aggregate module/compiler identity differs')
    artifacts = {}
    def artifact(item):
        data = regular(item)
        artifacts[item.relative_to(output).as_posix()] = digest(data)
        return data
    artifact(path)
    artifact(output / 'build/bootstrap/B3.image.bin')
    artifact(output / 'build/bootstrap/bootstrap.json')
    source = artifact(path.parent / module['source'])
    image = artifact(path.parent / module['image'])
    _compiled(output, path.parent, source, image, compiler, artifacts)
    standalone = module['standalone']
    elf = artifact(path.parent / standalone['path'])
    packer_name = 'filter_packer.hepta' if component == 'fence_json' else 'serde_filter_packer.hepta'
    packer_source = regular(root / 'native' / packer_name)
    cache = output / 'build/packers' / digest(packer_source)
    packer = artifact(cache / 'packer.image.bin')
    packer_info = json.loads(artifact(cache / 'manifest.json'))
    compile_receipt = json.loads(artifact(cache / 'packer.receipt.json'))
    packed_compile_output = artifact(cache / 'packer.output.bin')
    if (artifact(cache / 'source.hepta') != packer_source
            or artifact(cache / 'packer.input.bin') != packer_source
            or packer_info.get('source_sha256') != digest(packer_source)
            or packer_info.get('compiler_sha256') != digest(compiler)
            or packer_info.get('image_sha256') != digest(packer)
            or packer_info.get('compile_receipt') != compile_receipt
            or compile_receipt.get('produced_bytes') != len(packer)
            or compile_receipt.get('produced_sha256') != digest(packer)):
        raise ValueError('JSON actual HIA packer compilation evidence differs')
    native_receipt(compile_receipt, image=compiler, source=packer_source,
                   output=packed_compile_output, produced=packer)
    frame = b'HIAFLT01' + struct.pack('<Q', len(image)) + image
    packed = artifact(path.parent / 'pack.output.bin')
    receipt = json.loads(artifact(path.parent / 'pack.receipt.json'))
    if artifact(path.parent / 'pack.input.bin') != frame or receipt != standalone.get('pack_receipt'):
        raise ValueError('JSON actual HIA packing input/receipt differs')
    native_receipt(receipt, image=packer, source=frame, output=packed, produced=elf)
    return {'artifact_sha256': artifacts, 'manifest_sha256': digest(raw),
            'source_sha256': digest(source), 'image_sha256': digest(image), 'elf_sha256': digest(elf),
            'profile': config['profile'], 'capacities': list(config['capacities'])}


def native_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    root, output = root.resolve(), output.resolve()
    pins = source_inputs(root)
    artifacts, corpus, owners, tests = {}, {}, {}, {}
    for component, config in COMPONENTS.items():
        name = 'test_' + component + '.py'
        check, summary = completed_suite(root, output, report, completed, name, 7)
        built = build_evidence(root, output, report, component)
        folder = output / config['folder']
        manifest = relative(output, report['modules'][component]['manifest'])
        metadata = check_corpus(root, component, manifest, folder)
        if metadata != summary:
            raise ValueError('JSON corpus does not match the actual completed stdout: ' + component)
        observations = metadata.get('elf_observations')
        if not isinstance(observations, list) or len(observations) != 3:
            raise ValueError('JSON native suite omitted actual standalone processes')
        for row, expected in zip(observations, ELF_CASES[component]):
            if not same_json(row, {**expected, 'elf_sha256': built['elf_sha256']}):
                raise ValueError('JSON actual standalone request/result differs')
        artifacts.update(built['artifact_sha256'])
        for member in CORPUS_FILES:
            path = folder / member
            corpus[path.relative_to(output).as_posix()] = (stream_identity(path)[0]
                if member != 'native-corpus.json' else digest(regular(path)))
        owners[component] = {**built, 'cases': config['cases'], 'actual_native_calls': config['calls'],
                             'standalone_runs': 3, 'corpus': CORPUS_IDENTITIES[component]}
        tests[name] = {'stdout_sha256': check['stdout_sha256'], 'stderr_sha256': check['stderr_sha256']}
    name = 'test_serde_json_transport.py'
    check, transport = completed_suite(root, output, report, completed, name, 3)
    transport_bytes = regular(output / TRANSPORT_REPORT)
    expected_fields = {'schema': 'hepta.runtime.serde-filter-observation.v1',
        'source_sha256': owners['serde_json']['source_sha256'],
        'image_sha256': owners['serde_json']['image_sha256'], 'elf_sha256': owners['serde_json']['elf_sha256'],
        'packer_sha256': digest(regular(root / 'native/serde_filter_packer.hepta')),
        'qualification_inputs': pins, 'actual_elf_runs': 7}
    if transport != json.loads(transport_bytes) or any(transport.get(k) != v for k, v in expected_fields.items()):
        raise ValueError('JSON actual filter process report differs from completed stdout/source/image')
    runs = transport.get('runs')
    if not isinstance(runs, list) or len(runs) != len(TRANSPORT_CASES):
        raise ValueError('JSON filter process domain is incomplete')
    for actual, expected in zip(runs, TRANSPORT_CASES):
        if (not same_json({k: v for k, v in actual.items() if k != 'elapsed'}, expected)
                or type(actual.get('elapsed')) not in (float, int)
                or not math.isfinite(actual['elapsed']) or not 0 < actual['elapsed'] < 90):
            raise ValueError('JSON actual filter admission/result differs')
    corpus[TRANSPORT_REPORT] = digest(transport_bytes)
    tests[name] = {'stdout_sha256': check['stdout_sha256'], 'stderr_sha256': check['stderr_sha256']}
    for name, values in tests.items():
        artifacts[name + '.stdout'] = values['stdout_sha256']
        artifacts[name + '.stderr'] = values['stderr_sha256']
    return {'schema': 'hepta.runtime.json-native-evidence.v1', 'status': 'PASS',
            'owners': owners, 'qualification_inputs': pins, 'tests': tests,
            'artifact_sha256': artifacts, 'corpus_sha256': corpus,
            'actual_native_calls': 22918, 'actual_elf_runs': 13, 'captured_reference_cases': 22865,
            'native_cases_added_by_replay': 0, 'production_activated': False, 'whole_runtime_replaced': False}


def qualification_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    evidence = native_evidence(root, output, report, completed)
    name = 'test_json_evidence.py'
    check, summary = completed_suite(root, output, report, completed, name, 6)
    stored = regular(output / EVIDENCE_REPORT)
    expected = {'schema': 'hepta.runtime.json-evidence-controls.v1', 'status': 'PASS',
                'synthetic_receipt_controls': True, 'new_native_calls': 0,
                'source_inputs': source_inputs(root), 'counts': EVIDENCE_COUNTS}
    if not same_json(summary, json.loads(stored)) or not same_json(summary, expected):
        raise ValueError('JSON evidence mutation controls did not finish the complete domain')
    evidence['evidence_controls'] = summary['counts']
    evidence['corpus_sha256'][EVIDENCE_REPORT] = digest(stored)
    evidence['artifact_sha256'][name + '.stdout'] = check['stdout_sha256']
    evidence['artifact_sha256'][name + '.stderr'] = check['stderr_sha256']
    return evidence


def completed_reference_process(output: Path, report: dict, name: str):
    rows = [row for row in report['checks'] if row['name'] == name]
    if len(rows) != 1:
        raise ValueError('JSON reference requires exactly one actual completed process: ' + name)
    check = rows[0]
    stdout = regular(output / (name + '.stdout'))
    stderr = regular(output / (name + '.stderr'))
    if (check.get('exit_code') != 0 or type(check.get('exit_code')) is not int
            or check.get('timed_out') is not False or check.get('start_error')
            or check.get('timeout_seconds') != 180
            or check.get('stdout_sha256') != digest(stdout) or check.get('stdout_bytes') != len(stdout)
            or check.get('stderr_sha256') != digest(stderr) or check.get('stderr_bytes') != len(stderr)):
        raise ValueError('JSON actual reference process evidence differs: ' + name)
    return check, stdout, stderr


REFERENCE_BUILD_VARIABLES = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET')


def reference_environment(inherited: dict, rustc: Path) -> tuple[dict, list[str]]:
    env = dict(inherited)
    removed = [name for name in REFERENCE_BUILD_VARIABLES if name in env]
    for name in REFERENCE_BUILD_VARIABLES:
        env.pop(name, None)
    env['RUSTC'] = str(rustc)
    return env, removed


def reference_build(root: Path, output: Path, report: dict, completed) -> dict:
    build = report.get('json_reference_build')
    if not isinstance(build, dict):
        raise ValueError('JSON original Cargo build receipt is missing')
    check, stdout, stderr = completed_reference_process(output, report, 'json-rust-compile')
    command = [build['cargo'], 'build', '--locked', '--release', '--manifest-path',
               str(root / ORACLE / 'Cargo.toml'), '--target-dir', str(output / 'json-rust-reference/target')]
    binary = relative(output, build['executable'])
    if (check.get('command') != command or check.get('timeout_seconds') != 180
            or build.get('schema') != 'hepta.runtime.json-reference-build.v1'
            or build.get('qualification_inputs') != source_inputs(root)
            or build.get('executable') != 'json-rust-reference/target/release/hia-serde-json-reference'
            or build.get('executable_sha256') != digest(regular(binary))
            or build.get('cargo_sha256') != digest(regular(Path(build['cargo']).resolve()))
            or build.get('rustc_sha256') != digest(regular(Path(build['rustc']).resolve()))
            or build.get('build_environment_policy') != list(REFERENCE_BUILD_VARIABLES)
            or build.get('ignored_inherited_build_variables') != [
                name for name in REFERENCE_BUILD_VARIABLES if name in build.get('ignored_inherited_build_variables', [])]
            or build.get('compile_stdout_sha256') != check['stdout_sha256']
            or build.get('compile_stderr_sha256') != check['stderr_sha256']):
        raise ValueError('JSON actual locked Cargo compilation or executable custody differs')
    return build


def check_original_receipts(root: Path, output: Path, report: dict, completed) -> None:
    results = report.get('original_rust_comparisons', {})
    selected = [key for key in COMPONENTS if key in results]
    if not selected:
        if report.get('json_reference_build') is not None:
            raise ValueError('JSON shared Cargo build has no completed original replay')
        return
    build = reference_build(root, output, report, completed)
    for component in selected:
        expected = results[component]
        config = COMPONENTS[component]
        name = component.replace('_', '-') + '-rust-compare'
        check, output_bytes, stderr = completed_reference_process(output, report, name)
        native = regular(output / config['folder'] / 'native-output.txt')
        if (check.get('command') != [str(output / build['executable'])]
                or check.get('timeout_seconds') != 180 or stderr or output_bytes != native
                or expected != json.loads(regular(output / config['folder'] / 'rust-comparison.json'))
                or expected.get('schema') != 'hepta.runtime.json-original-rust-comparison.v1'
                or expected.get('status') != 'PASS' or expected.get('component') != component
                or expected.get('cases') != config['cases']
                or expected.get('original_output_sha256') != digest(output_bytes)
                or expected.get('native_output_sha256') != CORPUS_IDENTITIES[component]['native_output_sha256']
                or expected.get('requests_sha256') != CORPUS_IDENTITIES[component]['requests_sha256']
                or expected.get('executable_sha256') != build['executable_sha256']
                or expected.get('reference_build') != build
                or expected.get('stdout_sha256') != check['stdout_sha256']
                or expected.get('stderr_sha256') != check['stderr_sha256']
                or check.get('stdin_sha256') != CORPUS_IDENTITIES[component]['requests_sha256']
                or check.get('stdin_bytes') != CORPUS_IDENTITIES[component]['requests_bytes']
                or expected.get('native_cases_added_by_replay') != 0):
            raise ValueError('JSON full actual original replay or retained bytes differ: ' + component)


def compare_original(root: Path, output: Path, report: dict, rustc: Path, cargo: Path,
                     component: str, *, completed, record_check, environment) -> dict:
    evidence = qualification_evidence(root, output, report, completed)
    if evidence != report.get('json_evidence'):
        raise ValueError('JSON completed native evidence changed before original replay')
    if report.get('json_reference_build') is None:
        folder = output / 'json-rust-reference'
        folder.mkdir(mode=0o700)
        env, removed = reference_environment(environment(), rustc)
        cargo_sha = digest(regular(cargo.resolve()))
        rustc_sha = digest(regular(rustc.resolve()))
        command = [str(cargo), 'build', '--locked', '--release', '--manifest-path',
                   str(root / ORACLE / 'Cargo.toml'), '--target-dir', str(folder / 'target')]
        record_check(output, report, name='json-rust-compile', command=command, env=env, timeout=180)
        check, stdout, stderr = completed_reference_process(output, report, 'json-rust-compile')
        binary = folder / 'target/release/hia-serde-json-reference'
        report['json_reference_build'] = {
            'schema': 'hepta.runtime.json-reference-build.v1', 'cargo': str(cargo), 'rustc': str(rustc),
            'cargo_sha256': cargo_sha, 'rustc_sha256': rustc_sha,
            'build_environment_policy': list(REFERENCE_BUILD_VARIABLES),
            'ignored_inherited_build_variables': removed,
            'executable': binary.relative_to(output).as_posix(), 'executable_sha256': digest(regular(binary)),
            'qualification_inputs': source_inputs(root), 'compile_stdout_sha256': check['stdout_sha256'],
            'compile_stderr_sha256': check['stderr_sha256']}
    build = reference_build(root, output, report, completed)
    config = COMPONENTS[component]
    folder = output / config['folder']
    wire = regular(folder / 'requests.hex')
    expected = regular(folder / 'native-output.txt')
    name = component.replace('_', '-') + '-rust-compare'
    row = record_check(output, report, name=name, command=[str(output / build['executable'])],
                       input_bytes=wire, env=environment(), timeout=180)
    if row.stderr or row.stdout != expected:
        raise ValueError('JSON original locked serde replay differs: ' + component)
    check, stdout, stderr = completed_reference_process(output, report, name)
    check.update(stdin_sha256=digest(wire), stdin_bytes=len(wire))
    if (reference_build(root, output, report, completed) != build
            or qualification_evidence(root, output, report, completed) != evidence):
        raise ValueError('JSON original/native inputs changed during actual Rust replay')
    result = {'schema': 'hepta.runtime.json-original-rust-comparison.v1', 'status': 'PASS',
        'component': component, 'cases': config['cases'], 'requests_sha256': digest(wire),
        'native_output_sha256': digest(expected), 'original_output_sha256': digest(row.stdout),
        'executable_sha256': build['executable_sha256'], 'reference_build': build,
        'stdout_sha256': check['stdout_sha256'], 'stderr_sha256': check['stderr_sha256'],
        'reference_kind': ('unchanged OwnerDocument/LegacyJobKey derives with original locked serde dependencies'
            if component == 'fence_json' else 'original locked serde_json Value/Number with float_roundtrip and zmij'),
        'native_cases_added_by_replay': 0, 'production_activated': False, 'whole_runtime_replaced': False}
    with (folder / 'rust-comparison.json').open('x') as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


ELF_CASES = {'fence_json': [{'exit_code': 0,
                 'input_bytes': 108,
                 'input_sha256': '5097dbf1a0a68ac325e3fe5c75932f63425b1c78934b94c151067091f5912b7a',
                 'output_bytes': 151,
                 'output_sha256': '07062d7bf46f934693ada59484becd86b4760dc06c3001a37ce4f1acb2e9ed85',
                 'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                {'exit_code': 0,
                 'input_bytes': 50,
                 'input_sha256': '4f94c6007b82335be05149ee8b85dcca23d5f028bff3daf08bf8d4eab557f9d0',
                 'output_bytes': 135,
                 'output_sha256': '0c8a3a1143cd4c55c9956d98a9b6432326ce175d52d7ced24b6b25df005d4007',
                 'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                {'exit_code': 0,
                 'input_bytes': 84,
                 'input_sha256': 'a449d73ba887d6444cc681add3203a3ce980ecd1f1f07ec89aac4cf650356bb8',
                 'output_bytes': 143,
                 'output_sha256': '8c894327cf8b1af0e5026ba055224aceb6c7e85b869d5b78dd851c75e9da69a8',
                 'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}],
 'serde_json': [{'exit_code': 0,
                 'input_bytes': 47,
                 'input_sha256': 'e7d2aead36ebb2736f82f3d00657703d2da19c95546dafc5a40b1031f0761541',
                 'output_bytes': 30,
                 'output_sha256': '546d1cd44eccd536dfcaff2f1cd4354563e72c1b13654e32a55da6be53999139',
                 'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                {'exit_code': 0,
                 'input_bytes': 44,
                 'input_sha256': '0a884929cdc7f63068da28aee512ab69bdb0a469c0ae58740f016dd04d09fb48',
                 'output_bytes': 16,
                 'output_sha256': '7bd6c46da2db26a3909bd42ed31848177a04ee8c63b0127006bc7435a58d5947',
                 'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
                {'exit_code': 0,
                 'input_bytes': 32,
                 'input_sha256': '1ab5a4abe8b87511493372c9d9a5157fceb2620e949a6f12ef4838ddd4eec360',
                 'output_bytes': 6,
                 'output_sha256': 'c46e7ca1be4c8734f373a56530787288fa2058d73d07855e9247e949f811a42a',
                 'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}]}
TRANSPORT_CASES = [{'case': '8MiB-input-31876700-byte-result',
  'exit_code': 0,
  'input_bytes': 8388632,
  'input_sha256': '0c9dc1ef7d7c1ab3cef8b7a5399ce402844226b9a7cc6c0f36279867887c27d2',
  'output_bytes': 31876700,
  'output_sha256': 'c57173f956ff33a2020d0055812f5dcefa9e452cb0b68cf50320b4d023d4fbc3',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 {'case': 'malformed-frame',
  'exit_code': 2,
  'input_bytes': 8,
  'input_sha256': '249af67014134037b1a83a04b4b7e9e3540b228e16cb3aab84975d23b81a81b7',
  'output_bytes': 0,
  'output_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 {'case': 'module-eight-mib-limit',
  'exit_code': 2,
  'input_bytes': 8388633,
  'input_sha256': 'b2af05a38efc970e78658b7c56c3ada333d7b9a18f8f4fff9d90dbb98f79c814',
  'output_bytes': 0,
  'output_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 {'case': 'transport-sixteen-mib-plus-one',
  'exit_code': 3,
  'input_bytes': 16777217,
  'input_sha256': '2b818dc07b8a40bde72f742d0d7b43dd14a118ba98d47dae563f0b9ff5b89227',
  'output_bytes': 0,
  'output_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 {'case': 'closed-cli',
  'exit_code': 64,
  'input_bytes': 28,
  'input_sha256': '638d310a4cfe773e9346c628326cfa64f4f3d6fc56379a4000f4412095877512',
  'output_bytes': 0,
  'output_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 {'case': 'nonfinite-f64-refusal',
  'exit_code': 2,
  'input_bytes': 32,
  'input_sha256': '99821a8c59bfa2c3cd90516923f6c138a776570a69a538a158b66c7999b8f61a',
  'output_bytes': 0,
  'output_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 {'case': 'fresh-success',
  'exit_code': 0,
  'input_bytes': 37,
  'input_sha256': '10df3cf36ff2ae2d32636bc4774c002e9b269c49f62dc483786181ab95a742c8',
  'output_bytes': 7,
  'output_sha256': '015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862',
  'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}]
EVIDENCE_COUNTS = {'actual_capture': 1,
 'completion_refusals': 30,
 'source_refusals': 6,
 'artifact_refusals': 10,
 'corpus_refusals': 11,
 'transport_refusals': 8}
