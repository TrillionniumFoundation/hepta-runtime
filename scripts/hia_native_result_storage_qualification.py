# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Closed build and actual-process admission for the private storage owners."""
from pathlib import Path
import json
import os
import signal
import struct
import subprocess
import sys
import time

from result_storage_registry import (COMPILER, COMPILER_IMAGE, build_sources, encoded,
    profile, regular, require, sha)
from build_result_storage import inspect_elf, source_composition

PURE = ('storage_json', 'record_validation', 'safe_dto', 'retention')
FS = ('record_io', 'record_io_faults', 'directory', 'archive_metadata', 'archive_metadata_faults',
    'archive_publish', 'archive_publish_faults', 'archive_store', 'archive_store_faults')
GRAPHS = {name: name.removesuffix('_faults').removeprefix('archive_') for name in FS}
TEST_DIR = 'tests/hia_native'
SUMMARY_FIELDS = {
    'storage_json': {'compared_cases': 4221, 'controls_passed': 21, 'native_entries': 4242,
        'accepted': 3352, 'native_standalone_processes': 3, 'retained_reference_cases': 4221},
    'record_validation': {'compared_cases': 9361, 'controls_passed': 45,
        'actual_owner_entries': 25814, 'retained_reference_cases': 9361},
    'safe_dto': {'compared_cases': 5587, 'typed_cases': 5043, 'platform_cases': 544,
        'controls_passed': 27, 'actual_native_entries': 19398, 'retained_reference_cases': 5591,
        'actual_config_child_calls': 4491, 'actual_config_process_requests': 5035,
        'actual_value_child_calls': 9837},
    'retention': {'compared_cases': 6287, 'controls_passed': 42, 'retained_reference_cases': 6315,
        'actual_native_entries': 71230, 'actual_config_process_requests': 5145},
}
OBSERVER = {'status', 'native_result_code', 'source_unchanged', 'manifest_sha256',
    'input_sha256', 'input_bytes', 'output_sha256', 'output_bytes', 'output_capacity',
    'workspace_capacity', 'elapsed_nanoseconds', 'forbidden_compiler_modules_loaded'}


def object_at(path):
    value = json.loads(regular(path))
    require(type(value) is dict, 'expected a retained object: ' + str(path))
    return value


def pin(path):
    raw = regular(path)
    return {'bytes': len(raw), 'sha256': sha(raw)}


def confined(root, relative):
    path = Path(relative)
    require(not path.is_absolute() and '..' not in path.parts, 'unconfined storage observation')
    path = Path(root) / path
    require(path.resolve(strict=True).is_relative_to(Path(root).resolve(strict=True)), 'observation escaped root')
    return path


def source_pins(root):
    root = Path(root)
    names = set(build_sources(root))
    names.update(('scripts/hia_native_result_storage_qualification.py',
        'scripts/result_storage_native_evidence.py', 'Cargo.lock', 'Cargo.toml',
        'scripts/hia_native_result_storage_reference.py', 'scripts/hia_native_result_reference.py',
        'scripts/result_value_registry.py', 'native/sdk_rmcp_source_manifest.json',
        'tests/hia_native/run_result_storage_native.py', 'tests/hia_native/compare_result_storage_original.py',
        'native/result_storage_test_derivation.json', 'tests/hia_native/test_request_result.py',
        'tests/hia_native/result_value_cases.py', 'tests/hia_native/result_value_fixture.py',
        'native/filter_packer.hepta'))
    for pattern in ('test_result_*.py', 'result_fs_*.py', 'result_archive_*.py', 'result_directory_cases.py',
            'result_storage_*.py', 'result_record_*.py', 'result_safe_dto_cases.py', 'result_retention_cases.py'):
        names.update(str(path.relative_to(root)) for path in (root / TEST_DIR).glob(pattern))
    for directory in ('result_storage_reference', 'fixtures/result_storage_reference'):
        names.update(str(path.relative_to(root)) for path in (root / TEST_DIR / directory).rglob('*') if path.is_file())
    names.update(TEST_DIR + '/fixtures/retention-records-v2' + suffix for suffix in ('.json', '.jsonl.xz'))
    return {name: pin(root / name) for name in sorted(names)}


def run_process(root, folder, command, *, environment=None, timeout=180):
    """One owned group, unchanged 180-second deadline and three-second cleanup."""
    root, folder = Path(root), Path(folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    start = time.monotonic()
    row = {'command': list(map(str, command)), 'cwd': str(root), 'timeout_seconds': timeout,
        'cleanup_seconds': 3, 'timed_out': False, 'exit_code': None, 'process_reaped': False,
        'outer_parent_death_cleanup_qualified': False}
    process = None
    try:
        with (folder / 'stdout').open('xb') as out, (folder / 'stderr').open('xb') as err:
            process = subprocess.Popen(row['command'], cwd=root, env=environment, stdout=out,
                stderr=err, stdin=subprocess.DEVNULL, start_new_session=True)
            row['pid'] = process.pid
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            row.update(exit_code=process.returncode, process_reaped=True)
    except BaseException as error:
        row['error'] = repr(error)
        raise
    finally:
        # Cargo and reference controllers may leave descendants after the
        # direct child exits or fails. Retire the same owned group on every
        # return path, not only when this outer deadline fires.
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.returncode is None:
                process.wait(timeout=3)
                row.update(exit_code=process.returncode, process_reaped=True)
        row['elapsed_seconds'] = time.monotonic() - start
        for stream in ('stdout', 'stderr'):
            if (folder / stream).exists():
                row[stream] = pin(folder / stream)
        (folder / 'result.json').write_bytes(encoded(row))
    require(row['exit_code'] == 0 and not row['timed_out'] and row['process_reaped'],
        'actual storage process did not complete: ' + str(folder))
    return row


def process_evidence(folder, command, root, timeout=180):
    folder = Path(folder)
    row = object_at(folder / 'result.json')
    require(row.get('command') == list(map(str, command)) and row.get('cwd') == str(root)
        and row.get('timeout_seconds') == timeout and row.get('cleanup_seconds') == 3
        and row.get('exit_code') == 0 and row.get('timed_out') is False
        and row.get('process_reaped') is True, 'actual process receipt is incomplete or changed')
    for stream in ('stdout', 'stderr'):
        require(row[stream] == pin(folder / stream), 'actual process stream changed')
    return row, regular(folder / 'stdout'), regular(folder / 'stderr')


def compilation(root, build, spec, reference, artifacts):
    manifest = confined(build, reference['path']);directory = manifest.parent
    require(pin(manifest)['sha256'] == reference['sha256'], 'module manifest differs')
    metadata = object_at(manifest)
    require(metadata.get('schema') == 'hepta.runtime.native-module.v1'
        and metadata.get('compiler_commit') == COMPILER and metadata.get('compiler_sha256') == COMPILER_IMAGE
        and metadata.get('source_sha256') == spec['source_sha256']
        and metadata.get('image_sha256') == spec['image_sha256']
        and metadata.get('buffer_profile', 'standard') == spec['buffer_profile'], 'compiled image identity differs')
    source = regular(confined(directory, metadata['source']))
    image = regular(confined(directory, metadata['image']))
    require(source == regular(root / spec['source']) and sha(source) == spec['source_sha256']
        and sha(image) == spec['image_sha256'], 'retained image/source differs')
    observed = object_at(directory / 'module.stdout.log')
    receipt = object_at(directory / 'module.receipt.json')
    built = object_at(directory / 'build.json');request = object_at(directory / 'module.request.json')
    incoming, outgoing = regular(directory / 'module.input.bin'), regular(directory / 'module.output.bin')
    required = {'status', 'abi_status', 'core_u32', 'result_u64', 'source_unchanged',
        'source_sha256', 'output_sha256', 'image_sha256', 'forbidden_compiler_modules_loaded'}
    require(set(observed) >= required and not regular(directory / 'module.stderr.log')
        and all(receipt.get(k) == v for k, v in observed.items()) and built['compile_receipt'] == receipt,
        'actual native compiler observer differs')
    require(receipt.get('status') == 'returned' and receipt.get('abi_status') == 0
        and receipt.get('source_unchanged') is True and receipt.get('forbidden_compiler_modules_loaded') == []
        and receipt.get('source_sha256') == receipt.get('input_sha256') == spec['source_sha256']
        and receipt.get('produced_sha256') == spec['image_sha256']
        and receipt.get('core_u32') == receipt.get('result_u64') == receipt.get('produced_bytes') == len(image)
        and receipt.get('image_sha256') == COMPILER_IMAGE
        and built.get('compiler_dependency', {}).get('commit') == COMPILER,
        'actual native compiler call is incomplete')
    require(incoming == source and outgoing[:len(image)] == image and sha(outgoing) == receipt['output_sha256']
        and len(outgoing) == request.get('capacity') == 1048576
        and request.get('image_sha256') == COMPILER_IMAGE and request.get('source_sha256') == sha(source),
        'complete native compiler buffers differ')
    if spec['standalone'] is None:
        require(metadata['standalone'] is None, 'unexpected standalone transport')
    else:
        require(spec['standalone'] == 'filter' and spec['buffer_profile'] == 'standard', 'unknown storage transport')
        packed = metadata['standalone'];elf = regular(confined(directory, packed['path']))
        pack_observed = object_at(directory / 'pack.stdout.log')
        pack_receipt = object_at(directory / 'pack.receipt.json')
        frame = regular(directory / 'pack.input.bin');full = regular(directory / 'pack.output.bin')
        packer_source = regular(root / 'native/filter_packer.hepta')
        cache = build / 'packers' / sha(packer_source)
        packer_metadata = object_at(cache / 'manifest.json')
        packer = regular(cache / 'packer.image.bin')
        compiler_observed = object_at(cache / 'packer.stdout.log')
        compiler_receipt = object_at(cache / 'packer.receipt.json')
        compiler_request = object_at(cache / 'packer.request.json')
        compiler_output = regular(cache / 'packer.output.bin')
        require(packer_metadata['compile_receipt'] == compiler_receipt and set(compiler_observed) >= required
            and all(compiler_receipt.get(key) == value for key, value in compiler_observed.items())
            and not regular(cache / 'packer.stderr.log')
            and regular(cache / 'source.hepta') == regular(cache / 'packer.input.bin') == packer_source
            and compiler_receipt.get('status') == 'returned' and compiler_receipt.get('abi_status') == 0
            and compiler_receipt.get('source_unchanged') is True
            and compiler_receipt.get('forbidden_compiler_modules_loaded') == []
            and compiler_receipt.get('source_sha256') == compiler_receipt.get('input_sha256') == sha(packer_source)
            and compiler_receipt.get('image_sha256') == packer_metadata['compiler_sha256'] == COMPILER_IMAGE
            and compiler_receipt.get('produced_sha256') == packer_metadata['image_sha256'] == sha(packer)
            and compiler_receipt.get('produced_bytes') == compiler_receipt.get('core_u32')
                == compiler_receipt.get('result_u64') == len(packer)
            and compiler_receipt.get('output_sha256') == sha(compiler_output)
            and compiler_output[:len(packer)] == packer
            and len(compiler_output) == compiler_request.get('capacity') == 1048576
            and compiler_request.get('image_sha256') == COMPILER_IMAGE
            and compiler_request.get('source_sha256') == sha(packer_source),
            'actual native standalone packer compilation is incomplete')
        require(frame == b'HIAFLT01' + struct.pack('<Q', len(image)) + image
            and pack_receipt == packed['pack_receipt'] and set(pack_observed) >= required
            and all(pack_receipt.get(k) == v for k, v in pack_observed.items())
            and not regular(directory / 'pack.stderr.log'), 'actual standalone packing receipt differs')
        require(pack_receipt['status'] == 'returned' and pack_receipt['abi_status'] == 0
            and pack_receipt['source_unchanged'] is True and pack_receipt['forbidden_compiler_modules_loaded'] == []
            and pack_receipt['input_sha256'] == sha(frame) and pack_receipt['output_sha256'] == sha(full)
            and pack_receipt['core_u32'] == pack_receipt['result_u64'] == len(elf)
            and full[:len(elf)] == elf and elf.endswith(image)
            and packed['sha256'] == sha(elf) and packed['packer_source_sha256'] == sha(packer_source)
            and pack_receipt['image_sha256'] == sha(packer)
            and packer_metadata['source_sha256'] == sha(packer_source), 'actual standalone bytes differ')
        for path in cache.iterdir():
            if path.is_file():
                artifacts[str(path.relative_to(build))] = pin(path)
    for path in directory.iterdir():
        if path.is_file():
            artifacts[str(path.relative_to(build))] = pin(path)
    return metadata, image


def build_evidence(root, build, *, hepta=None, require_process=True):
    root, build = Path(root).resolve(strict=True), Path(build).resolve(strict=True)
    fixed = profile(root);bundle = object_at(build / 'result-storage-build.json');artifacts = {}
    require(bundle['sources'] == build_sources(root) and bundle['compiler_commit'] == COMPILER
        and bundle['compiler_sha256'] == COMPILER_IMAGE and set(bundle['modules']) == set(fixed['modules'])
        and set(bundle['graphs']) == set(fixed['graphs']) and bundle['actual_original_executions'] == 0,
        'fixed storage build domain changed')
    images = {};manifests = {}
    for name, spec in fixed['modules'].items():
        manifests[name], images[name] = compilation(root, build, spec, bundle['modules'][name], artifacts)
    for name, graph in fixed['graphs'].items():
        manifest = confined(build, bundle['graphs'][name]['path'])
        require(pin(manifest)['sha256'] == bundle['graphs'][name]['sha256'], 'graph manifest changed')
        row = object_at(manifest);folder = manifest.parent
        layout_raw = regular(root / graph['layout']);layout = json.loads(layout_raw)
        require(sha(layout_raw) == graph['layout_sha256'], 'native boundary layout changed')
        prefix = bytes.fromhex(layout['prefix_hex'])
        require(sha(prefix) == layout['prefix_sha256'], 'native boundary bytes changed')
        if name == 'configuration':
            order = graph['members']
            holes = {key: value['call_displacement_offset'] for key, value in
                zip(order, layout['original_bundle']['members'], strict=True)}
        else:
            order = [graph['members'][key] for key in layout['image_order']]
            holes = {graph['members'][key]: value for key, value in layout['call_holes'].items()}
        elf = regular(confined(folder, row['executable']))
        require(row['members'] == inspect_elf(elf, prefix, images, order, holes)
            and row['executable_sha256'] == sha(elf) and row['executable_bytes'] == len(elf),
            'actual embedded images or fixed call graph changed')
        frame = graph['magic'].encode() + b''.join(struct.pack('<Q', len(images[key])) for key in order)
        frame += bytes(8 * graph.get('reserved_words', 0)) + b''.join(images[key] for key in order)
        require(regular(folder / 'pack.input.bin') == frame and row['input_sha256'] == sha(frame),
            'complete fixed packer input changed')
        packer = bundle['modules'][graph['packer']]
        command = [sys.executable, '-I', '-B', str(root / 'scripts/result_storage_pack_child.py'),
            '--graph', name, '--manifest', str(confined(build, packer['path'])),
            '--input', str(folder / 'pack.input.bin'), '--output', str(folder / row['executable'])]
        receipt = object_at(folder / 'pack-process.json')
        out, err = regular(folder / 'pack.stdout'), regular(folder / 'pack.stderr')
        require(receipt['command'] == command and receipt['cwd'] == str(root)
            and receipt['timeout_seconds'] == 30 and receipt['exit_code'] == 0
            and receipt['timed_out'] is False and receipt['start_error'] is None and not err
            and (receipt['stdout_bytes'], receipt['stdout_sha256']) == (len(out), sha(out))
            and (receipt['stderr_bytes'], receipt['stderr_sha256']) == (len(err), sha(err)),
            'actual packer process is incomplete')
        observed = json.loads(out)
        require(set(observed) == OBSERVER and observed['status'] == 'returned'
            and observed['native_result_code'] == observed['output_bytes'] == observed['output_capacity'] == len(elf)
            and observed['manifest_sha256'] == packer['sha256'] and observed['input_sha256'] == sha(frame)
            and observed['input_bytes'] == len(frame) and observed['output_sha256'] == sha(elf)
            and observed['workspace_capacity'] == 4096 and observed['source_unchanged'] is True
            and observed['forbidden_compiler_modules_loaded'] == [], 'actual packer observer differs')
        for path in folder.iterdir():
            if path.is_file():
                artifacts[str(path.relative_to(build))] = pin(path)
    if hepta is not None:
        require(bundle['composition'] == source_composition(root, Path(hepta)), 'actual imported function closure differs')
    for name in ('B1.image.bin', 'B2.image.bin', 'B3.image.bin'):
        path = build / 'bootstrap' / name
        require(sha(regular(path)) == COMPILER_IMAGE, 'native compiler fixed point changed')
        artifacts[str(path.relative_to(build))] = pin(path)
    if require_process:
        command = [sys.executable, '-I', '-B', str(root / 'scripts/build_result_storage.py'),
            '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
        _, out, err = process_evidence(build / 'result-storage-build-process', command, root)
        require(not err and json.loads(out) == {'build': str(build / 'result-storage-build.json'),
            'modules': 30, 'static_graphs': 6, 'actual_original_executions': 0}, 'actual build summary differs')
        for path in (build / 'result-storage-build-process').iterdir():
            artifacts[str(path.relative_to(build))] = pin(path)
    artifacts['result-storage-build.json'] = pin(build / 'result-storage-build.json')
    return {'schema': 'hepta.result-storage.build-evidence.v1', 'modules': manifests,
        'bundle': bundle, 'artifact_pins': artifacts, 'new_native_executions': 0,
        'new_original_executions': 0, 'fresh_full_cold_qualified': False}


def build_storage(hepta, build, root):
    root, build = Path(root).resolve(strict=True), Path(build).resolve()
    build.mkdir(parents=True, exist_ok=True)
    before = source_pins(root)
    command = [sys.executable, '-I', '-B', str(root / 'scripts/build_result_storage.py'),
        '--hepta', str(Path(hepta).resolve(strict=True)), '--build-root', str(build)]
    run_process(root, build / 'result-storage-build-process', command,
        environment={key: value for key, value in os.environ.items() if not key.startswith('HIA_')})
    require(source_pins(root) == before, 'sources changed during complete native build')
    return build_evidence(root, build, hepta=hepta)


def commands(root, build, output):
    root, build, output = map(Path, (root, build, output))
    bundle = object_at(build / 'result-storage-build.json')
    module = lambda name: confined(build, bundle['modules'][name]['path'])
    graph = lambda name: confined(build, bundle['graphs'][name]['path'])
    configuration = graph('configuration')
    configuration = configuration.parent / object_at(configuration)['executable']
    arguments = {
        'storage_json': ['--manifest', module('storage_json')],
        'record_validation': ['--manifest', module('record_validation'), '--json-manifest', module('storage_json'),
            '--codec-manifest', module('codec')],
        'safe_dto': ['--manifest', module('safe_dto'), '--value-manifest', module('value'), '--config-elf', configuration],
        'retention': ['--manifest', module('retention'), '--value-manifest', module('value'),
            '--typed-manifest', module('typed'), '--metadata-manifest', module('request'),
            '--dto-manifest', module('safe_dto'), '--codec-manifest', module('codec'), '--config-elf', configuration],
    }
    result = {}
    for domain in PURE:
        result[domain] = list(map(str, [sys.executable, '-I', '-B', root / TEST_DIR / ('test_result_' + domain + '.py'),
            *arguments[domain], '--runtime', root, '--output', output / domain]))
    for domain in FS:
        path = graph(GRAPHS[domain]);executable = path.parent / object_at(path)['executable']
        result[domain] = list(map(str, [sys.executable, '-I', '-B', root / TEST_DIR / 'test_result_storage_fs.py',
            '--domain', domain, '--phase', 'native', '--executable', executable, '--output', output / domain]))
    return result


def domain_evidence(root, build, output, domain):
    """Validate a full native domain; this function never executes an owner."""
    from result_storage_native_evidence import inventory, profile_domain, simple, test_module
    root, build, output = map(Path, (root, build, output))
    require(domain in PURE + FS, 'unknown result storage native domain')
    folder = output / domain;report = object_at(folder / 'result.json')
    bundle = object_at(build / 'result-storage-build.json')
    module = lambda name: object_at(confined(build, bundle['modules'][name]['path']))
    require(report.get('status') == 'PASS' and type(report.get('elapsed_seconds')) in (int, float)
        and 0 <= report['elapsed_seconds'] <= 180, 'native domain is not a complete bounded observation')
    require(all(report.get(key) is False for key in ('whole_runtime_replaced', 'production_activated',
        'old_stack_removal_qualified')), 'private evidence expanded its production scope')
    if domain in PURE:
        require(all(report.get(key) == value for key, value in SUMMARY_FIELDS[domain].items())
            and report.get('reference_kind') == 'retained-original-fixture'
            and report.get('actual_original_requests', report.get('actual_original_cases')) == 0
            and len(report['controls']) == report['controls_passed']
            and all(row.get('passed') is True for row in report['controls']),
            'native semantic or negative-control domain differs')
        expected = {
            'record_validation': {'owner': module('record_validation'), 'typed_json': module('storage_json'),
                'binary_codec': module('codec')},
            'safe_dto': {'owner': module('safe_dto'), 'value': module('value')},
            'retention': {'owner': module('retention'), 'value': module('value'), 'typed': module('typed'),
                'metadata': module('request'), 'dto': module('safe_dto'), 'codec': module('codec')},
        }
        require(report.get('module') == module(domain) if domain == 'storage_json'
            else report.get('modules') == expected[domain], 'native test did not execute the admitted images')
        if domain in ('storage_json', 'record_validation'):
            corpus = simple(root, domain, folder, report)
        else:
            manifest = confined(build, bundle['graphs']['configuration']['path'])
            executable = manifest.parent / object_at(manifest)['executable']
            require(report['config_executable'] == pin(executable), 'native configuration executable changed')
            corpus = profile_domain(root, domain, folder, report, executable)
            raw_value = test_module(root, 'result_storage_raw_value')
            require(report.get('raw_value_extension') == raw_value.native_evidence(
                root, domain, folder / 'raw-value', executable), 'complete RawValue storage extension differs')
        require(corpus['cases'] == report['compared_cases']
            and corpus['reference_requests'] == report['retained_reference_cases'], 'complete native corpus counts differ')
        if domain == 'storage_json':
            cases = test_module(root, 'result_storage_json_cases')
            metadata = module('storage_json')
            manifest = confined(build, bundle['modules']['storage_json']['path'])
            executable = manifest.parent / metadata['standalone']['path']
            require(len(report['processes']) == 3, 'actual standalone domain is incomplete')
            for kind, value in enumerate((cases.RECORD, cases.ANCHOR, cases.MARKER), 1):
                name = 'native-elf-' + str(kind);row = object_at(folder / (name + '.process.json'))
                wire = cases.frame(kind, cases.encoded(value))
                require(row == report['processes'][kind - 1] and row['command'] == [str(executable)]
                    and row['exit_code'] == 0 and row['reaped'] is True and row['timed_out'] is False
                    and row['timeout_seconds'] == 180, 'actual standalone process is incomplete')
                for channel in ('stdin', 'stdout', 'stderr'):
                    raw = regular(folder / (name + '.' + channel))
                    require((row[channel + '_bytes'], row[channel + '_sha256']) == (len(raw), sha(raw))
                        and (channel != 'stdin' or raw == wire) and (channel != 'stderr' or not raw),
                        'actual standalone full stream changed')
                matching = [line for (label, item), line in zip(cases.cases(),
                    regular(folder / 'native.stdout').splitlines(), strict=True) if item == wire]
                require(matching and all(line == matching[0] for line in matching)
                    and regular(folder / (name + '.stdout')) == bytes.fromhex(matching[0].split(b':')[1].decode()),
                    'actual standalone output differs from the complete native corpus')
    else:
        test = test_module(root, 'test_result_storage_fs')
        require(test.admit_capture(folder, domain) == report, 'complete filesystem capture differs')
        manifest = confined(build, bundle['graphs'][GRAPHS[domain]]['path'])
        executable = manifest.parent / object_at(manifest)['executable']
        require(report['executable'] == test.pin(executable) and report['source_unchanged'] is True
            and report['phase'] == 'native' and report['semantic_reference_comparison_complete'] is False
            and report['new_original_processes'] == 0 and report['new_native_processes'] == report['processes'],
            'filesystem observation did not execute the admitted native graph')
        count, requests, processes, killed = test.DOMAINS[domain][2:]
        require((report['case_count'], report['requests'], report['processes'], report['deliberately_killed_requests'])
            == (count, requests, processes, killed), 'complete filesystem process domain differs')
        corpus = {'cases': count, 'requests': requests, 'processes': processes,
            'deliberately_killed_requests': killed, 'complete_response_bytes': sum(
                row['complete_output']['bytes'] for row in report['cases'])}
    return {'domain': domain, 'result': report, 'corpus': corpus, 'artifacts': inventory(folder),
        'new_native_executions': 0, 'new_original_executions': 0}


def summary_from_report(domain, report):
    if domain in FS:
        keys = ('schema', 'status', 'phase', 'domain', 'case_count', 'requests', 'processes',
            'deliberately_killed_requests', 'new_original_processes', 'new_native_processes',
            'semantic_reference_comparison_complete', 'elapsed_seconds')
        return {key: report[key] for key in keys}
    omit = {
        'storage_json': ('cases', 'controls', 'module', 'processes'),
        'record_validation': ('cases', 'controls', 'modules', 'original_process'),
        'safe_dto': ('profiles', 'controls', 'modules', 'startup_refusals'),
        'retention': ('profiles', 'controls', 'modules', 'startup_refusals'),
    }[domain]
    return {key: value for key, value in report.items() if key not in omit}


def native_evidence(root, build, output, completed):
    """Bind all thirteen complete streams to externally observed bounded processes.

    ``completed`` maps each fixed domain to its actual outer process receipt
    directory. A historical or self-declared domain report is insufficient.
    """
    root, build, output = (Path(path).resolve(strict=True) for path in (root, build, output))
    require(set(completed) == set(PURE + FS), 'actual native process set differs')
    compiled = build_evidence(root, build, require_process=False)
    expected = commands(root, build, output);domains = {};artifacts = {}
    for domain in PURE + FS:
        result = domain_evidence(root, build, output, domain)
        directory = Path(completed[domain]).resolve(strict=True)
        row, stdout, stderr = process_evidence(directory, expected[domain], root)
        require(not stderr and json.loads(stdout) == summary_from_report(domain, result['result']),
            'actual completed native stdout differs from its complete report')
        domains[domain] = {'corpus': result['corpus'], 'result_sha256': pin(output / domain / 'result.json')['sha256'],
            'process': row, 'process_directory': str(directory), 'artifacts': result['artifacts']}
        for name in ('result.json', 'stdout', 'stderr'):
            artifacts[str(directory / name)] = pin(directory / name)
    return {'schema': 'hepta.result-storage.native-evidence.v1', 'sources': source_pins(root),
        'build_artifacts': compiled['artifact_pins'],
        'domains': domains, 'process_artifacts': artifacts, 'actual_original_executions': 0,
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'whole_runtime_replaced': False, 'production_activated': False, 'result_storage_closed': False}
