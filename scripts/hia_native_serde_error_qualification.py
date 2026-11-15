# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind completed native diagnostics, real compile/pack receipts and full corpus.

This module performs no JSON diagnostic semantics. It verifies retained bytes.
The production parser and formatter are native/serde_error.hepta.
"""
from __future__ import annotations
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time

COMMIT = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
TREE = '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
SOURCE = '14eea1ebc4bd12cb10e961d61bea58dded9befb15a3c67191fe6301577bc00e9'
IMAGE = '1ccbbb66c5a1946c87295ce2bd89c17e9592730885123c903a3f1a0fcea6918f'
EXECUTABLE = 'e81e11de9b69d67bfda73e0deeacc3dd1e1cff8371d2026ad17e4c9342400a84'
PACKER = '9f36fa06de096e0e49c97154528cdae2ad2f226b7b118617faea514ea8d5aa75'
PACKER_IMAGE = 'c713476415e790bfe64912a64d6f154b096e900427c38d23d9441b09e6370444'
TEST_DIR = 'tests/hia_native/serde_error'
SUITES = {'base': 'test_serde_error.py', 'resources': 'test_serde_error_resources.py'}
SOURCE_FILES = (
    'native/serde_error.hepta', 'native/serde_error_abi.md',
    'native/serde_error_composition.json', 'native/serde_error_reference.json',
    'native/serde_error_corpus_contract.json',
    'scripts/author_serde_error.py', 'scripts/serde_error_parser_source.py.txt',
    'scripts/serde_error_string_source.py.txt', 'scripts/serde_error_display_source.py.txt',
    'scripts/hia_native_serde_error_qualification.py',
    'scripts/hia_native_serde_error_reference.py',
    TEST_DIR + '/test_serde_error.py', TEST_DIR + '/test_serde_error_resources.py',
    TEST_DIR + '/test_serde_error_evidence.py', TEST_DIR + '/error_cases.py',
    TEST_DIR + '/fixtures/original_probe.jsonl.gz',
    TEST_DIR + '/fixtures/original_probe_provenance.json',
    TEST_DIR + '/oracle/Cargo.toml', TEST_DIR + '/oracle/Cargo.lock',
    TEST_DIR + '/oracle/main.rs',
    'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
    'native/serde_filter_packer.hepta', 'native/serde_json.hepta',
    'native/text_budget.hepta', 'native/serde_json_composition.json', 'Cargo.lock', 'Cargo.toml',
)
STDOUT_FIELDS = frozenset(('abi_status', 'core_u32', 'forbidden_compiler_modules_loaded',
    'image_sha256', 'limits', 'loader_operations', 'native_elapsed_ns', 'output_sha256',
    'output_unchanged', 'result_u64', 'return_encoding', 'source_sha256',
    'source_unchanged', 'status', 'workspace_header'))


def require(condition, message):
    if not condition:
        raise ValueError('serde error evidence: ' + message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def same(left, right, message):
    require(canonical(left) == canonical(right), message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(), 'nonregular input ' + str(path))
    return path.read_bytes()


def pin(path):
    raw = read(path)
    return {'bytes': len(raw), 'sha256': digest(raw)}


def object_at(path):
    value = json.loads(read(path))
    require(type(value) is dict and bool(value), 'empty/object input ' + str(path))
    return value


def child(root, name):
    value = Path(name)
    require(not value.is_absolute() and value.parts and '..' not in value.parts, 'relative path escaped')
    return root / value


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def source_bindings(root):
    return {name: pin(root / name) for name in SOURCE_FILES}


def source_composition(root, hepta):
    proof = object_at(root / 'native/serde_error_composition.json')
    require(proof['source_sha256'] == SOURCE == digest(read(root / 'native/serde_error.hepta')),
            'HIA source changed')
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    actual = {f['name']: f for f in assemble_program(read(root / 'native/serde_error.hepta')).as_dict()['functions']}
    author = load('serde_error_author_verified', root / 'scripts/author_serde_error.py')
    require(len(actual) == 56 and len(proof['imports']) == 2, 'function closure changed')
    for row in proof['imports']:
        raw = read(root / row['source'])
        require(digest(raw) == row['sha256'], 'imported source changed')
        original = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
        reverse = {new: old for old, new in row['relocation'].items()}
        require(len(reverse) == len(row['relocation']), 'duplicate imported destination')
        for old, new in row['relocation'].items():
            function = copy.deepcopy(original[old])
            require(digest(canonical(function)) == row['functions'][old], 'original function changed')
            if old in row['coalesced_private_arena_functions']:
                function = author.private_number_source(function, old)
            require(digest(canonical(function)) == row['derived_functions'][old], 'resource adaptation changed')
            derived = copy.deepcopy(actual[new])
            derived['name'] = old
            for block in derived['blocks']:
                for operation in block['ops']:
                    if operation['op'] == 'call':
                        require(operation['attrs']['function'] in reverse, 'imported call escaped')
                        operation['attrs']['function'] = reverse[operation['attrs']['function']]
            same(function, derived, 'imported arithmetic/control graph changed')
    return {'functions': 56, 'imports': 2, 'source': SOURCE,
            'composition': pin(root / 'native/serde_error_composition.json')}


def receipt(folder, stem, image, incoming, produced):
    record = object_at(folder / (stem + '.receipt.json'))
    output = read(folder / (stem + '.output.bin'))
    request = object_at(folder / (stem + '.request.json'))
    stdout = object_at(folder / (stem + '.stdout.log'))
    require(set(stdout) == STDOUT_FIELDS, 'actual native observer stdout fields incomplete')
    same(stdout, {key: record[key] for key in STDOUT_FIELDS}, 'actual observer stdout differs')
    require(read(folder / (stem + '.stderr.log')) == b'', 'native observer stderr not empty')
    expected = {'status': 'returned', 'abi_status': 0, 'core_u32': len(produced),
        'result_u64': len(produced), 'source_unchanged': True,
        'input_bytes': len(incoming), 'input_sha256': digest(incoming),
        'source_sha256': digest(incoming), 'artifact_sha256': digest(image),
        'image_sha256': digest(image), 'output_sha256': digest(output),
        'forbidden_compiler_modules_loaded': [], 'return_encoding': 'zero-extended-u32'}
    same({key: record.get(key) for key in expected}, expected, 'compile/pack receipt differs')
    require(0 < len(produced) <= 1048576 and len(output) == 1048576
            and output[:len(produced)] == produced
            and read(folder / (stem + '.input.bin')) == incoming,
            'actual compile/pack input/output differs')
    expected_request = {'capacity': 1048576, 'format': 'flat-x86-64', 'image_sha256': digest(image),
        'source_sha256': digest(incoming), 'workspace_fill': 0, 'workspace_size': 1048576}
    same({key: request.get(key) for key in expected_request}, expected_request, 'native request changed')
    require(Path(request['source']).name == stem + '.input.bin'
            and Path(request['output']).name == stem + '.output.bin', 'native receipt paths changed')
    return record


def build_evidence(root, hepta, manifest):
    builder = load('serde_error_build_verified', root / 'scripts/hia_native_build.py')
    dependency = builder.check_dependency(hepta)
    folder = manifest.parent
    build = folder.parent.parent
    module = object_at(manifest)
    bootstrap = object_at(build / 'bootstrap/bootstrap.json')
    same(bootstrap['dependency'], dependency, 'compiler dependency differs')
    require(dependency['commit'] == COMMIT and dependency['tree'] == TREE, 'compiler commit/tree changed')
    compiler = read(build / 'bootstrap/B3.image.bin')
    require(digest(compiler) == COMPILER, 'compiler image changed')
    for level in ('B1', 'B2'):
        require(read(build / ('bootstrap/' + level + '.image.bin')) == compiler, 'fixed point changed')
    expected = {'schema': 'hepta.runtime.native-module.v1',
        'abi': 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'target': 'linux-x86_64',
        'compiler_commit': COMMIT, 'compiler_sha256': COMPILER, 'source_sha256': SOURCE,
        'image_sha256': IMAGE, 'buffer_profile': 'serde-json.v1',
        'input_capacity': 16777216, 'output_capacity': 67108864, 'workspace_capacity': 268435456}
    same({key: module.get(key) for key in expected}, expected, 'module identity/profile changed')
    for key in ('source', 'image'):
        require(len(Path(module[key]).parts) == 1, 'module child path escaped')
    source, image = read(folder / module['source']), read(folder / module['image'])
    require(source == read(root / 'native/serde_error.hepta') and digest(image) == IMAGE, 'actual module bytes changed')
    compiled = receipt(folder, 'module', compiler, source, image)
    built = object_at(folder / 'build.json')
    same(built['compile_receipt'], compiled, 'recorded compilation changed')
    same(built['compiler_dependency'], dependency, 'compile dependency changed')
    pack = module['standalone']
    require(pack['transport'] == 'filter' and pack['packer_source_sha256'] == PACKER
            and pack['runtime_libc_required'] is False and pack['runtime_python_required'] is False
            and len(Path(pack['path']).parts) == 1, 'standalone boundary changed')
    executable = read(folder / pack['path'])
    require(digest(executable) == EXECUTABLE == pack['sha256'] and len(executable) == 270005
            and executable[-len(image):] == image, 'actual packed ELF/source image changed')
    sys.path.insert(0, str(hepta))
    from tools.qualify_hia_selfhost_cli import inspect_executable
    same(pack['inspection'], inspect_executable(executable), 'ELF inspection changed')
    packer_folder = build / 'packers' / PACKER
    packer = read(packer_folder / 'packer.image.bin')
    packer_source = read(root / 'native/serde_filter_packer.hepta')
    require(digest(packer) == PACKER_IMAGE and digest(packer_source) == PACKER
            and read(packer_folder / 'source.hepta') == packer_source, 'packer identity changed')
    packer_compilation = receipt(packer_folder, 'packer', compiler, packer_source, packer)
    pm = object_at(packer_folder / 'manifest.json')
    require(pm['compiler_sha256'] == COMPILER and pm['source_sha256'] == PACKER
            and pm['image_sha256'] == PACKER_IMAGE, 'packer manifest changed')
    same(pm['compile_receipt'], packer_compilation, 'packer compilation changed')
    frame = b'HIAFLT01' + struct.pack('<Q', len(image)) + image
    same(pack['pack_receipt'], receipt(folder, 'pack', packer, frame, executable), 'packing receipt changed')
    artifacts = {}
    for selected in (folder, packer_folder):
        for path in selected.iterdir():
            if path.is_file():
                artifacts[str(path.relative_to(build))] = pin(path)
    for name in ('bootstrap.json', 'B1.image.bin', 'B2.image.bin', 'B3.image.bin'):
        path = build / 'bootstrap' / name
        artifacts[str(path.relative_to(build))] = pin(path)
    return {'manifest': pin(manifest), 'source': SOURCE, 'image': IMAGE, 'executable': EXECUTABLE,
        'compiler': COMPILER, 'compiler_commit': COMMIT, 'build_artifacts': artifacts,
        'fixed_point_rechecked': True, 'fresh_full_cold_replay': False,
        'composition': source_composition(root, hepta)}


def corpus_evidence(folder, contract):
    metadata = object_at(folder / 'native-report.json')
    expected = contract['corpus']
    same({key: metadata['corpus'][key] for key in expected}, expected, 'whole corpus contract changed')
    for name, identity in metadata['corpus']['files'].items():
        same(pin(child(folder / 'corpus', name)), identity, 'corpus compressed bytes changed')
    require(set(metadata['corpus']['files']) == {'cases.bin.gz', 'native-output.bin.gz', 'cases.jsonl.gz'},
            'corpus file inventory changed')
    input_hash, output_hash, index_hash = (hashlib.sha256() for _ in range(3))
    input_size = output_size = index_size = count = 0
    domains = {}
    with gzip.open(folder / 'corpus/cases.bin.gz', 'rb') as incoming, \
            gzip.open(folder / 'corpus/native-output.bin.gz', 'rb') as outgoing, \
            gzip.open(folder / 'corpus/cases.jsonl.gz', 'rb') as index:
        for line in index:
            row = json.loads(line)
            require(row['ordinal'] == count, 'case ordinal changed')
            header = incoming.read(8)
            require(len(header) == 8, 'missing input frame')
            length = struct.unpack('<Q', header)[0]
            require(24 <= length <= 8388632, 'input exceeds original bounded domain')
            wire = incoming.read(length)
            require(len(wire) == length and wire[:8] == b'HSJERQ01'
                    and struct.unpack_from('<QQ', wire, 8) == (1, length - 24), 'invalid retained request')
            prefix = outgoing.read(12)
            require(len(prefix) == 12, 'missing output frame')
            code, size = struct.unpack('<IQ', prefix)
            require(code == size and 64 <= size <= 1024, 'invalid retained diagnostic size')
            answer = outgoing.read(size)
            require(len(answer) == size and answer[:8] == b'HSJERR01', 'invalid retained diagnostic')
            status, category, line_no, column, chars, zero1, zero2 = struct.unpack('<7Q', answer[8:64])
            require(zero1 == zero2 == 0 and chars == size - 64, 'diagnostic reserved/length changed')
            require((status == 0 and answer == b'HSJERR01' + bytes(56)) or
                    (status == 1 and category in (1, 2, 3) and line_no >= 1 and chars > 0),
                    'diagnostic classification changed')
            answer[64:].decode('utf8')
            same({key: row[key] for key in ('input_bytes', 'input_sha256', 'output_bytes', 'output_sha256')},
                 {'input_bytes': length, 'input_sha256': digest(wire),
                  'output_bytes': size, 'output_sha256': digest(answer)}, 'indexed actual bytes changed')
            input_hash.update(header + wire); output_hash.update(prefix + answer); index_hash.update(line)
            input_size += 8 + length; output_size += 12 + size; index_size += len(line)
            domains[row['domain']] = domains.get(row['domain'], 0) + 1
            count += 1
        require(not incoming.read(1) and not outgoing.read(1), 'trailing corpus data')
    same({'cases': count, 'domains': domains, 'input_bytes': input_size, 'input_sha256': input_hash.hexdigest(),
          'output_bytes': output_size, 'output_sha256': output_hash.hexdigest()}, expected,
         'full corpus bytes/domain changed')
    same({'bytes': index_size, 'sha256': index_hash.hexdigest()}, contract['index'], 'complete index changed')
    return {'rows': count, 'input_bytes': input_size, 'input_sha256': input_hash.hexdigest(),
            'output_bytes': output_size, 'output_sha256': output_hash.hexdigest(),
            'metadata': pin(folder / 'native-report.json'), 'compressed': metadata['corpus']['files']}


def completed_suite(root, runtime, manifest, folder, process_folder, label):
    contract = object_at(root / 'native/serde_error_corpus_contract.json')[label]
    report = object_at(folder / 'native-report.json')
    process = object_at(process_folder / 'result.json')
    require(process['exit_code'] == 0 and process['timed_out'] is False
            and process['process_reaped'] is True and process['timeout_seconds'] == 180,
            'suite process not successfully completed')
    command = process['command']
    require(len(command) == 10 and Path(command[3]).is_absolute()
            and Path(command[5]).is_absolute() and Path(command[7]).is_absolute()
            and Path(command[9]).is_absolute(), 'actual command paths malformed')
    origin = Path(command[3]).parents[3]
    capture = Path(command[9])
    require(capture.name == label and all('..' not in Path(command[i]).parts for i in (3, 5, 7, 9)),
            'actual command origin malformed')
    expected = ['-I', '-B', str(origin / TEST_DIR / SUITES[label]), '--manifest', command[5],
                '--runtime', str(origin), '--output', str(capture)]
    require(len(command) == 10 and command[1:] == expected, 'actual suite command changed')
    for stream in ('stdout', 'stderr'):
        same(pin(process_folder / stream), process[stream], 'suite process output changed')
    stdout = object_at(process_folder / 'stdout')
    required = {key: contract[key] for key in ('summary', 'native_calls', 'semantic_cases',
                                              'controls', 'actual_elf_processes')}
    same({key: stdout.get(key) for key in required}, required, 'actual suite counts changed')
    require(set(stdout) == set(required) | {'status', 'elapsed_seconds'} and stdout['status'] == 'PASS',
            'actual suite stdout incomplete')
    for key in ('schema', 'summary', 'native_calls', 'semantic_cases', 'actual_elf_processes'):
        same(report[key], contract[key], 'retained suite count differs')
    require(report['status'] == 'PASS' and report['source_unchanged'] is True
            and report['elapsed_seconds'] == stdout['elapsed_seconds'], 'suite/source status changed')
    stderr = read(process_folder / 'stderr').decode()
    count = contract['summary']['tests_run']
    require(len(re.findall(r'\.\.\. ok\n', stderr)) == count
            and re.search(r'\nRan ' + str(count) + r' tests in [0-9.]+s\n\nOK\n\Z', stderr),
            'suite did not complete every group')
    names = ['native/serde_error.hepta', TEST_DIR + '/test_serde_error.py']
    if label == 'base':
        names += [TEST_DIR + '/error_cases.py', TEST_DIR + '/fixtures/original_probe.jsonl.gz',
                  TEST_DIR + '/fixtures/original_probe_provenance.json']
    else:
        names += [TEST_DIR + '/test_serde_error_resources.py']
    same(report['source_files'], {name: pin(root / name) for name in names}, 'actual tested sources changed')
    same(report['loader'], pin(runtime / 'scripts/hia_native_loader.py'), 'actual loader changed')
    same(report['manifest'], pin(manifest), 'actual module manifest changed')
    same(report['module'], object_at(manifest), 'actual module identity changed')
    require(len(report['elf']) == contract['actual_elf_processes'], 'actual ELF domain changed')
    for index, row in enumerate(report['elf']):
        expected_static = contract['static_elf'][index]
        same({key: row[key] for key in expected_static}, expected_static, 'static input/output domain changed')
        require(row['exit_code'] == 0 and row['timed_out'] is False and row['process_reaped'] is True
                and row['timeout_seconds'] == 20 and row['empty_path'] is True
                and row['executable_sha256'] == EXECUTABLE, 'actual ELF receipt changed')
        stem = ('elf-' + str(index)) if label == 'base' else 'elf'
        for stream in ('stdout', 'stderr'):
            same(pin(folder / (stem + '.' + stream)), row[stream], 'actual ELF bytes changed')
        require(read(folder / (stem + '.stderr')) == b'', 'actual ELF error output')
        if label == 'base':
            require(row['ordinal'] == index, 'actual ELF ordering changed')
            same(pin(folder / (stem + '.input')), row['input'], 'actual ELF input changed')
    if label == 'resources':
        same(report['controls'], [{'ordinal': 0, 'workspace_capacity': 142600688, 'code': 4294967294,
                                  'output_unchanged': True}, {'ordinal': 1, 'workspace_capacity': 142557938,
                                  'code': 4294967294, 'output_unchanged': True}], 'exact capacity controls changed')
        require(len(report['observations']) == 2, 'resource observations missing')
        for row, (peak, stack, arrays) in zip(report['observations'], ((142600689, 38, 0), (142557939, 2288, 125)), strict=True):
            require(row['workspace_exact'] == row['actual_allocation'] == peak
                    and row['stack_records'] == stack and row['raw_bytes'] == 8388608
                    and row['nesting'] == 18 and row['local_array_depth'] == arrays,
                    'combined resource boundary changed')
    else:
        require(report['controls'] == 41, 'base controls changed')
    return {'process': pin(process_folder / 'result.json'), 'stdout': pin(process_folder / 'stdout'),
            'stderr': pin(process_folder / 'stderr'), 'summary': contract,
            'corpus': corpus_evidence(folder, contract)}


def native_evidence(root, hepta, manifest, output, *, runtime=None):
    root, hepta, manifest, output = map(Path, (root, hepta, manifest, output))
    runtime = root if runtime is None else Path(runtime)
    sources = source_bindings(root)
    built = build_evidence(root, hepta, manifest)
    suites = {name: completed_suite(root, runtime, manifest, output / name,
              output / (name + '-process'), name) for name in SUITES}
    same(sources, source_bindings(root), 'sources changed during evidence check')
    return {'schema': 'hepta.runtime.serde-error-qualification.v1', 'status': 'PASS',
        'sources': sources, 'build': built, 'suites': suites, 'semantic_cases': 98701,
        'native_calls': 98753, 'controls': 43, 'test_groups': 10, 'actual_elf_processes': 5,
        'new_native_executions': 0, 'new_original_executions': 0,
        'original_complete_replay_required': True, 'typed_derive_diagnostics_closed': False,
        'generic_value_serialization_closed': False, 'whole_runtime_closed': False}


def controls_evidence(root, hepta, manifest, output):
    folder = output / 'controls-process'
    process = object_at(folder / 'result.json')
    command = process['command']
    require(len(command) == 12 and all(Path(command[i]).is_absolute()
            and '..' not in Path(command[i]).parts for i in (3, 5, 7, 9, 11)), 'control command paths malformed')
    origin = Path(command[3]).parents[3]
    capture = Path(command[9])
    expected_command = ['-I', '-B', str(origin / TEST_DIR / 'test_serde_error_evidence.py'),
        '--hepta', command[5], '--manifest', command[7], '--native-output', str(capture),
        '--output', str(capture / 'controls')]
    require(process['command'][1:] == expected_command and process['exit_code'] == 0
            and process['timed_out'] is False and process['process_reaped'] is True
            and process['timeout_seconds'] == 180, 'evidence-control process incomplete')
    for stream in ('stdout', 'stderr'):
        same(pin(folder / stream), process[stream], 'evidence-control process bytes changed')
    expected = {'schema': 'hepta.runtime.serde-error-evidence-controls.v1', 'status': 'PASS',
        'summary': {'tests_run': 4, 'failures': 0, 'errors': 0, 'skipped': 0,
                    'expected_failures': 0, 'unexpected_successes': 0},
        'accepted': 2, 'refused': 16, 'new_native_calls': 0, 'new_original_calls': 0}
    same(object_at(folder / 'stdout'), expected, 'evidence controls changed')
    report = object_at(output / 'controls/result.json')
    same({key: report[key] for key in expected}, expected, 'retained evidence controls changed')
    same(report['sources'], source_bindings(root), 'tested verifier sources changed')
    require(report['source_unchanged'] is True, 'verifier sources changed during controls')
    stderr = read(folder / 'stderr').decode()
    require(len(re.findall(r'\.\.\. ok\n', stderr)) == 4
            and re.search(r'\nRan 4 tests in [0-9.]+s\n\nOK\n\Z', stderr), 'verifier tests incomplete')
    return {'summary': expected, 'report': pin(output / 'controls/result.json'),
            'process': pin(folder / 'result.json'), 'stdout': pin(folder / 'stdout'), 'stderr': pin(folder / 'stderr')}


def qualification_evidence(root, hepta, manifest, output):
    result = native_evidence(root, hepta, manifest, output)
    return {**result, 'controls_evidence': controls_evidence(root, hepta, manifest, output)}


def run_in_owned_group(folder, command, *, incoming=None, env=None, cwd=None):
    """Run a child in the outer qualification's owned process group.

    No nested session escapes the aggregate's 180-second group kill. A direct
    CLI caller must supply an owned group, for example with setsid.
    File-backed streams cannot hold communicate() alive after a timeout.
    """
    require(os.getpgrp() == os.getpid(), 'execution requires the outer owned process group')
    folder.mkdir(parents=True)
    start = time.monotonic()
    record = {'command': list(map(str, command)), 'timeout_seconds': 180,
              'timed_out': False, 'exit_code': None, 'process_reaped': False,
              'inherited_owned_process_group': os.getpgrp(),
              'cwd': str(Path.cwd() if cwd is None else Path(cwd).resolve()),
              'input': None if incoming is None else {'path': str(Path(incoming).resolve()), **pin(incoming)}}
    try:
        with (open(os.devnull, 'rb') if incoming is None else Path(incoming).open('rb')) as source, \
                (folder / 'stdout').open('xb') as output, (folder / 'stderr').open('xb') as errors:
            process = subprocess.Popen(record['command'], stdin=source, stdout=output, stderr=errors,
                                       env=env, cwd=record['cwd'], start_new_session=False)
            record['pid'] = process.pid
            require(os.getpgid(process.pid) == os.getpgrp(), 'child escaped outer owned group')
            try:
                process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                record['timed_out'] = True
                record['elapsed_seconds'] = time.monotonic() - start
                record['stdout'], record['stderr'] = pin(folder / 'stdout'), pin(folder / 'stderr')
                (folder / 'result.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
                os.killpg(os.getpgrp(), signal.SIGKILL)
                raise RuntimeError('owned group timeout kill returned')
            record.update(exit_code=process.returncode, process_reaped=True)
    except OSError as error:
        record['start_error'] = repr(error)
        raise
    finally:
        record['elapsed_seconds'] = time.monotonic() - start
        for name in ('stdout', 'stderr'):
            if (folder / name).is_file():
                record[name] = pin(folder / name)
        (folder / 'result.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    require(record['exit_code'] == 0 and record['process_reaped'] and not record['timed_out'],
            'actual process failed; complete output retained')
    if incoming is not None:
        same({key:record['input'][key] for key in ('bytes','sha256')}, pin(incoming), 'actual stdin changed during execution')
    return record


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--phase', choices=('base', 'resources', 'controls', 'evidence'), required=True)
    options = parser.parse_args()
    root, hepta, manifest, output = (path.resolve() for path in
        (options.root, options.hepta, options.manifest, options.output))
    output.mkdir(exist_ok=True, parents=True)
    if options.phase == 'evidence':
        result = qualification_evidence(root, hepta, manifest, output)
        (output / 'native-evidence.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        print(json.dumps({key: result[key] for key in ('status', 'semantic_cases', 'native_calls',
            'controls', 'test_groups', 'actual_elf_processes')}, sort_keys=True))
        return
    before = source_bindings(root)
    build_evidence(root, hepta, manifest)
    if options.phase == 'controls':
        command = [sys.executable, '-I', '-B', str(root / TEST_DIR / 'test_serde_error_evidence.py'),
            '--hepta', str(hepta), '--manifest', str(manifest), '--native-output', str(output),
            '--output', str(output / 'controls')]
        run_in_owned_group(output / 'controls-process', command)
        same(before, source_bindings(root), 'sources changed during verifier controls')
        controls_evidence(root, hepta, manifest, output)
        print(read(output / 'controls-process/stdout').decode().strip())
        return
    command = [sys.executable, '-I', '-B', str(root / TEST_DIR / SUITES[options.phase]),
               '--manifest', str(manifest), '--runtime', str(root), '--output', str(output / options.phase)]
    run_in_owned_group(output / (options.phase + '-process'), command)
    same(before, source_bindings(root), 'native sources changed during suite')
    result = completed_suite(root, root, manifest, output / options.phase,
                             output / (options.phase + '-process'), options.phase)
    build_evidence(root, hepta, manifest)
    (output / (options.phase + '-evidence.json')).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(read(output / (options.phase + '-process/stdout')).decode().strip())


if __name__ == '__main__':
    main()
