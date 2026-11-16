"""Run the frozen ordinary body domain against two actual private processes.

Both lanes use the same absolute working directory, sequentially. Completed
captures are retained by an owned rename before the next independent fixture is
created. No key rewriting, response normalization or filesystem model is used.
"""
from __future__ import annotations
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import signal
import struct
import sys
import time
import traceback
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cases
import observations
import native_observations
import run_ordinary as ordinary

PINNED_NATIVE = '5bf66aa0aaaca65e4be44e2ef9a225ab2ed387bd53069b32700fdaf854c0cf72'
FROZEN = {
    'cases.py': {'bytes': 9423, 'sha256': '3597bf5c7bae18917034147052d32e1b7c0908b9c58d6e55950563ceab751be4'},
    'observations.py': {'bytes': 5952, 'sha256': 'c9a0043cef9819d13050dae19b85c5326aa61fe26300986dd6931d1a65690f88'},
    'run_ordinary.py': {'bytes': 18261, 'sha256': 'd13cdd4cddf5882db8f1eb2e5c051547d490729adad580b6012f865e7cb8853f'},
}
OUTER_DEADLINE = 180
pin, dump = ordinary.pin, ordinary.dump


def require(value, reason):
    if not value:
        raise ValueError(reason)


def files(root):
    return {str(path.relative_to(root)): pin(path.read_bytes()) for path in sorted(root.rglob('*'))
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}


def original_build(path):
    spec = importlib.util.spec_from_file_location('body_original_verifier', HERE / 'verify_reference.py')
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    verification = verifier.verify(HERE)
    raw = path.read_bytes(); built = json.loads(raw)
    require(built['status'] == 'FRESH_LOCAL_TEXT_BODY_REFERENCE_BUILD_PASS'
        and built['source_verification'] == verification
        and [row['name'] for row in built['processes']] == [
            'body-rust-version', 'body-cargo-version', 'body-cargo-metadata', 'body-rust-build']
        and all(row['exit_code'] == 0 and row['timed_out'] is False
                and row['deadline_seconds'] == 180 for row in built['processes']),
        'paired body reference lacks the exact original build receipt')
    binary = Path(built['executable']['path']).resolve(strict=True)
    identity = pin(binary.read_bytes())
    require(identity == {key: built['executable'][key] for key in ('bytes', 'sha256')}
        and identity['sha256'] == ordinary.EXPECTED_REFERENCE_BINARY,
        'paired body original binary differs')
    return binary, dict(receipt=pin(raw), executable=identity, source_verification=verification)


def native_build(path):
    raw = path.read_bytes(); built = json.loads(raw); root = path.parent
    require(built['status'] == 'PASS' and len(built['members']) == 12
        and [row['number'] for row in built['members']] == list(range(12))
        and all(built[name] is False for name in (
            'fresh_compiler_cold', 'original_build', 'ordinary_semantics_qualified',
            'cancellation_qualified', 'public_handler_qualified')),
        'native graph development build scope differs')
    binary = Path(built['elf']).resolve(strict=True); elf = binary.read_bytes()
    require(pin(elf) == dict(bytes=built['elf_bytes'], sha256=built['elf_sha256'])
        and len(elf) == 2299727 and built['elf_sha256'] == PINNED_NATIVE,
        'frozen native body executable differs')
    retained = {str(path): pin(raw), str(binary): pin(elf)}
    images = []
    for row in built['members']:
        manifest = Path(row['manifest']).resolve(strict=True); data = manifest.read_bytes()
        require(pin(data)['sha256'] == row['manifest_sha256'], 'native member manifest differs')
        value = json.loads(data)
        source = manifest.parent / value['source']; image = manifest.parent / value['image']
        source_raw, image_raw = source.read_bytes(), image.read_bytes()
        require(pin(source_raw)['sha256'] == row['source_sha256'] == value['source_sha256']
            and pin(image_raw) == dict(bytes=row['image_bytes'], sha256=row['image_sha256'])
            and row['image_sha256'] == value['image_sha256'], 'native member source/image differs')
        retained.update({str(manifest): pin(data), str(source): pin(source_raw), str(image): pin(image_raw)})
        images.append(image_raw)
    author_path = root / 'authoring.json'; author_raw = author_path.read_bytes(); author = json.loads(author_raw)
    prefix_path = root / 'prefix.bin'; prefix = prefix_path.read_bytes()
    bridge_path = root / 'local_text_body_adapter.S'; bridge = bridge_path.read_bytes()
    require(pin(prefix)['sha256'] == built['prefix_sha256'] == author['prefix_sha256']
        and pin(bridge)['sha256'] == built['bridge_sha256'] == author['bridge_sha256'],
        'native adapter source or immutable prefix differs')
    actual_prefix = bytearray(prefix)
    struct.pack_into('<QQ', actual_prefix, 96, len(elf), len(elf))
    struct.pack_into('<12Q', actual_prefix, author['table_offset'], *(len(image) for image in images))
    require(elf == bytes(actual_prefix) + b''.join(images), 'native executable is not the exact member graph')
    packer_path = Path(built['packer_manifest']).resolve(strict=True)
    packer_raw = packer_path.read_bytes(); packer = json.loads(packer_raw)
    packer_source = packer_path.parent / packer['source']; packer_image = packer_path.parent / packer['image']
    require(pin(packer_raw)['sha256'] == built['packer_manifest_sha256']
        and pin(packer_source.read_bytes())['sha256'] == packer['source_sha256'] == author['packer_sha256']
        and pin(packer_image.read_bytes())['sha256'] == packer['image_sha256'],
        'native actual packer source/image differs')
    for name, field, expected in (
        ('pack.input.bin', 'pack_input_sha256', b'HLTBPK03' + ordinary.q(*(len(image) for image in images)) + b''.join(images)),
        ('pack.output.bin', 'pack_output_sha256', elf + b'\xb3' * 4096),
        ('pack.workspace.bin', 'pack_workspace_sha256', b'\xc7' * 4096),
    ):
        location = root / name; value = location.read_bytes()
        require(value == expected and pin(value)['sha256'] == built[field], 'native complete packer buffer differs')
        retained[str(location)] = pin(value)
    for location in (author_path, prefix_path, bridge_path, packer_path, packer_source, packer_image):
        retained[str(location)] = pin(location.read_bytes())
    return binary, dict(receipt=pin(raw), executable=pin(elf), source_and_artifact_files=retained)


def capture(definition, binary, lane, vault, decoder):
    retained = []
    def decode(raw, operations):
        frames = decoder(raw, operations)
        retained.extend(frames)
        return frames
    old = ordinary.observations
    ordinary.observations = types.SimpleNamespace(words=observations.words, decode=decode)
    try:
        result = ordinary.run_case(definition, binary, lane, vault)
    finally:
        ordinary.observations = old
    return result, retained


def same_bytes(left, right, label):
    a, b = left.read_bytes(), right.read_bytes()
    require(a == b, 'complete paired ' + label + ' differs')
    return len(a)


def run_pair(definition, binaries, folder, vault):
    folder.mkdir(); lane = folder / 'lane'
    report = dict(name=definition['name'], status='RUNNING', operations=len(definition['operations']),
        actual_working_directory=str(lane / 'work'), same_absolute_workdir=True,
        completed_capture_relocated=True, process_deadline_seconds=ordinary.DEADLINE, captures={})
    outputs = {}; decoded = {}
    dump(folder / 'result.json', report)
    try:
        for label, decoder in (('original', observations.decode), ('native', native_observations.decode)):
            try:
                outputs[label], decoded[label] = capture(definition, binaries[label], lane, vault, decoder)
            finally:
                if lane.exists():
                    lane.rename(folder / label)
                    report['captures'][label] = dict(folder=label,
                        receipt=pin((folder / label / 'result.json').read_bytes()))
                    dump(folder / 'result.json', report)
        old, new = outputs['original'], outputs['native']
        for name in ('operations', 'setup_frames', 'input_frames', 'cwd', 'environment',
                     'filesystem_before', 'responses', 'files_after_body'):
            require(old[name] == new[name], 'paired ordinary result differs: ' + name)
        for row in (old, new):
            require(row['status'] == 'PASS' and row['exit_code'] == 0 and row['process_reaped'] is True
                and row['timed_out'] is False and row['process_deadline_seconds'] == 60,
                'paired process did not complete within its original deadline')
        compared = sum(same_bytes(folder / 'original' / (name + '.bin'),
            folder / 'native' / (name + '.bin'), name) for name in ('stdin', 'stdout'))
        native_observations.compare(decoded['original'], decoded['native'])
        report.update(status='PAIRED_COMPLETE_STATE_PASS', byte_identical_input_and_response_bytes=compared,
            complete_original_observer_bytes=old['streams']['stderr']['bytes'],
            complete_native_arena_observer_bytes=new['streams']['stderr']['bytes'],
            compared_owner_boundaries=6 * len(definition['operations']),
            compared_hint_boundaries=len(definition['operations']),
            file_snapshots_identical=True, complete_states_identical=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        dump(folder / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference-build', type=Path, required=True)
    parser.add_argument('--native-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() != 0, 'body permission cases require the unprivileged original account')
    before = files(HERE)
    require(all(before[name] == value for name, value in FROZEN.items()), 'frozen ordinary source domain differs')
    old_binary, old = original_build(args.reference_build.resolve(strict=True))
    new_binary, new = native_build(args.native_build.resolve(strict=True))
    definitions = cases.cases()
    require(len(definitions) == 68 and sum(len(row['operations']) for row in definitions) == 129,
        'complete frozen ordinary domain differs')
    output = args.output.resolve(); output.mkdir(exist_ok=False)
    vault = output / 'blobs'; vault.mkdir()
    report = dict(schema='hepta.runtime.local-text-body-paired-development.v1', status='RUNNING',
        source_files=before, reference_build=old, native_build=new,
        reference_build_path=str(args.reference_build.resolve()), native_build_path=str(args.native_build.resolve()),
        expected_case_names=[row['name'] for row in definitions], expected_root_pairs=68,
        expected_operations_per_side=129, process_deadline_seconds=60, capture_deadline_seconds=OUTER_DEADLINE,
        fresh_reference_build_performed=False, fresh_native_build_performed=False, same_absolute_workdir=True,
        full_body_async_qualified=False, public_handler_qualified=False, whole_runtime_replaced=False,
        old_stack_removal_qualified=False, cases=[])
    old_mask = os.umask(0o022)
    previous_signal = signal.getsignal(signal.SIGALRM)
    def timeout(_signal, _frame):
        raise TimeoutError('complete paired body capture exceeded its original 180-second deadline')
    signal.signal(signal.SIGALRM, timeout); signal.setitimer(signal.ITIMER_REAL, OUTER_DEADLINE)
    began = time.monotonic()
    try:
        for index, definition in enumerate(definitions):
            name = f'case-{index:02d}-{definition["name"]}'
            row = run_pair(definition, {'original': old_binary, 'native': new_binary}, output / name, vault)
            report['cases'].append(dict(folder=name, receipt=pin((output / name / 'result.json').read_bytes()), **row))
            dump(output / 'result.json', report)
            print(json.dumps(dict(case=definition['name'], operations=row['operations'], status=row['status'])), flush=True)
        require(files(HERE) == before and original_build(args.reference_build.resolve())[1] == old
            and native_build(args.native_build.resolve())[1] == new,
            'paired source/build/actual executable custody changed')
        report.update(status='LOCAL_TEXT_BODY_ORDINARY_PAIRED_PASS', actual_root_processes=136,
            actual_root_pairs=len(report['cases']), actual_operations_per_side=sum(row['operations'] for row in report['cases']),
            complete_input_and_response_bytes=sum(row['byte_identical_input_and_response_bytes'] for row in report['cases']),
            complete_original_observer_bytes=sum(row['complete_original_observer_bytes'] for row in report['cases']),
            complete_native_arena_observer_bytes=sum(row['complete_native_arena_observer_bytes'] for row in report['cases']),
            source_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous_signal)
        os.umask(old_mask); report['elapsed_seconds'] = time.monotonic() - began
        dump(output / 'result.json', report)
    print(json.dumps({key: report[key] for key in ('status', 'actual_root_processes', 'actual_root_pairs',
        'actual_operations_per_side', 'complete_input_and_response_bytes', 'complete_original_observer_bytes',
        'complete_native_arena_observer_bytes', 'elapsed_seconds')}), flush=True)


if __name__ == '__main__':
    main()
