"""Reject modified source-bound service artifacts and complete native receipts."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(path) not in sys.path: sys.path.insert(0, str(path))
from hia_native_file_lock_service_build import inspect_bundle, read, sha, obj, file_record
from hia_native_file_lock_service_qualification import pins, native_evidence, contract_evidence


def altered_json(path, edit):
    value = obj(path); edit(value)
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def flip(raw):
    if not raw: return b'x'
    at = len(raw) // 2
    return raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=os.environ.get('HIA_FILE_LOCK_SERVICE_MANIFEST'))
    parser.add_argument('--native-corpus', type=Path, required=True)
    parser.add_argument('--native-stdout', type=Path, required=True)
    parser.add_argument('--state-corpus', type=Path, required=True)
    parser.add_argument('--contract-corpus', type=Path, required=True)
    parser.add_argument('--contract-stdout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); assert args.bundle is not None
    args.bundle = args.bundle.resolve(strict=True); args.output.mkdir(mode=0o700)
    before = pins(ROOT); started = time.monotonic()
    report = {'schema': 'hepta.runtime.file-lock-service-evidence-controls.v1', 'status': 'RUNNING',
        'groups': 3, 'source_files': before, 'actual_native_calls': 0, 'actual_original_calls': 0, 'refusals': []}
    scratch = args.output / 'owned-control-copies'; scratch.mkdir(mode=0o700)

    def refuse(name, changes, verify):
        originals, modes, changes_record = {}, {}, {}
        for path, after in changes.items():
            path = Path(path); original = read(path); originals[path] = original; modes[path] = path.stat().st_mode & 0o777
            path.chmod(0o600); path.write_bytes(after)
            changed = {'before': {'bytes': len(original), 'sha256': sha(original)},
                'after': {'bytes': len(after), 'sha256': sha(after)}}
            if len(original) == len(after):
                positions = [i for i, (a, b) in enumerate(zip(original, after)) if a != b]
                changed['byte_changes'] = [[i, original[i], after[i]] for i in positions]
            else:
                changed['replacement_hex'] = after.hex()
            changes_record[str(path.relative_to(scratch))] = changed
        try:
            try:
                verify()
            except (ValueError, AssertionError, OSError, KeyError, TypeError, EOFError, zlib.error) as error:
                report['refusals'].append({'name': name, 'status': 'REFUSED', 'error': str(error),
                    'changed_files': changes_record, 'actual_native_calls': 0, 'actual_original_calls': 0})
            else:
                raise AssertionError('modified service evidence was accepted: ' + name)
        finally:
            for path, original in originals.items():
                path.write_bytes(original); path.chmod(modes[path])

    try:
        native = native_evidence(args.bundle, args.native_corpus, args.state_corpus,
            source_root=ROOT, stdout=args.native_stdout)
        contract = contract_evidence(args.bundle, args.contract_corpus, source_root=ROOT, stdout=args.contract_stdout)
        for name, value in (('native', native), ('contract', contract)):
            path = args.output / ('accepted-' + name + '-evidence.json')
            path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
            report['accepted_' + name + '_evidence'] = file_record(path)
        bundle_dir = scratch / 'bundle'; shutil.copytree(args.bundle.parent, bundle_dir)
        manifest = bundle_dir / 'manifest.json'
        verify_artifact = lambda: inspect_bundle(manifest, source_root=ROOT)
        for name in ('controller.image.bin', 'key.image.bin', 'state.image.bin', 'packer.image.bin',
            'file-lock-service.elf', 'controller-build/module.output.bin', 'key-build/module.stdout.log',
            'state-build/module.receipt.json', 'pack/pack.input.bin', 'pack/pack.output.bin',
            'pack/pack.stdout.log', 'pack/pack.receipt.json'):
            path = bundle_dir / name
            refuse('artifact-' + name.replace('/', '-'), {path: flip(read(path))}, verify_artifact)
        for kind in ('controller', 'key', 'state', 'packer'):
            path = bundle_dir / (kind + '.image.bin'); changed = flip(read(path)); digest = sha(changed)
            metadata = bundle_dir / (kind + '.json')
            refuse('rehash-image-' + kind, {
                path: changed,
                metadata: altered_json(metadata, lambda value: value.__setitem__('image_sha256', digest)),
                manifest: altered_json(manifest, lambda value: value['modules'][kind].__setitem__('image_sha256', digest)),
            }, verify_artifact)
        path = bundle_dir / 'file-lock-service.elf'; changed = bytearray(read(path)); changed[176] ^= 1
        refuse('rehash-fixed-prefix', {path: bytes(changed),
            manifest: altered_json(manifest, lambda value: value['executable']['inspection'].__setitem__('sha256', sha(changed)))}, verify_artifact)
        for name, field, value in (('false-production', 'production_activated', True),
            ('wrong-compiler', 'compiler_commit', '0' * 40)):
            refuse(name, {manifest: altered_json(manifest, lambda report: report.__setitem__(field, value))}, verify_artifact)
        native_dir = scratch / 'native'; shutil.copytree(args.native_corpus, native_dir)
        native_stdout = scratch / 'native.stdout'; shutil.copyfile(args.native_stdout, native_stdout)
        verify_native = lambda: native_evidence(args.bundle, native_dir, args.state_corpus,
            source_root=ROOT, stdout=native_stdout)
        first = obj(native_dir / 'result.json')['results']['state']['sessions'][0]['session']
        for name, relative in (
            ('state-input', f'state/session-{first}/requests.bin.gz'),
            ('actual-thread-output', f'state/session-{first}/native-wire.bin.gz'),
            ('canonical-output', 'canonical/process/native-output.bin.gz'),
            ('concurrent-schedule', 'concurrent/schedule.json')):
            path = native_dir / relative
            refuse(name, {path: flip(read(path))}, verify_native)
        refuse('missing-completed-result-binding', {native_stdout: altered_json(native_stdout,
            lambda value: value.pop('result'))}, verify_native)
        contract_dir = scratch / 'contract'; shutil.copytree(args.contract_corpus, contract_dir)
        verify_contract = lambda: contract_evidence(args.bundle, contract_dir, source_root=ROOT, stdout=args.contract_stdout)
        path = contract_dir / 'result.json'
        refuse('omitted-controller-refusal', {path: altered_json(path, lambda value: value['controller'].pop())}, verify_contract)
        refuse('false-contract-original-calls', {path: altered_json(path, lambda value: value.__setitem__('actual_original_calls', 1))}, verify_contract)
        assert len(report['refusals']) == 26
        assert pins(ROOT) == before
        assert native_evidence(args.bundle, args.native_corpus, args.state_corpus, source_root=ROOT,
            stdout=args.native_stdout) == native
        assert contract_evidence(args.bundle, args.contract_corpus, source_root=ROOT, stdout=args.contract_stdout) == contract
        # The exact immutable accepted artifacts plus each recorded byte delta
        # reproduce every rejected candidate. Retire only these owned copies.
        shutil.rmtree(scratch)
        report.update(status='PASS', rejected_candidates=26, owned_control_copies_retired=True)
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error)); raise
    finally:
        report['elapsed'] = time.monotonic() - started
        (args.output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    summary = {key: report[key] for key in ('status', 'groups', 'elapsed', 'rejected_candidates',
        'actual_native_calls', 'actual_original_calls')}
    summary['result'] = file_record(args.output / 'result.json')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
