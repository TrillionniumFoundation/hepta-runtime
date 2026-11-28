"""Qualify the new evidence layout using owned copies, without runtime calls."""
from pathlib import Path
from contextlib import contextmanager
import argparse
import gzip
import importlib.util
import json
import shutil
import sys
import time

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser()
    for name in ('reader', 'source-root', 'manifest', 'capture', 'reference', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('_filesystem_evidence_controls', args.reader)
    n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)
    q = n.q
    started = time.monotonic()
    baseline = n.native_evidence(args.source_root, args.manifest, args.capture, args.reference)
    owners = {'source': args.source_root, 'bundle': args.manifest.parent, 'native': args.capture,
              'original': args.reference, 'qualification': args.reader.parent}
    copied = args.output/'moved-one'
    copied.mkdir()
    def copy_artifacts(destination):
        for relative, sha in baseline['artifact_sha256'].items():
            namespace, name = relative.split('/', 1)
            source = q.inside(owners[namespace], name)
            target = destination/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open('rb') as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            q.same(q.pin(target), {'bytes': baseline['artifact_bytes'][relative], 'sha256': sha}, 'copied artifact full bytes')
    copy_artifacts(copied)
    reader = n.load(copied/'qualification/strict_native.py', '_filesystem_first_relocated_reader')
    def read_all():
        return reader.native_evidence(copied/'source', copied/'bundle'/args.manifest.name,
                                      copied/'native', copied/'original')
    q.same(read_all(), baseline, 'all evidence owners moved with no live fixture dependency')
    events = []
    @contextmanager
    def changed(path, raw):
        before = path.read_bytes()
        path.write_bytes(raw)
        try:
            yield
        finally:
            path.write_bytes(before)
    def refused(name, action, contains=None):
        begin = time.monotonic()
        try:
            action()
        except (ValueError, FileNotFoundError) as error:
            message = str(error)
            if contains is not None:
                q.need(contains in message, 'control failed outside intended guard: '+name+' '+message)
            events.append(dict(name=name, status='REJECTED', message=message, elapsed_seconds=time.monotonic()-begin))
        else:
            raise AssertionError('mutated filesystem evidence admitted: '+name)
    def mutate_json(path, change, name, contains=None):
        value = q.strict_json(path.read_bytes()); change(value)
        with changed(path, q.canonical(value)):
            refused(name, read_all, contains)
    native = copied/'native'
    summary = native/'NATIVE.json'
    raw = summary.read_bytes()
    with changed(summary, b'{"status":"PASS",'+raw.lstrip()[1:]):
        refused('duplicate_summary_member', read_all, 'duplicate JSON member')
    mutate_json(summary, lambda value: value.update(cases=122), 'forged_case_count', 'summary recomputation')
    source_path = native/'SOURCE.json'
    source = q.strict_json(source_path.read_bytes()); source['original_outputs_read'] = True
    with changed(source_path, q.canonical(source)):
        mutate_json(summary, lambda value: value.update(source=q.pin(source_path)),
                    'resigned_original_output_dependency', 'independent native source original_outputs_read')
    helper = copied/'source/tests/hia_native/filesystem_parity/cases.py'
    with changed(helper, helper.read_bytes()+b'\n'):
        refused('input_generator_changed', read_all, 'artifact bytes differ')
    executable = copied/'bundle/filesystem-parity.elf'
    with changed(executable, b'\0'+executable.read_bytes()[1:]):
        refused('physical_elf_corruption', read_all)
    module_receipt = copied/'bundle/owner/module.receipt.json'
    mutate_json(module_receipt, lambda value: value.update(result_u64=0), 'compiler_receipt_changed')
    original_source = copied/'original/source/original_parity_ops.rs'
    with changed(original_source, original_source.read_bytes()+b'\n'):
        refused('unchanged_original_module_changed', read_all, 'artifact bytes differ')
    held = executable.with_name('held-elf')
    executable.rename(held)
    try:
        refused('missing_required_build_artifact', read_all)
        executable.symlink_to(owners['bundle']/'filesystem-parity.elf')
        try:
            refused('artifact_symlink_outside_owner', read_all, 'symlink')
        finally:
            executable.unlink()
    finally:
        held.rename(executable)
    def stream_mutation(process_name, key, change, name, contains):
        process_path = native/'processes'/process_name/'process.json'
        all_path = native/'processes.json'
        process = q.strict_json(process_path.read_bytes())
        path = native/process[key]['path']; raw = path.read_bytes()
        altered = change(raw)
        compressed = path.with_name(path.name+'.gz')
        with changed(path, altered), changed(compressed, gzip.compress(altered, mtime=0)):
            process[key].update(q.pin(path))
            all_processes = q.strict_json(all_path.read_bytes())
            index = next(index for index, item in enumerate(all_processes) if item['name'] == process_name)
            all_processes[index] = process
            with changed(process_path, q.canonical(process)), changed(all_path, q.canonical(all_processes)):
                mutate_json(summary, lambda value: value.update(processes=q.pin(all_path)), name, contains)
    def changed_byte(raw, offset, value=None):
        result = bytearray(raw)
        result[offset] = result[offset] ^ 1 if value is None else value
        return bytes(result)
    stream_mutation('validation', 'stdout', lambda raw: changed_byte(raw, 96),
                    'resigned_terminal_redelivery_changed', 'terminal redelivery full bytes changed')
    stream_mutation('file_move', 'stderr', lambda raw: changed_byte(raw, 72, 7),
                    'resigned_call_owner_mask', 'ACK does not identify pending CALL')
    second = args.output/'moved-two'
    second.mkdir()
    copy_artifacts(second)
    second_reader = n.load(second/'qualification/strict_native.py', '_filesystem_second_relocated_reader')
    q.same(second_reader.native_evidence(second/'source', second/'bundle'/args.manifest.name,
                                        second/'native', second/'original'), baseline, 'second independent owner relocation')
    for root in (copied, second):
        for relative, sha in baseline['artifact_sha256'].items():
            q.same(q.pin(root/relative), {'bytes': baseline['artifact_bytes'][relative], 'sha256': sha}, 'all restored copied bytes')
    for relative, sha in baseline['artifact_sha256'].items():
        namespace, name = relative.split('/', 1)
        q.same(q.pin(owners[namespace]/name), {'bytes': baseline['artifact_bytes'][relative], 'sha256': sha}, 'original evidence stayed unchanged')
    result = dict(schema='hepta.runtime.filesystem-parity-native-first-controls.v1', status='PASS',
                  controls=len(events), relocations=2, artifacts=len(baseline['artifact_sha256']),
                  artifact_bytes=sum(baseline['artifact_bytes'].values()), events=events,
                  baseline_sha256=n.digest(q.canonical(baseline)), source_artifacts_unchanged=True,
                  live_fixture_dependencies=[], new_native_calls=0, new_rust_processes=0,
                  elapsed_seconds=time.monotonic()-started)
    with (args.output/'RESULT.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False); stream.write('\n')
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
