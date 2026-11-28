"""Reject physical session corpus, compiled-image and process-receipt changes."""
from pathlib import Path
import argparse
import json
import os
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path[:0] = [str(ROOT / 'scripts'), str(REFERENCE / 'scripts')]
import hia_native_session_qualification as q


def replace(path, raw):
    temporary = path.with_name(path.name + '.mutation')
    with temporary.open('xb') as stream:
        stream.write(raw)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=ROOT)
    parser.add_argument('--reference', type=Path, default=REFERENCE)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--stdout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recorded-output', type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    root, ref = args.runtime.resolve(strict=True), args.reference.resolve(strict=True)
    bundle, corpus, stdout = (p.resolve(strict=True) for p in (args.bundle, args.corpus, args.stdout))
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False, mode=0o700)
    original_output = bundle.parents[3]
    recorded_output = args.recorded_output or original_output
    baseline = q.checked_native(root, bundle, corpus, args.hepta, stdout, reference_root=ref,
                                recorded_output=recorded_output)
    def snapshot(parent):
        sources, reference, observed = parent / 'source', parent / 'reference', parent / 'evidence'
        for origin, target, kind in ((root, sources, 'owner'), (ref, reference, 'reference')):
            for name in baseline['source_pins'][kind]:
                path = target / name; path.parent.mkdir(parents=True, exist_ok=True)
                os.link(origin / name, path)
        for name in baseline['artifact_sha256']:
            path = observed / name; path.parent.mkdir(parents=True, exist_ok=True)
            os.link(original_output / name, path)
        return sources, reference, observed
    def check(sources, reference, observed):
        return q.checked_native(sources, observed / bundle.relative_to(original_output),
            observed / corpus.relative_to(original_output), args.hepta,
            observed / stdout.relative_to(original_output), reference_root=reference,
            recorded_output=recorded_output)
    labels = ('source', 'proof', 'image', 'compile-receipt', 'elf', 'call-table', 'workspace',
              'bundle-scope', 'native-scope', 'missing-wide-response', 'missing-row',
              'duplicate-stdout', 'elf-argument', 'missing-elf-stream', 'native-count')
    refusals = []
    with tempfile.TemporaryDirectory(prefix='session-evidence-', dir=original_output.parent) as temp:
        sources, reference, observed = snapshot(Path(temp) / 'positive')
        q.exact(check(sources, reference, observed), baseline, 'unmodified relocated evidence differs')
        for index, label in enumerate(labels):
            sources, reference, observed = snapshot(Path(temp) / str(index))
            cloned_bundle = observed / bundle.relative_to(original_output)
            cloned_corpus = observed / corpus.relative_to(original_output)
            meta = q.object_at(cloned_bundle)
            module_path = q.relative(cloned_bundle.parents[2], meta['module'])
            module = q.object_at(module_path)
            fixture_path = q.relative(cloned_bundle.parents[2], meta['fixture'])
            fixture = q.object_at(fixture_path)
            if label in ('source', 'proof'):
                name = 'native/session_workdir.' + ('hepta' if label == 'source' else 'invalid')
                path = sources / ('native/session_workdir_composition.json' if label == 'proof' else name)
                replace(path, path.read_bytes() + b'\n')
            elif label in ('image', 'elf'):
                path = (q.relative(module_path.parent, module['image']) if label == 'image'
                        else fixture_path.parent / fixture['executable'])
                raw = bytearray(path.read_bytes()); raw[-1] ^= 1; replace(path, raw)
            elif label == 'compile-receipt':
                path = module_path.parent / 'module.receipt.json'
                data = q.object_at(path); data['source_unchanged'] = False
                replace(path, q.json_bytes(data))
            elif label in ('call-table', 'workspace'):
                fixture['profile'][1]['workspace_capacity' if label == 'workspace' else 'call_mask'] = 1
                replace(fixture_path, q.json_bytes(fixture))
            elif label == 'bundle-scope':
                meta['whole_runtime_replaced'] = True; replace(cloned_bundle, q.json_bytes(meta))
            elif label in ('native-scope', 'native-count'):
                path = cloned_corpus / 'result.json'; data = q.object_at(path)
                if label == 'native-scope':
                    data['public_workdir_handler_complete'] = True
                else:
                    data['counts']['reference_rows'] -= 1
                replace(path, q.json_bytes(data))
                replace(observed / stdout.relative_to(original_output), q.json_bytes(data))
            elif label in ('missing-wide-response', 'missing-row'):
                path = cloned_corpus / ('native-output.bin.gz' if label == 'missing-wide-response' else 'rows.jsonl.gz')
                replace(path, path.read_bytes()[:-5])
            elif label == 'duplicate-stdout':
                path = observed / stdout.relative_to(original_output); replace(path, path.read_bytes() * 2)
            elif label == 'elf-argument':
                path = cloned_corpus / 'elf-0.process.json'; data = q.object_at(path)
                data['command'].append('--other-session'); replace(path, q.json_bytes(data))
            else:
                (cloned_corpus / 'elf-7.stdout.gz').unlink()
            try:
                check(sources, reference, observed)
            except (ValueError, KeyError, OSError, EOFError) as error:
                refusals.append({'label': label, 'refused': True, 'reason': str(error)})
            else:
                raise AssertionError('altered session evidence was admitted: ' + label)
    q.exact(q.checked_native(root, bundle, corpus, args.hepta, stdout, reference_root=ref,
                            recorded_output=recorded_output),
            baseline, 'evidence controls changed immutable original bytes')
    report = {'schema': 'hepta.runtime.session-evidence-controls.v1', 'status': 'PASS',
        'accepted': 2, 'refusals': len(refusals), 'controls': refusals,
        'source_pins': q.source_pins(root, ref), 'baseline_sha256': q.sha(q.json_bytes(baseline)),
        'native_calls_added': 0, 'rust_calls_added': 0, 'elapsed_seconds': time.monotonic() - started,
        'production_activated': False, 'whole_runtime_replaced': False}
    (output / 'result.json').write_bytes(q.json_bytes(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
