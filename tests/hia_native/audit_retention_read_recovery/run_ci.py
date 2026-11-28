"""Bounded process custody around inert recovery stages."""
from pathlib import Path
import argparse
import json
import os
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import archive
import repair


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['restore','read','controls','independent','export'])
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    assert repair.identity() == args.source_manifest_sha256
    destination = args.destination.absolute()
    if args.stage == 'restore':
        result = archive.restore(ROOT, destination)
    elif args.stage == 'export':
        result = archive.export(ROOT, destination, destination.parent / 'audit-retention-recovery.tar.gz')
    else:
        original = destination / 'producer/source'
        output = destination / 'producer/run'
        sys.path.insert(0, str(original))
        from process import Recorder
        recorder = Recorder(ROOT, destination / 'processes' / args.stage)
        argv = [sys.executable, '-I', '-B', ROOT / 'repair.py', '--source', original, '--output', output,
                '--source-manifest-sha256', args.source_manifest_sha256]
        if args.stage == 'controls':
            argv.extend(['--mode', 'controls'])
        if args.stage == 'independent':
            argv.append('--require-controls')
        try:
            raw, row = recorder.run(args.stage, argv, timeout=180)
            proof = json.loads(raw)
            result = dict(stage=args.stage, status='PASS', process=row,
                          preserved_producer_files=archive.preserve_original(destination),
                          semantic_reexecutions=0)
            if args.stage != 'controls':
                assert proof['before'] == proof['after'] and len(proof['probes']) == 12
                assert proof['native_or_rust_executions'] == proof['reader_writes'] == 0
                result['evidence'] = proof['evidence']
            (destination / (args.stage.upper() + '.json')).write_bytes(archive.encoded(result))
        except BaseException:
            for path in sorted((destination / 'processes' / args.stage).glob('*.stderr')):
                print(path.read_text(), file=sys.stderr)
            raise
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
