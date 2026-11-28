"""Record fixed 180-second custody for pure archive restore/export processes."""
from pathlib import Path
import argparse
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import repair


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['restore', 'export'])
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    assert repair.identity() == args.source_manifest_sha256
    sys.path.insert(0, str(ROOT.parent / 'audit_retention'))
    from process import Recorder
    destination = args.destination.absolute()
    recorder = Recorder(ROOT, destination.parent / 'audit-retention-recovery-stage-processes' / args.stage)
    argv = [sys.executable, '-I', '-B', ROOT / 'run_ci.py', args.stage, '--destination', destination,
            '--source-manifest-sha256', args.source_manifest_sha256]
    try:
        raw, row = recorder.run(args.stage, argv, timeout=180)
        print(raw.decode(), end='')
    except BaseException:
        print((recorder.directory / (args.stage + '.stderr')).read_text(), file=sys.stderr)
        raise


if __name__ == '__main__':
    main()
