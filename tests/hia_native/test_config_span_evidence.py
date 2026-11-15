"""Execute every physical refusal and both independent native evidence relocations."""
from pathlib import Path
import argparse
import json
import runpy
import sys

ROOT = Path(__file__).resolve().parents[2]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    roots = args.output.parent / 'roots.json'
    with roots.open('x') as stream:
        json.dump(dict(source=str(ROOT), build=str(args.manifest.resolve().parent),
                       capture=str(args.native.resolve())), stream, sort_keys=True, indent=2)
        stream.write('\n')
    script = ROOT / 'tests/hia_native/config_span/test_evidence.py'
    sys.argv = [str(script), '--reader', str(ROOT / 'scripts/hia_native_config_span_qualification.py'),
                '--roots', str(roots), '--output', str(args.output.resolve())]
    runpy.run_path(str(script), run_name='__main__')
