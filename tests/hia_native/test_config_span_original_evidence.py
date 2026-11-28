"""Execute complete fresh-original evidence refusals and independent relocations."""
from pathlib import Path
import argparse
import runpy
import sys

ROOT = Path(__file__).resolve().parents[2]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = ROOT / 'tests/hia_native/config_span/guard_original'
    script = source / 'test_reference_evidence.py'
    sys.argv = [str(script), '--reader', str(source / 'strict_reference.py'), '--source', str(source),
                '--capture', str(args.capture.resolve()), '--output', str(args.output.resolve())]
    runpy.run_path(str(script), run_name='__main__')
