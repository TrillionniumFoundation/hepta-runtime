"""Run the four complete native configuration span domains."""
from pathlib import Path
import argparse
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[2]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    path = ROOT / 'tests/hia_native/config_span/run.py'
    spec = importlib.util.spec_from_file_location('_config_span_native_run', path)
    producer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(producer)
    result = producer.execute_native(args.manifest, args.output, source_root=ROOT)
    print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)
