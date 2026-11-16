"""Run the full original SDK reader with file writes and execution denied."""
from pathlib import Path
import importlib.util
import json
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import verify
import read_only_guard

def main():
    args = verify.arguments()
    package = args.package.resolve(strict=True); run = args.run.resolve(strict=True)
    started = time.monotonic()
    result = read_only_guard.guarded(lambda: verify.verify(package, run), roots=[package, run],
                                     foreign_path=Path('/dev/null'))
    assert result['before'] == result['after'] and len(result['probes']) == 11
    print(json.dumps(dict(status='READ_ONLY_BELLMAN_PUBLIC_ORIGINAL_REFERENCE_PASS',
        evidence=result['evidence'], unchanged_entries=len(result['before']), guard_refusals=len(result['probes']),
        native_executions=0, rust_executions=0, reader_writes=0, wall_seconds=time.monotonic() - started), sort_keys=True))

if __name__ == '__main__':
    main()
