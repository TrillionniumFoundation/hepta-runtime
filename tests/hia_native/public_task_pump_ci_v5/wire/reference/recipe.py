"""Fresh CI-only reference through unchanged target code and the actual SDK."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from original_reader import source, pin
from process_capture import run, put

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'original Rust executions are restricted to fresh CI'
    source_manifest = source(ROOT)
    output = args.output.resolve(); output.mkdir(mode=0o700)
    shutil.copytree(ROOT, output / 'recipe-source')
    env = dict(os.environ)
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0', RUSTUP_TOOLCHAIN='1.95.0')
    python = [sys.executable, '-I', '-S', '-B']
    result = dict(status='RUNNING', source_manifest=source_manifest,
        git_head=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
        attempt=os.environ.get('GITHUB_RUN_ATTEMPT'), public_handler_qualified=False,
        full_server_router_qualified=False, audit_qualified=False, async_pending_registry_qualified=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False)
    started = time.monotonic()
    try:
        run(output, 'original', python + [str(ROOT / 'observe_full_original.py'),
            '--output', str(output / 'original')], env, limit=600)
        run(output, 'public', python + [str(ROOT / 'observe_public.py'),
            '--original', str(output / 'original'), '--output', str(output / 'public')], env, limit=180)
        run(output, 'readonly', python + [str(ROOT / 'readonly.py'), '--package', str(ROOT),
            '--run', str(output)], env, limit=180)
        proof = json.loads((output / 'processes/readonly.stdout').read_bytes())
        assert proof['status'] == 'READ_ONLY_BELLMAN_PUBLIC_ORIGINAL_REFERENCE_PASS'
        assert proof['guard_refusals'] == 11 and proof['reader_writes'] == 0
        assert proof['native_executions'] == proof['rust_executions'] == 0
        assert proof['evidence']['public']['public_cases'] == 1366
        result.update(status='FRESH_BELLMAN_PUBLIC_ORIGINAL_REFERENCE_PASS',
            complete_original_cases=683, complete_public_cases=1366,
            read_only=pin((output / 'processes/readonly.stdout').read_bytes()))
    except BaseException as exc:
        result.update(status='FAIL', failure=dict(type=type(exc).__name__, message=str(exc)))
        raise
    finally:
        result['wall_seconds'] = time.monotonic() - started
        put(output / 'run.json', result)
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
