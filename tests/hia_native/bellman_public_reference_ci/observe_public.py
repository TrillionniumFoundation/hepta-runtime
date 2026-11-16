"""CI-only serial public SDK observation; no response bytes are manufactured."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from process_capture import run, put
from wire_cases import rows, frame, domain, pin

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'original execution is restricted to fresh CI'
    source = json.loads((ROOT / 'package-manifest.json').read_bytes())
    for name, expected in source['files'].items():
        assert pin((ROOT / name).read_bytes()) == expected, name
    frozen = json.loads((ROOT / 'wire-domain.json').read_bytes())
    assert domain() == frozen
    output = a.output.resolve(); output.mkdir()
    request = b''.join(frame(row, wire) for row, wire in rows())
    put(output / 'public.stdin', request)
    binary = a.original.resolve() / 'original-public'
    env = dict(os.environ)
    env.update(RUSTUP_TOOLCHAIN='1.95.0', PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0')
    process = run(output, 'public-original', [str(binary)], env,
                  limit=frozen['public_process_deadline_seconds'], stdin=request)
    put(output / 'report.json', dict(status='PUBLIC_SDK_BYTES_OBSERVED_READER_REQUIRED',
        source_manifest=pin((ROOT / 'package-manifest.json').read_bytes()),
        domain=pin((ROOT / 'wire-domain.json').read_bytes()), binary=pin(binary.read_bytes()),
        input=pin(request), output={k: process['stdout'][k] for k in ['bytes', 'sha256']},
        records=frozen['records'], public_cases=1366, full_server_router_qualified=False,
        audit_qualified=False, async_pending_registry_qualified=False, native_executed=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False))
    print(json.dumps(dict(status='PUBLIC_SDK_BYTES_OBSERVED_READER_REQUIRED', records=frozen['records'],
                         public_cases=1366, input_bytes=len(request), output=process['stdout']), sort_keys=True))

if __name__ == '__main__':
    main()
