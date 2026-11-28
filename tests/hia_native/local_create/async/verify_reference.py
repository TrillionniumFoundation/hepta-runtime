"""Verify the exact original function and the locked reference dependency scope."""
from pathlib import Path
import hashlib
import json
import tomllib

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(root=HERE):
    root = Path(root)
    identity = json.loads((root / 'source-extraction.json').read_bytes())
    reference = root / 'reference'
    target = (reference / 'file_ops.rs').read_bytes()
    assert len(target) == identity['target_bytes']
    assert sha(target) == identity['target_sha256']
    assert hashlib.sha1(b'blob ' + str(len(target)).encode() + b'\0' + target).hexdigest() == identity['target_git_blob']
    body = target[identity['function_start']:identity['function_end']]
    assert len(body) == identity['original_function_bytes'] == 242
    assert sha(body) == identity['function_sha256'] == 'c0b4807c4ba4ebd00a41987cbfb95d802f17ab391802314f6fdcc6e685aa22fc'
    included = (reference / 'src/original_function.rs').read_bytes()
    assert included == bytes.fromhex(identity['wrapper_prefix_hex']) + body + b'\n'
    driver = (reference / 'src/main.rs').read_bytes()
    assert driver.count(b'include!("original_function.rs");') == 1
    assert b'async fn create_local_file' not in driver
    cargo = tomllib.loads((reference / 'Cargo.toml').read_text())
    assert cargo['dependencies'] == {'tokio': {'version': '=1.53.1', 'features': ['rt', 'fs', 'io-util']}}
    lock = tomllib.loads((reference / 'Cargo.lock').read_text())
    assert {(p['name'], p['version']) for p in lock['package']} == {
        ('hepta-local-create-original-oracle', '0.1.0'), ('tokio', '1.53.1'),
        ('bytes', '1.12.1'), ('pin-project-lite', '0.2.17')}
    result = dict(status='EXACT_ORIGINAL_SOURCE_PASS', original_function_bytes=242,
                  original_function_sha256=sha(body), target_commit=identity['target_commit'],
                  process_deadline_seconds=identity['original_process_deadline_seconds'],
                  private_scheduling_profile=identity['runtime_profile'],
                  files={str(p.relative_to(root)): dict(bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
                         for p in sorted(reference.rglob('*')) if p.is_file() and 'target' not in p.parts},
                  actual_rust_execution=False, public_handler_qualified=False, whole_runtime_replaced=False)
    return result


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True, indent=2))
