"""Reproduce the complete unchanged Linux module and original locked subset."""
from pathlib import Path
import hashlib
import json
import shutil
import tomllib

SOURCE_SHA = '0e608303d16c22b95dc99bae2e6bb00ba0571872f52d15a7fe8e2f021286ccc1'
MODULE_SHA = '41a661a04712855dc00870432601e36f6c8e893ba8e56901611c5955e3f62a07'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def assemble(source):
    original = (source/'original_parity_ops.rs').read_bytes()
    assert pin(original) == {'bytes': 11952, 'sha256': SOURCE_SHA}
    module = original[5405:11895]
    assert pin(module) == {'bytes': 6490, 'sha256': MODULE_SHA}
    driver = (source/'src/driver.rs').read_bytes()
    generated = b'// Actual unchanged local_linux module with private observation harness.\n'+module+b'\n'+driver
    assert generated.count(module) == 1
    original_lock = tomllib.loads((source/'original-runtime.lock').read_text())['package']
    expected = {(p['name'], p['version'], p.get('source')): p.get('checksum') for p in original_lock}
    locked = tomllib.loads((source/'Cargo.lock').read_text())['package']
    registry = {}
    for row in locked:
        if 'source' not in row:
            assert row['name'] == 'hepta-filesystem-parity-original' and row['version'] == '0.1.0'
        else:
            key = row['name'], row['version'], row['source']
            assert key in expected and expected[key] == row['checksum']
            registry[row['name']] = {'version': row['version'], 'source': row['source'], 'checksum': row['checksum']}
    assert set(registry) == {'anyhow', 'libc'}
    proof = {'schema': 'hepta.runtime.filesystem-parity-original-source.v1', 'original_source': pin(original),
        'unchanged_module': {'start': 5405, 'end': 11895, **pin(module)}, 'driver': pin(driver),
        'generated_source': pin(generated), 'registry_dependencies': registry,
        'local_linux_module_unchanged': True, 'public_wrapper_executed': False,
        'async_wrapper_executed': False, 'cache_session_qualified': False, 'native_qualified': False}
    return generated, proof


def materialize(source, output):
    generated, proof = assemble(source)
    output.mkdir(mode=0o700); (output/'src').mkdir()
    for name in ('Cargo.toml', 'Cargo.lock'): shutil.copyfile(source/name, output/name)
    (output/'src/main.rs').write_bytes(generated)
    return proof
