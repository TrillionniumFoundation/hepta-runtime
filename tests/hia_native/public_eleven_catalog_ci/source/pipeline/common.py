"""Fixed source admission and complete-buffer evidence for the 11-tool owner."""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from domain import FLAGS, SELECTED_TOOLS, TARGET
TRUSTED_PROFILE = (ROOT / 'source-profile.json').read_bytes()
_BASE_READER = None

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}

def put(path, value):
    raw = value if type(value) is bytes else encoded(value)
    with Path(path).open('xb') as stream:
        assert stream.write(raw) == len(raw)

def base_reader(source=ROOT):
    # The verifier is code from this fixed package, never from an evidence
    # clone passed by the caller. Such clones are only checked byte data.
    global _BASE_READER
    if _BASE_READER is not None:
        return _BASE_READER
    path = ROOT / 'policy_base/read_catalog.py'
    spec = importlib.util.spec_from_file_location('retained_catalog_reader', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    _BASE_READER = module
    return _BASE_READER

def source_check(source=ROOT):
    source = Path(source).resolve(strict=True)
    base = base_reader(source)
    retained, asset, tools, body = base.source_check(source / 'policy_base')
    reader = base.Reader(source)
    profile_raw = reader.raw('source-profile.json')
    assert profile_raw == TRUSTED_PROFILE
    profile = base.parse(profile_raw)
    assert profile['schema'] == 'hepta.runtime.public-eleven-source.v1'
    assert profile['target_commit'] == TARGET
    actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}
    assert actual == set(profile['files']) | {'source-profile.json'}
    for name, expected in profile['files'].items(): reader.raw(name, expected)
    proof = reader.document('native/projection-proof.json')
    assert proof['source_sha256'] == sha(reader.raw('native/catalog_eleven_policy.hepta'))
    assert proof['author_sha256'] == sha(reader.raw('author_projection.py'))
    assert proof['domain_sha256'] == sha(reader.raw('domain.py'))
    assert proof['baseline_table_reproduced_exactly'] is True
    assert proof['selected_tools'] == list(SELECTED_TOOLS)
    assert proof['expected_wire_used_as_implementation'] is False
    return base, reader, asset, tools, body

def module_pins(source=ROOT):
    return {
        'catalog-eleven-policy': ('native/catalog_eleven_policy.hepta',
            sha((source / 'native/catalog_eleven_policy.hepta').read_bytes()), 'standard'),
        'serde-json': ('policy_base/native/serde_json.hepta',
            'ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18', 'serde-json.v1'),
        'sdk-catalog-wide': ('policy_base/native/sdk_catalog.hepta',
            '756f1c990a20a268a5ad0b4e4007382e7ace1f99cb5f0a9cd65b0d6b621ba181', 'serde-json.v1'),
    }

def build_check(build, source=ROOT):
    base = base_reader(source)
    # Reuse the exact already qualified compiler/receipt reader with a closed
    # new source inventory. All module profiles keep its original capacities.
    original_inventory = base.SOURCE_PINS
    try:
        base.SOURCE_PINS = module_pins(source)
        return base.build_check(build, source)
    finally:
        base.SOURCE_PINS = original_inventory

def shape_domain():
    return [(flags, modern) for flags in FLAGS for modern in (0, 1)]

def record(folder, label, wire, code, output, workspace):
    row = {'prefix': label, 'code': code, 'input_sha256': sha(wire),
        'output_sha256': sha(output), 'workspace_sha256': sha(workspace),
        'output_capacity': len(output), 'workspace_capacity': len(workspace)}
    for suffix, raw in (('input', wire), ('output', output), ('workspace', workspace)):
        put(folder / (label + '.' + suffix + '.gz'), gzip.compress(raw, compresslevel=1, mtime=0))
    return row

def load_module(build, name, source=ROOT):
    sys.path.insert(0, str(source / 'policy_base/runtime_support/scripts'))
    from hia_native_loader import NativeModule
    path = build / 'modules' / name / 'manifest.json'
    return NativeModule(path, manifest_sha256=sha(path.read_bytes()))
