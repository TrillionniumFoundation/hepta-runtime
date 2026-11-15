"""Verify the exact unmodified source slices before any original execution."""
from pathlib import Path
import hashlib
import json


def verify(runtime, harness=None):
    harness = Path(harness or Path(__file__).resolve().parent)
    manifest = json.loads((harness/'source_manifest.json').read_bytes())
    raw = (Path(runtime)/manifest['source']).read_bytes()
    assert len(raw) == manifest['source_bytes']
    assert hashlib.sha256(raw).hexdigest() == manifest['source_sha256']
    start = raw.index(b'#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\n#[serde(rename_all = "snake_case")]\npub enum BatchEditOperationType')
    end = raw.index(b'#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct ExtractLinesParams', start)
    schema_start = raw.index(b'fn line_endpoint_schema(')
    schema_end = raw.index(b'\n}\n', schema_start)+3
    parts = {'line_endpoint_schema': raw[schema_start:schema_end],
             'batch_types_and_deserializer': raw[start:end]}
    for key, value in parts.items():
        assert {'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()} == manifest['sections'][key]
    original = b'\n'.join(parts.values())
    assert original == (harness/'src/original.rs').read_bytes()
    assert len(original) == manifest['original_bytes']
    assert hashlib.sha256(original).hexdigest() == manifest['original_sha256']
    return manifest
