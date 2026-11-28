"""Shared byte-only proof and archive primitives."""
from pathlib import Path
import hashlib
import json

def require(value, message):
    if not value: raise ValueError(message)

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate evidence key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def pin(path):
    p = Path(path)
    with p.open("rb") as stream:
        return dict(bytes=p.stat().st_size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())
