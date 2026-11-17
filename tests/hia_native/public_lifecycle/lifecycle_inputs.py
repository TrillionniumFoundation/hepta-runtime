# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Small exact-file input primitives shared by the public lifecycle tests."""
from pathlib import Path
import hashlib

def pin(path, expected=None):
    path=Path(path)
    assert path.is_file() and not path.is_symlink(), path
    raw=path.read_bytes()
    result=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    if expected is not None:assert result==expected, path
    return result
