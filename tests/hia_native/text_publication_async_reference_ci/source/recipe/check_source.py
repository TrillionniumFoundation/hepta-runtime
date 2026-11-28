#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"))
from verify_reference import verify,identity
manifest=json.loads((ROOT/"SOURCE_MANIFEST.json").read_bytes())
actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file()}
assert actual=={r["path"] for r in manifest["files"]}|{"SOURCE_MANIFEST.json"}
for row in manifest["files"]:
    raw=(ROOT/row["path"]).read_bytes()
    assert identity(raw)=={k:row[k] for k in ("bytes","sha256","git_blob")},row["path"]
    assert (ROOT/row["path"]).stat().st_mode&0o777==0o644,row["path"]
    if row["path"].endswith(".py"):compile(raw,row["path"],"exec")
print(json.dumps(verify(ROOT/"reference"),sort_keys=True))
