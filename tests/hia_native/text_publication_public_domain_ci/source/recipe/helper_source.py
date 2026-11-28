#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Use exact existing observational functions; no old CLI or cases execute."""
from pathlib import Path
import ast
import ctypes
import gzip
import hashlib
import json
import struct
import sys
import types

def prepare(source):
    raw=Path(source).read_bytes()
    assert hashlib.sha256(raw).hexdigest()=="3e69ac8d416b8cc249bdb7cd3fa98bb9139c41e46be5bea65883ada1e36197a5"
    tree=ast.parse(raw)
    names={"TypedInput","decode_records","canonical_snapshot"}
    selected=[node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names]
    assert {node.name for node in selected}==names and len(selected)==3
    module=types.ModuleType("retained_text75_observations")
    module.__dict__.update(Path=Path,ctypes=ctypes,gzip=gzip,json=json,sys=sys,struct=struct,
        sha=lambda b:hashlib.sha256(b).hexdigest(),
        Q=lambda *v:struct.pack("<"+"Q"*len(v),*v),
        U=lambda b,p:struct.unpack_from("<Q",b,p)[0],
        encode=lambda value:(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode())
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(source),"exec"),module.__dict__)
    return module
