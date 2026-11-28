#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Recompose only the test-owned wrapper; the target methods stay byte-exact."""
from pathlib import Path
import json
def verify(root):
    root=Path(root)
    base=(root/"retained/private-main.rs.txt").read_bytes()
    peer=(root/"retained/extract-public-main.rs.txt").read_bytes()
    top=base[:base.index(b"fn word(raw:")]
    for row in json.loads((root/"authoring/wrapper-changes.json").read_bytes()):
        old,new=row["before"].encode(),row["after"].encode()
        assert top.count(old)==1
        top=top.replace(old,new)
    helpers=peer[peer.index(b"fn word(raw:"):peer.index(b"struct WireSession {")]
    session=peer[peer.index(b"struct WireSession {"):]
    for row in json.loads((root/"authoring/session-changes.json").read_bytes()):
        old,new=row["before"].encode(),row["after"].encode()
        assert session.count(old)==1
        session=session.replace(old,new)
    result=top+(root/"authoring/public-adapter.rs.txt").read_bytes()+helpers+session
    assert result==(root/"reference/src/main.rs").read_bytes()
    return {"status":"EXACT_OBSERVER_WRAPPER_COMPOSITION_PASS","target_source_changed":False,
        "actual_serve":True,"actual_tool_call_context":True,"actual_async_method_adapter":True,
        "reference_executed":False}
