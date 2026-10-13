#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit successor verification before running unchanged v4 file regressions.

The full successor is verified first. Only then is the exact v4 subset returned
to historical operation tests. This never treats an extra unreviewed tool as
compatible or qualifies the new capabilities merely by projecting the catalog.
"""
import hashlib
import pathlib
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract

ADDITIONS={'host_health','read_multiple_files','search_start','search_results','search_list','search_stop'}

AUDIT_CONFIG_ADDITIONS={'effective_config','request_history'}

def verify_successor(tools,path):
    successor=pathlib.Path(path)
    contract=ToolContract.load(successor,hashlib.sha256(successor.read_bytes()).hexdigest())
    contract.verify(tools)
    v4file=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'
    baseline=ToolContract.load(v4file,'d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1')
    expected = ADDITIONS if len(contract.tools)==56 else ADDITIONS | AUDIT_CONFIG_ADDITIONS
    assert set(contract.by_name)-set(baseline.by_name)==expected,'unexpected successor additions'
    assert len(contract.tools) in (56,58)
    if len(contract.tools)==58:
        v5file=ROOT/'deploy/contracts/hepta-runtime-full-operator-v5.json'
        v5=ToolContract.load(v5file,'f3fd365ae69e1189c550c4314c4fdfb12f4c80d8cc86d1bc0aca6bd1bf7c4cba')
        assert all(contract.by_name[n]==v for n,v in v5.by_name.items()),'v5 definition drift'
    assert all(contract.by_name[n]==v for n,v in baseline.by_name.items()),'v4 definition drift'
    return [t for t in tools if t['name'] in baseline.by_name]
