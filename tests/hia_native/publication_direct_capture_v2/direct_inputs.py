#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Encode only actual input parameters; never manufacture a handler result."""
import json,struct
from common import require
def gateway(step):
    require(step["kind"] in ("direct_start","direct_unpolled_drop"),"direct source operation")
    require(type(step["parameters"]) is dict and step["metadata"] is None,"frozen None metadata direct input")
    raw=json.dumps(step["parameters"],ensure_ascii=False,separators=(",",":")).encode()
    return b"HTPWGQ03"+struct.pack("<5Q",1,len(raw),0,0,0)+raw
def auxiliary_body(path):
    p=str(path).encode();content=b"owned queue-slot holder\n";expected=b"absent"
    return b"HTPBQ001"+struct.pack("<7Q",1,0,1,len(p),len(content),len(expected),
        len(p)+len(content)+len(expected))+p+content+expected
