#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Source-only fixed closure, syntax and exact original-span checks."""
from pathlib import Path
import ast
from common import source_evidence, require
from prepare_reference import verify_reference

def check(source):
    source=Path(source);identity=source_evidence(source)
    py=0
    for path in source.rglob("*"):
        if path.suffix in (".py",".pseudo") and path.is_file():
            ast.parse(path.read_bytes(),filename=str(path));py+=1
    original=verify_reference(source)
    require(original["scope"]["original_tests"]==8 and original["scope"]["public_handler"] is False,
        "private reference scope changed")
    return dict(status="SOURCE_ONLY_PASS",source=identity,parsed_sources=py,original=original)
