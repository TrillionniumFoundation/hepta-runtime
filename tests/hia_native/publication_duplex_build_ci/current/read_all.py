#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full unchanged predecessors plus all four actual linked and packed entries."""
from pathlib import Path
import sys
from async_build_common import *
import read_graph,dynamic_builder,read_build,previous_reader,read_only_guard as guard
def prepare(output):
    output=Path(output).resolve(strict=True);predecessor=output/"prior/capture"
    old=previous_reader.prepare(predecessor);dynamic_builder.load(output/"source")
    return old,predecessor
def operation(output,prepared):
    old,predecessor=prepared;_,original,retained=old
    return dict(previous=previous_reader.verify(predecessor,old),current=read_build.verify(retained,output,original))
def checked(output,*,roots=None):
    prepared=prepare(output)
    return guard.guarded(lambda:operation(Path(output),prepared),
        roots=roots or [Path(output),HERE.parent],foreign_path=Path("/dev/null"))
