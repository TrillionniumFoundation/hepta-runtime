#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""One guarded complete read of predecessor and mechanically relinked graph."""
from pathlib import Path
import sys
from async_build_common import *
import read_graph,dynamic_builder,read_build,previous_reader,read_only_guard as guard
def prepare(output):
    output=Path(output).resolve(strict=True);previous=output/"previous/capture"
    before=previous_reader.prepare(previous);dynamic_builder.load(output/"source")
    return before,previous
def operation(output,prepared):
    before,previous=prepared;retained=previous/"retained"
    return dict(previous=before.verify(retained,previous),current=read_build.verify(retained,output,previous))
def checked(output,*,roots=None):
    prepared=prepare(output)
    return guard.guarded(lambda:operation(Path(output),prepared),roots=roots or [Path(output),HERE.parent],foreign_path=Path("/dev/null"))
