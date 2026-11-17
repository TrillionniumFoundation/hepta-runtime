#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Load every exact retained full reader before entering the read-only guard."""
from pathlib import Path
import importlib.util,sys
from async_build_common import require,files,raw
import read_graph,dynamic_builder
HERE=Path(__file__).resolve().parent.parent/"prior-build"
LOADED=None
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def load():
    global LOADED
    if LOADED is not None:return LOADED
    current=sys.modules["async_build_common"]
    try:
        latest=module("duplex_exact_immediate_common",HERE/"current/async_build_common.py")
        latest.package();sys.modules["async_build_common"]=latest
        immediate=module("duplex_exact_immediate_reader",HERE/"current/read_build.py")
        earlier=module("duplex_exact_previous_common",HERE/"previous-build/async_build_common.py")
        earlier.package();sys.modules["async_build_common"]=earlier
        prior=module("duplex_exact_previous_reader",HERE/"previous-build/read_build.py")
    finally:sys.modules["async_build_common"]=current
    LOADED=(prior,immediate);return LOADED
def prepare(predecessor):
    predecessor=Path(predecessor).resolve(strict=True)
    require(files(predecessor.parent/"recipe-source")==files(HERE),"all63 immediate recipe bytes")
    original=predecessor/"previous/capture";retained=original/"retained"
    require(files(original.parent/"recipe-source")==files(HERE/"previous-build"),"all44 original recipe bytes")
    read_graph.prepare(retained);dynamic_builder.load(original/"source");dynamic_builder.load(predecessor/"source")
    return load(),original,retained
def verify(predecessor,prepared):
    (prior,immediate),original,retained=prepared
    return dict(retained=read_graph.verify(retained),original=prior.verify(retained,original),
        immediate=immediate.verify(retained,predecessor,original))
