#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Load the frozen prior reader with its own exact source-closure functions."""
from pathlib import Path
import importlib.util,sys
from async_build_common import require,files,raw
import read_graph,dynamic_builder
HERE=Path(__file__).resolve().parent.parent/"previous-build"
LOADED=None
def load():
    global LOADED
    if LOADED is not None:return LOADED
    original=sys.modules["async_build_common"]
    def module(name,path):
        spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
    try:
        old=module("publication_exact_previous_common",HERE/"async_build_common.py")
        old.package()
        sys.modules["async_build_common"]=old
        reader=module("publication_exact_previous_reader",HERE/"read_build.py")
    finally:sys.modules["async_build_common"]=original
    LOADED=reader;return reader
def prepare(previous):
    previous=Path(previous).resolve(strict=True)
    require(files(previous.parent/"recipe-source")==files(HERE),"all44 prior recipe bytes/modes")
    read_graph.prepare(previous/"retained");dynamic_builder.load(previous/"source")
    return load()
