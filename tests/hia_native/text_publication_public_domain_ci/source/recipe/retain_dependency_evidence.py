#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Copy only complete dependency indices/receipts; parent archives retain every build byte."""
from pathlib import Path
import argparse,shutil
p=argparse.ArgumentParser();p.add_argument("--dependencies",type=Path,required=True)
p.add_argument("--output",type=Path,required=True);a=p.parse_args()
assert not a.output.exists();a.output.mkdir(parents=True)
names=["DEPENDENCIES.json","graph/FILES.json","graph/ARCHIVE.json",
    "graph/extracted/capture/native-build/BUILD.json",
    "graph/extracted/capture/composition/source/native/runtime_mcp_sources.json",
    "reference/FILES.json","reference/ARCHIVE.json","reference/extracted/capture/BUILD.json",
    "reference/extracted/capture/source-closure.json","reference/extracted/capture/processes.json",
    "reference/extracted/capture/registry-sources.json",
    "reference/extracted/recipe-source/reference/source_manifest.json"]
for name in names:
    target=a.output/name;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(a.dependencies/name,target)
