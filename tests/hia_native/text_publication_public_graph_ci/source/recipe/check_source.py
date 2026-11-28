#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import argparse
import json
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from callable_common import syntax
p = argparse.ArgumentParser()
p.add_argument("--source", type=Path, required=True)
a = p.parse_args()
print(json.dumps(syntax(a.source.resolve(strict=True)), sort_keys=True))
