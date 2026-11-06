#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Original held-agent entry point for the separately sealed async supplement."""
import argparse, hashlib, os, signal, sys, types
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r36')
RUNNER = {'path': '/home/qian/hepta-runtime-optimization-20261106-r36/supplement-tools-01/run_async_read_abba.py', 'bytes': 33485, 'sha256': '0ccc525e519e065fe5d0e640810f0da112f8c0c885f91ecf1aae26ee117d46e4'}
PROTOCOL_SHA = '78f908a031adb10491e9bb8e0ba6dadba21e2e5b30ea559b028062fbfefa3bf2'
HELPER_SHA = '7cb886eccbefb6f52464e2c0bbab995d185349864afd9f53eaf1a36334d0ae95'
args_parser = argparse.ArgumentParser()
args_parser.add_argument("--launcher-sha256", required=True)
args = args_parser.parse_args()
helper_path = ROOT / "tools-01/r36_campaign.py"
helper_raw = helper_path.read_bytes()
if hashlib.sha256(helper_raw).hexdigest() != HELPER_SHA:
    raise RuntimeError("reviewed helper differs")
helper = types.ModuleType("held_async_verified_helper")
helper.__file__ = str(helper_path)
exec(compile(helper_raw, str(helper_path), "exec"), helper.__dict__)
helper.checked(ROOT / "supplement-tools-01/held_async_read_supplement.py", args.launcher_sha256)
helper.checked(ROOT / "async-read-protocol-01.json", PROTOCOL_SHA)
_, raw = helper.checked(RUNNER["path"], RUNNER, retain=True)
module = types.ModuleType("held_async_read_original")
module.__file__ = RUNNER["path"]
exec(compile(raw, module.__file__, "exec"), module.__dict__)
sys.argv = [module.__file__, "--launcher-sha256", args.launcher_sha256, "--protocol-sha256", PROTOCOL_SHA]
os.umask(0o077)
for number in (signal.SIGINT, signal.SIGTERM):
    signal.signal(number, module.interrupted)
sys.exit(module.main())
