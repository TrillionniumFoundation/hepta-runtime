#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run the independent Hepta computer-use owner on private IPv4 loopback."""
import argparse
import json
import os
import pathlib
import signal
import stat
import threading
import time
from dc_compat.engine import Operator
from dc_compat.http_server import OperatorHTTP
from chatgpt_full_operator import private_token


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, type=pathlib.Path)
    parser.add_argument('--workspace', required=True, type=pathlib.Path)
    parser.add_argument('--token-file', required=True, type=pathlib.Path)
    parser.add_argument('--document-python', required=True)
    parser.add_argument('--port', default=8794, type=int)
    parser.add_argument('--initial-settings', type=pathlib.Path)
    parser.add_argument('--state-device', type=int)
    parser.add_argument('--state-inode', type=int)
    parser.add_argument('--without-computer', action='store_true')
    parser.add_argument('--acknowledge-full-operator', required=True, action='store_true')
    args = parser.parse_args()
    if not args.state.is_absolute() or not args.workspace.is_absolute():
        parser.error('absolute private state and workspace paths required')
    if (args.state_device is None) != (args.state_inode is None):
        parser.error('both original state identity fields are required')
    if args.state_device is not None:
        info = args.state.lstat()
        if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (args.state_device, args.state_inode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise RuntimeError('Original private computer owner state root is missing or replaced; no fresh owner started')
    os.umask(0o077)
    initial = json.loads(args.initial_settings.read_bytes()) if args.initial_settings else None
    engine = Operator(args.state, args.workspace, document_python=args.document_python,
                      initial=initial, enable_computer=not args.without_computer)
    if set(row['name'] for row in engine.registry.tools()) != engine.registry.implemented_tools:
        raise RuntimeError('Refusing to advertise a partially implemented computer-use catalog')
    owner = OperatorHTTP(engine, private_token(args.token_file), port=args.port)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    try:
        while not stop.wait(0.1) and not engine.shutdown_requested.is_set():
            pass
    finally:
        owner.close()


if __name__ == '__main__':
    main()
