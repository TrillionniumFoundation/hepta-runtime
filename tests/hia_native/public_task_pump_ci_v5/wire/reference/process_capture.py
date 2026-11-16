"""Complete isolated process capture, preserved from the worker reference. """
from __future__ import annotations

import argparse

import hashlib

import io

import json

import os

from pathlib import Path

import shutil

import signal

import subprocess

import tarfile

import time

import tomllib

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

def run(output, label, command, env, *, limit, stdin=None):
    directory = output / 'processes'
    directory.mkdir(exist_ok=True)
    stdout, stderr = (directory / (label + '.stdout'), directory / (label + '.stderr'))
    row = {'label': label, 'command': [str(x) for x in command], 'cwd': str(output), 'parent_pid': os.getpid(), 'pid': None, 'pgid': None, 'timeout_seconds': limit, 'started': False, 'timed_out': False, 'stdin_sha256': None if stdin is None else sha(stdin), 'environment': {k: env.get(k) for k in ['RUSTUP_TOOLCHAIN', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_ENCODED_RUSTFLAGS']}}
    process = None
    failure = None
    start = time.monotonic_ns()
    try:
        with stdout.open('xb') as out, stderr.open('xb') as err:
            process = subprocess.Popen(command, cwd=output, env=env, stdout=out, stderr=err, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, start_new_session=True)
            row.update(started=True, pid=process.pid, pgid=process.pid)
            try:
                process.communicate(input=stdin, timeout=limit)
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                raise
    except BaseException as exc:
        failure = exc
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            finally:
                row['returncode'] = process.wait()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        row['elapsed_ns'] = time.monotonic_ns() - start
        if failure is not None:
            row['failure'] = {'type': type(failure).__name__, 'message': str(failure)}
        for key, path in [('stdout', stdout), ('stderr', stderr)]:
            raw = path.read_bytes() if path.exists() else b''
            row[key] = {'path': str(path.relative_to(output)), 'bytes': len(raw), 'sha256': sha(raw)}
        put(directory / (label + '.json'), row)
    if failure is not None:
        raise failure
    assert row['returncode'] == 0 and (not row['timed_out']), row
    return row
