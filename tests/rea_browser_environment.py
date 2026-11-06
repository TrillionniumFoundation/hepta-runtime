#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Test-only actual-Chrome exec observations; no runtime configuration hooks.

Chromium can relocate environ strings and overwrite their original stack area
when setting its process title. /proc/PID/environ reads that initial area, not
the current libc environ pointers. An empty selection from it is never accepted
as private-environment evidence. The pinned constructor observes its own actual
Chrome ELF, and its record is bound to that same live PID/start tick/executable.
Uninstrumented capture/cancellation remain separate required checks.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

from rea_java_external import digest, private_write

KEYS = {'HOME': 'home', 'XDG_DATA_HOME': 'xdg-data',
        'XDG_CONFIG_HOME': 'xdg-config', 'XDG_CACHE_HOME': 'xdg-cache'}

EXECUTABLE_FIELDS = ('device', 'inode', 'size', 'mode', 'uid', 'gid', 'links',
                     'mtime_ns', 'ctime_ns')


def validate_executable(record, expected):
    assert isinstance(record, dict) and set(record) == set(EXECUTABLE_FIELDS), (
        'Actual Chrome executable receipt must contain exactly all nine identity fields')
    assert all(type(record[key]) is int for key in EXECUTABLE_FIELDS), (
        'Actual Chrome executable identity fields must be integers')
    assert record == {key: expected[key] for key in EXECUTABLE_FIELDS}, (
        'Actual Chrome executable receipt differs from the pinned installation')


def executable_receipt_controls(expected):
    valid = {key: expected[key] for key in EXECUTABLE_FIELDS}
    validate_executable(valid, expected)
    cases = [('empty', {})] + [
        ('missing_' + field, {key: value for key, value in valid.items() if key != field})
        for field in EXECUTABLE_FIELDS]
    results = []
    for name, candidate in cases:
        try:
            validate_executable(candidate, expected)
        except AssertionError as error:
            results.append(dict(case=name, accepted=False, rejection=str(error)))
        else:
            raise AssertionError('Incomplete Chrome executable receipt was accepted')
    assert len(results) == 10
    return results


def expected_environment(profile):
    return {key: str(profile / name) for key, name in KEYS.items()}


def decode_environment(record):
    assert set(record['environment_hex']) == set(KEYS)
    return {key: bytes.fromhex(value).decode('utf-8') if value is not None else None
            for key, value in record['environment_hex'].items()}


def validate_environment(record, expected):
    selected = decode_environment(record)
    assert record['key_counts'] == {key: 1 for key in KEYS}, (
        'Actual Chrome exec environment has missing or duplicate private keys', record['key_counts'])
    assert selected == expected, ('Actual Chrome exec environment is not private', selected)
    return selected


class ChromeEnvironmentObserver:
    def __init__(self, root, installation):
        self.root = root / 'chrome-environment-observer'
        self.root.mkdir(mode=0o700)
        self.records = self.root / 'records'
        self.records.mkdir(mode=0o700)
        self.installation = installation
        source = Path(__file__).resolve().parent / 'fixtures/rea_browser_env_observer.c'
        copied = self.root / source.name
        private_write(copied, source.read_bytes())
        copied.chmod(0o400)
        compiler = Path('/usr/bin/cc').resolve(strict=True)
        version = subprocess.run([str(compiler), '--version'], check=True,
                                 capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        self.pins = {str(source): digest(source), str(copied): digest(copied),
                     str(Path(__file__).resolve()): digest(Path(__file__).resolve()),
                     str(compiler): digest(compiler)}
        self.library = self.root / 'observe-exec.so'
        self.negative_library = self.root / 'observe-exec-negative.so'
        commands = []
        for library, negative in ((self.library, 0), (self.negative_library, 1)):
            command = [str(compiler), '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                       '-DREA_OBSERVER_EXECUTABLE=' + json.dumps(installation['executable']['realpath']),
                       '-DREA_OBSERVER_DIRECTORY=' + json.dumps(str(self.records)),
                       '-DREA_OBSERVER_EXIT_AFTER_RECORD=' + str(negative),
                       str(copied), '-o', str(library)]
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
            library.chmod(0o500)
            self.pins[str(library)] = digest(library)
            commands.append(command)
        self.binding = dict(schema='hepta.rea.chrome-exec-observer-binding.v1',
            implementation='test-only LD_PRELOAD ELF constructor before Chrome main',
            injection='existing process_start.env.LD_PRELOAD only on the additional instrumented job',
            runtime_or_launcher_hooks_added=False, compiler_version=version, build_commands=commands,
            closure_sha256=dict(self.pins), observed_keys=list(KEYS),
            actual_chrome_executable=installation['executable'],
            executable_receipt_schema_controls=executable_receipt_controls(installation['executable']),
            scope='constructor environment of the same instrumented Chrome PID only; no claim about another or uninstrumented PID')
        private_write(self.root / 'binding.json', self.binding)

    def read(self, pid, ticks):
        path = self.records / ('chrome-%d-%d.json' % (pid, ticks))
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            assert stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
            assert before.st_uid == os.getuid() and before.st_nlink == 1 and 0 < before.st_size <= 65536
            chunks, size = [], 0
            while True:
                data = os.read(fd, 65537 - size)
                if not data:
                    break
                chunks.append(data)
                size += len(data)
                assert size <= 65536
            after = os.fstat(fd)
            assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            raw = b''.join(chunks)
            assert len(raw) == before.st_size
        finally:
            os.close(fd)
        record = json.loads(raw)
        assert record['schema'] == 'hepta.rea.chrome-exec-environment.v1'
        assert record['phase'] == 'actual_chrome_elf_constructor_before_main'
        assert record['pid'] == record['pgid'] == pid and record['start_ticks'] == ticks
        expected = self.installation['executable']
        validate_executable(record['executable'], expected)
        return dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), record=record)

    def verify_live(self, identity, expected):
        evidence = self.read(identity['pid'], identity['start_ticks'])
        record = evidence['record']
        assert all(record[key] == identity[key] for key in ('pid', 'parent_pid', 'pgid', 'start_ticks'))
        assert record['negative_control_exit_before_main'] is False
        evidence['environment'] = validate_environment(record, expected)
        self.verify_closure()
        return evidence

    def negative_controls(self):
        results = []
        controls = self.root / 'negative-controls'
        controls.mkdir(mode=0o700)
        for key in KEYS:
            for mutation in ('missing', 'non-private'):
                case = controls / (key.lower() + '-' + mutation)
                case.mkdir(mode=0o700)
                profile = case / 'expected-profile'
                profile.mkdir(mode=0o700)
                expected = expected_environment(profile)
                for path in expected.values():
                    Path(path).mkdir(mode=0o700)
                outside = case / 'outside-profile'
                outside.mkdir(mode=0o700)
                environment = dict(os.environ, **expected, LD_PRELOAD=str(self.negative_library))
                if mutation == 'missing':
                    del environment[key]
                else:
                    environment[key] = str(outside)
                child = subprocess.Popen([self.installation['launcher']['invocation_path'], '--version'],
                    env=environment, start_new_session=True, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Keep custody until any timeout signal has been sent.
                try:
                    deadline = time.monotonic() + 15
                    while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                        assert time.monotonic() < deadline, 'Chrome negative control did not exit'
                        time.sleep(.01)
                    assert child.wait(timeout=1) == 0
                except BaseException:
                    if child.returncode is None:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        child.wait(timeout=5)
                    raise
                records = list(self.records.glob('chrome-%d-*.json' % child.pid))
                assert len(records) == 1
                ticks = int(records[0].stem.rsplit('-', 1)[1])
                evidence = self.read(child.pid, ticks)
                record = evidence['record']
                assert record['parent_pid'] == os.getpid()
                assert record['negative_control_exit_before_main'] is True
                observed = decode_environment(record)
                assert all(observed[name] == expected[name] for name in KEYS if name != key)
                assert observed[key] == (None if mutation == 'missing' else str(outside))
                try:
                    validate_environment(record, expected)
                except AssertionError as error:
                    rejection = str(error)
                else:
                    raise AssertionError('Actual Chrome negative environment was accepted')
                results.append(dict(key=key, mutation=mutation, accepted=False,
                                    rejection=rejection, evidence=evidence))
        assert len(results) == 8
        self.verify_closure()
        private_write(self.root / 'negative-controls.json', results)
        return results

    def verify_closure(self):
        assert {path: digest(Path(path)) for path in self.pins} == self.pins
