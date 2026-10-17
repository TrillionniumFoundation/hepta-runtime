# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent, private operator settings with the six DC-compatible controls."""
from __future__ import annotations
import copy
import json
import os
import pathlib
import platform
import shlex
import stat
import threading
from .processes import _private_root, _read_file, _publish
from .registry import ToolError

DEFAULT_BLOCKED = ['mkfs', 'format', 'mount', 'umount', 'fdisk', 'dd', 'parted', 'diskpart',
    'sudo', 'su', 'passwd', 'adduser', 'useradd', 'usermod', 'groupadd', 'chsh', 'visudo',
    'shutdown', 'reboot', 'halt', 'poweroff', 'init', 'iptables', 'firewall', 'netsh',
    'sfc', 'bcdedit', 'reg', 'net', 'sc', 'runas', 'cipher', 'takeown']
EDITABLE = frozenset(('blockedCommands', 'defaultShell', 'allowedDirectories',
                      'fileReadLineLimit', 'fileWriteLineLimit', 'telemetryEnabled'))


class CompatConfig:
    def __init__(self, state_dir, workspace, *, document_python=None, initial=None):
        self.workspace = pathlib.Path(workspace).expanduser().resolve(strict=True)
        if not self.workspace.is_dir():
            raise ToolError('operator workspace must be a directory')
        self.state_dir = pathlib.Path(state_dir)
        previously_present = self.state_dir.exists()
        self.directory = _private_root(self.state_dir)
        self.document_python = str(document_python or os.environ.get('HEPTA_RUNTIME_DOCUMENT_PYTHON')
                                   or '/usr/bin/python3')
        self._lock = threading.RLock()
        self._values = {'blockedCommands': DEFAULT_BLOCKED[:],
            'defaultShell': os.environ.get('SHELL') or '/bin/sh', 'allowedDirectories': [],
            'fileReadLineLimit': 1000, 'fileWriteLineLimit': 50, 'telemetryEnabled': False}
        if initial:
            for key, value in initial.items():
                if key in EDITABLE:
                    self.validate_value(key, value)
                self._values[key] = copy.deepcopy(value)
        try:
            stored = json.loads(_read_file(self.directory, 'settings.json', 1024 * 1024))
            if not isinstance(stored, dict):
                raise ToolError('invalid operator settings')
            for key, value in stored.items():
                if key in EDITABLE:
                    self.validate_value(key, value)
            self._values.update(stored)
        except FileNotFoundError:
            # A missing policy is never equivalent to an unrestricted fresh
            # profile. The anchor also makes interrupted first writes fail
            # closed until an administrator restores the reviewed settings.
            if previously_present or any(self.state_dir.iterdir()):
                raise ToolError('Existing operator configuration is missing settings.json; restore it before starting')
            _publish(self.directory, 'settings.anchor', {'version': 1})
            _publish(self.directory, 'settings.json', self._values)
        if not (self.state_dir / 'settings.anchor').exists():
            _publish(self.directory, 'settings.anchor', {'version': 1})

    @staticmethod
    def validate_value(key, value):
        if key not in EDITABLE:
            raise ToolError('Setting is not editable: ' + str(key))
        if key in ('blockedCommands', 'allowedDirectories'):
            if not isinstance(value, list) or any(not isinstance(x, str) or '\0' in x for x in value):
                raise ToolError(key + ' requires an array of strings')
        elif key == 'defaultShell':
            if not isinstance(value, str) or not value.strip() or '\0' in value:
                raise ToolError('defaultShell requires a nonempty executable name')
        elif key == 'telemetryEnabled':
            if type(value) is not bool:
                raise ToolError('telemetryEnabled requires a boolean')
        elif type(value) is not int or value <= 0:
            raise ToolError(key + ' requires a positive integer')

    def get(self, key, default=None):
        with self._lock:
            return copy.deepcopy(self._values.get(key, default))

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self._values)

    def set(self, key, value):
        self.validate_value(key, value)
        with self._lock:
            updated = dict(self._values, **{key: copy.deepcopy(value)})
            _publish(self.directory, 'settings.json', updated)
            self._values = updated

    def resolve_path(self, value):
        if not isinstance(value, (str, pathlib.Path)) or '\0' in str(value):
            raise ToolError('path must be a string without NUL')
        path = pathlib.Path(value).expanduser()
        if not path.is_absolute():
            path = self.workspace / path
        resolved = path.resolve(strict=False)
        roots = self.get('allowedDirectories', [])
        if roots:
            accepted = False
            for root in roots:
                base = pathlib.Path(root).expanduser()
                if not base.is_absolute():
                    base = self.workspace / base
                base = base.resolve(strict=False)
                if resolved == base or base in resolved.parents:
                    accepted = True
                    break
            if not accepted:
                raise ToolError('Path is outside allowedDirectories: ' + str(value))
        return resolved

    def validate_command(self, command):
        """Check command positions, so a literal argument named sudo stays data.

        Like DC settings this is an operator convenience filter, not a shell
        sandbox. The process has the invoking login account's normal authority.
        """
        blocked = {x.lower() for x in self.get('blockedCommands', [])}
        if not blocked:
            return True
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars='|;&()<>')
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            return False
        position, redirect = True, False
        for token in tokens:
            if token and all(c in '|;&()' for c in token):
                position = True
                continue
            if token in ('>', '>>', '<', '<<', '2>', '2>>'):
                redirect = True
                continue
            if redirect:
                redirect = False
                continue
            if not position:
                continue
            if '=' in token and token.split('=', 1)[0].isidentifier():
                continue
            base = pathlib.PurePath(token).name.lower()
            if base in blocked:
                return False
            if base not in ('exec', 'command', 'env', 'nohup'):
                position = False
        return True

    def describe(self, client=None, history=None):
        values = self.snapshot()
        values.update(currentClient=client or {}, clientHistory=history or [], version='hepta-dc-compat-v12',
            provider='Hepta Runtime', telemetryTransmissionEnabled=False,
            systemInfo={'platform': platform.system().lower(), 'release': platform.release(),
                        'architecture': platform.machine(), 'hostname': platform.node(),
                        'homedir': str(pathlib.Path.home()), 'defaultShell': values['defaultShell']})
        shells = []
        try:
            shells = [x.strip() for x in pathlib.Path('/etc/shells').read_text().splitlines()
                      if x.strip() and not x.startswith('#')]
        except OSError:
            pass
        return {'config': values, 'uiHints': {'availableShells': list(dict.fromkeys(shells + [values['defaultShell']]))},
            'entries': [{'key': key, 'value': values[key], 'editable': True,
                'valueType': 'array' if isinstance(values[key], list) else
                             'boolean' if isinstance(values[key], bool) else
                             'number' if isinstance(values[key], int) else 'string'} for key in sorted(EDITABLE)]}

    def close(self):
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
