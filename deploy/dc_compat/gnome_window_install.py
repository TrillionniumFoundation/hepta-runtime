# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Build a reviewable extension ZIP; install/enable only with explicit flags.

No restart, Shell Eval, permission weakening, logout or GNOME configuration
change is performed by the default package-only operation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import zipfile

UUID = 'hepta-window-bridge@hepta-runtime.local'
FILES = ('metadata.json', 'extension.js', 'logic.js', 'service.js', 'LICENSE')


def build_package(output):
    source = pathlib.Path(__file__).with_name('gnome_window_extension')
    output = pathlib.Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            path = source / name
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    return {'path': str(output.absolute()), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
            'files': list(FILES), 'contains_credentials': False}


def prepare_config(path, profile_id):
    if not isinstance(profile_id, str) or not 1 <= len(profile_id) <= 128:
        raise ValueError('A stable profile ID of 1-128 characters is required')
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Refuse replacement: restarting/installing never rotates an existing token.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(json.dumps({'version': 1, 'profile_id': profile_id, 'token': secrets.token_hex(32)}).encode())
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {'path': str(path.absolute()), 'created': True, 'mode': '0600', 'token_printed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--prepare-config', action='store_true')
    parser.add_argument('--profile-id')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--enable', action='store_true')
    args = parser.parse_args(argv)
    if args.enable and not args.install:
        parser.error('--enable requires explicit --install')
    report = {'package': build_package(args.output), 'installed': False, 'enabled': False,
              'restart_performed': False, 'logout_performed': False}
    config = pathlib.Path(os.environ.get('XDG_CONFIG_HOME', pathlib.Path.home() / '.config')) / 'hepta-runtime' / 'gnome-window-bridge.json'
    if args.prepare_config:
        report['config'] = prepare_config(config, args.profile_id)
    if args.install:
        if not config.is_file():
            raise RuntimeError('Prepare the private bridge config before installation')
        from .gnome_window_provider import GnomeWindowManager, read_private_config
        private = read_private_config(config, args.profile_id)
        version = subprocess.run(['gnome-shell', '--version'], capture_output=True, text=True, check=True)
        if not re.search(r'GNOME Shell 46(?:\.|\s|$)', version.stdout):
            raise RuntimeError('This reviewed extension targets GNOME Shell 46 only')
        subprocess.run(['gnome-extensions', 'install', '--force', str(pathlib.Path(args.output).absolute())], check=True, stdout=subprocess.DEVNULL)
        report['installed'] = True
        if args.enable:
            result = subprocess.run(['gnome-extensions', 'enable', UUID], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            report['enabled'] = result.returncode == 0
            report['bridge_verified'] = False
            if report['enabled']:
                manager = GnomeWindowManager({'token_path': str(config), 'profile_id': private['profile_id']})
                try:
                    health = manager._call('GetCapabilities')
                    report['bridge_verified'] = bool(health.get('protocol') == 1)
                    report['bridge_locked'] = health.get('locked')
                except Exception as error:
                    report['bridge_error_class'] = type(error).__name__
                finally:
                    if manager.bus:
                        manager.bus.close_sync(None)
            if not report['enabled']:
                report['manual_session_step_required'] = 'GNOME may need to discover the new extension at the next login. Save work and explicitly choose a logout/login later, then enable Hepta Window Bridge in Extensions. No logout or restart was attempted.'
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
