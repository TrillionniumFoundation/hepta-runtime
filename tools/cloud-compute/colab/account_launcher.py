#!/usr/bin/env python3
"""Explicit account routing for the installed Hepta Colab adapter (no secrets in config)."""
import argparse
import hashlib
import re
import json
import logging
import os
from pathlib import Path
import runpy
import subprocess
import sys
import webbrowser

RELEASE = Path(__file__).resolve().parent
CONFIG = Path.home() / '.config/hepta-colab/accounts.json'

def configure(alias, config):
    if alias not in config['accounts']:
        raise ValueError('unknown_account_alias')
    entry = config['accounts'][alias]
    sys.path.insert(0, str(RELEASE))
    from colab_cli import auth
    auth.KEYRING_SERVICE_NAME = entry['keyring_service']
    # Never fall back to or migrate the single-account legacy token.
    auth.LEGACY_TOKEN_PATH = str(Path(entry['state_dir']) / 'legacy-token-disabled.json')
    return entry

class ScopedProfileError(Exception):
    def __init__(self, code):
        self.code = code


def scoped_profile(entry, alias, key, action, extra):
    """Derive a create-only profile from an account-owned provisioning key.

    This flag never accepts a filesystem path, account override or old runtime.
    Legacy calls without the flag retain their exact existing profile.
    """
    from manage_colab import Journal, private_read
    from authorize_colab import _open_status_parent
    from hepta_colab import Profile

    if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', key):
        raise ScopedProfileError('INVALID_PROVISION_KEY')
    command = extra[0] if extra else None
    if action == 'manage':
        if command != 'bind':
            raise ScopedProfileError('PROVISION_KEY_REQUIRES_BIND_OR_RUN')
        keys = []
        for i, arg in enumerate(extra):
            if arg == '--key':
                if i + 1 >= len(extra):
                    raise ScopedProfileError('PROVISION_KEY_MISMATCH')
                keys.append(extra[i + 1])
            elif arg.startswith('--key='):
                keys.append(arg.split('=', 1)[1])
        if keys != [key]:
            raise ScopedProfileError('PROVISION_KEY_MISMATCH')
    elif action != 'run' or command not in {'submit', 'run', 'status', 'cancel', 'read', 'fetch', 'inspect-key'}:
        raise ScopedProfileError('PROVISION_KEY_REQUIRES_BIND_OR_RUN')

    state = Path(entry['state_dir'])
    digest = hashlib.sha256(key.encode('utf-8')).hexdigest()
    root = state / 'profiles'
    path = root / (digest + '.json')
    journal = Journal(state / 'bootstrap')
    with journal.locked():
        record = journal.load(key)
        if record is None:
            raise ScopedProfileError('PROVISIONING_REQUEST_NOT_FOUND')
        if record.get('account_email', '').casefold() != entry['email'].casefold():
            raise ScopedProfileError('AUTH_ACCOUNT_MISMATCH')
        if record.get('profile_path') not in (None, str(path)):
            raise ScopedProfileError('PROFILE_PATH_CONFLICT')
        if action == 'manage':
            # Validate the parent before mkdir, then the complete parent chain.
            probe = root / '.validate-profile-parent' if root.exists() else root
            fd, _ = _open_status_parent(str(probe))
            os.close(fd)
            root.mkdir(mode=0o700, exist_ok=True)
            if root.is_symlink():
                raise ScopedProfileError('PROFILE_DIRECTORY_UNSAFE')
            info = root.stat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ScopedProfileError('PROFILE_DIRECTORY_NOT_PRIVATE')
            fd, _ = _open_status_parent(str(path))
            os.close(fd)
        else:
            if record.get('profile_path') != str(path) or not record.get('profile_hash'):
                raise ScopedProfileError('PROVISION_PROFILE_NOT_BOUND')
            if command in {'submit', 'run'} and record.get('phase') != 'bound':
                raise ScopedProfileError('PROVISION_RUNTIME_NOT_BOUND')
            profile = Profile(**private_read(path))
            if (profile.fingerprint != record['profile_hash']
                    or not isinstance(profile.expected_account_email, str)
                    or profile.expected_account_email.casefold() != entry['email'].casefold()
                    or profile.state_file != str(journal.state_file)
                    or any(getattr(profile, field) != record.get(record_field)
                           for field, record_field in (
                               ('endpoint', 'endpoint'), ('kernel_id', 'kernel_id'),
                               ('session_id', 'client_session_id'),
                               ('session_name', 'session_name')))):
                raise ScopedProfileError('PROVISION_PROFILE_IDENTITY_MISMATCH')
    return str(path), 'rog-colab-' + alias + '-' + digest[:16]


def main():
    os.umask(0o077)
    runtime_dir = '/run/user/' + str(os.getuid())
    os.environ['XDG_RUNTIME_DIR'] = runtime_dir
    os.environ['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + runtime_dir + '/bus'
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('account', help='Alias from the private accounts.json configuration')
    parser.add_argument('--provision-key', help='Use the immutable profile bound to this account provisioning key; put before action')
    parser.add_argument('action', choices=['authorize', 'manage', 'run'])
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text())
    entry = configure(args.account, config)
    state = Path(entry['state_dir'])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Fixed identities may not be overridden by trailing CLI options.
    forbidden = {'--expected-account','--expected-email','--state-dir','--quota-project','--profile','--status-file','--jobs-state-dir','--name'}
    if any(a.split('=',1)[0] in forbidden
           or (a.startswith('--') and a != '--'
               and any(flag.startswith(a.split('=',1)[0]) for flag in forbidden))
           for a in args.args):
        print(json.dumps({'status':'blocked','error_code':'ACCOUNT_IDENTITY_OVERRIDE_DENIED'}))
        return 2
    profile_path = entry['profile']
    profile_name = 'rog-colab-' + args.account
    if args.provision_key is not None:
        try:
            profile_path, profile_name = scoped_profile(entry, args.account, args.provision_key,
                                                        args.action, list(args.args))
        except Exception as exc:
            code = getattr(exc, 'code', 'PROVISION_PROFILE_VALIDATION_FAILED')
            if not isinstance(code, str) or not re.fullmatch(r'[A-Z0-9_]+', code):
                code = 'PROVISION_PROFILE_VALIDATION_FAILED'
            print(json.dumps({'status':'blocked','error_code':code}))
            return 2
    if args.action == 'authorize':
        class ProfileBrowser(webbrowser.BaseBrowser):
            def open(self, url, new=0, autoraise=True):
                env = os.environ.copy()
                env['DISPLAY'] = ':0'
                subprocess.Popen(['/usr/bin/google-chrome', '--profile-directory='+entry['chrome_profile'], url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
                return True
        webbrowser.register('hepta-account-profile', None, ProfileBrowser(), preferred=True)
        # Bind Google's account hint to the same verified account identity.
        from google_auth_oauthlib.flow import InstalledAppFlow
        original = InstalledAppFlow.run_local_server
        def hinted(flow, *pos, **kw):
            kw['login_hint'] = entry['email']
            return original(flow, *pos, **kw)
        InstalledAppFlow.run_local_server = hinted
        script = 'authorize_colab.py'
        argv = ['--expected-account', entry['email'], '--loopback', '--open-browser',
                '--status-file', str(state/'auth-status.json')]
    elif args.action == 'manage':
        script = 'manage_colab.py'
        argv = ['--state-dir', str(state/'bootstrap'), '--expected-email', entry['email']]
        if entry.get('quota_project'):
            argv += ['--quota-project',entry['quota_project']]
    else:
        script = 'hepta_colab.py'
        argv = ['--state-dir',str(state/'jobs'),'--profile',profile_path]
    extra = list(args.args)
    if args.action == 'manage' and extra and extra[0] == 'bind':
        extra += ['--profile', profile_path, '--jobs-state-dir', str(state/'jobs'),
                  '--name', profile_name]
    elif args.action == 'manage' and extra and extra[0] == 'release':
        extra += ['--jobs-state-dir', str(state/'jobs')]
    sys.argv = [str(RELEASE/script), *argv, *extra]
    runpy.run_path(str(RELEASE/script),run_name='__main__')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
