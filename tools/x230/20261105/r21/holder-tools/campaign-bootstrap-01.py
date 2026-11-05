#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Mac-held stdin bootstrap: verify the installed launcher, then exec those bytes."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--launcher-sha256', required=True)
args = parser.parse_args()
assert re.fullmatch(r'[0-9a-f]{64}', args.launcher_sha256)
path = Path('/home/qian/hepta-runtime-optimization-20261105-r21/campaign-tools/run_six_host_campaign_01.py')
assert path.resolve() == path
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    before = os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
    with os.fdopen(os.dup(fd), 'rb') as stream:
        source = stream.read(68591)
    after, current = os.fstat(fd), path.lstat()
    keys = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    assert all(getattr(before, k) == getattr(after, k) == getattr(current, k) for k in keys)
finally:
    os.close(fd)
assert len(source) == 68590 and hashlib.sha256(source).hexdigest() == '7cef87d976488ea63c5970f90b2e695bad835b1e01293aaaa5eeaee575e962a2'
sys.argv = [str(path), '--launcher-sha256', args.launcher_sha256,
    '--expected-acceptance-sha256', '950a3e0d905e12937fa94ed4f9c4ad138e4797e5e4276abc19bc6c208a2a59a1',
    '--expected-control-report-sha256', 'e664d6c75572d590df4537fc47cfddc1b66b7f1aeba100a5b7e542bcdf43e1b1',
    '--expected-qualification-report-sha256', '301e50f699d7a967d977add6d8da6872a3e09cedaabf1b0366658f6cf26af06a',
    '--expected-candidate-sha256', '7709579269d5c7ec1eba8512dd7cc028ecc602c08156f8172a15203080e39878']
scope = {'__name__': '__main__', '__file__': str(path), '__package__': None}
exec(compile(source, str(path), 'exec'), scope)
