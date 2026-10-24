#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Provision only a dedicated OpenAI Tunnels Read+Use key. Never prints secrets."""
import argparse, grp, json, os, pathlib, re, stat, subprocess, tempfile
ROOT = pathlib.Path('/etc/hepta-runtime')

def atomic(name, data, gid):
    fd, temporary = tempfile.mkstemp(prefix='.provision-', dir=ROOT)
    try:
        os.fchmod(fd, 0o640); os.fchown(fd, 0, gid)
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(temporary, ROOT / name)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tunnel-id')
    parser.add_argument('--key-file', type=pathlib.Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--replace', action='store_true')
    args = parser.parse_args()
    if args.check:
        result = {'tunnel_id_configured': (ROOT/'tunnel.env').is_file(),
                  'dedicated_key_present': (ROOT/'tunnel-api-key').is_file(),
                  'runtime_token_present': (ROOT/'mcp-token').is_file(),
                  'client_present': pathlib.Path('/usr/local/bin/tunnel-client').is_file()}
        print(json.dumps(result, indent=2)); return
    if os.geteuid() != 0: parser.error('run as root')
    if not args.tunnel_id or not re.fullmatch(r'tunnel_[A-Za-z0-9_-]{4,160}', args.tunnel_id):
        parser.error('supply the actual workspace-associated tunnel ID')
    if not args.key_file: parser.error('--key-file must name the dedicated runtime key file')
    if not ROOT.is_dir() or ROOT.is_symlink() or not (ROOT/'mcp-token').is_file():
        parser.error('install the runtime controller first')
    if not args.replace and ((ROOT/'tunnel.env').exists() or (ROOT/'tunnel-api-key').exists()):
        parser.error('existing tunnel configuration; use --replace for intentional rotation')
    fd = os.open(args.key_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as inp:
        meta = os.fstat(inp.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077 or meta.st_size > 4096:
            parser.error('key source must be a root-owned regular file with mode 0600 or 0400')
        key = inp.read(4097).strip()
    if not key.startswith(b'sk-') or not 20 <= len(key) <= 4096 or any(c <= 32 or c >= 127 for c in key):
        parser.error('invalid dedicated runtime key format')
    gid = grp.getgrnam('hepta-runtime').gr_gid
    atomic('tunnel-api-key', key + b'\n', gid)
    env = ('CONTROL_PLANE_TUNNEL_ID=' + args.tunnel_id + '\n'
           'MCP_SERVER_URL="url=http://127.0.0.1:8787/mcp,channel=main"\n'
           'MCP_EXTRA_HEADERS="X-Hepta-Runtime-Token: file:/etc/hepta-runtime/mcp-token"\n'
           'MCP_DISCOVERY_EXTRA_HEADERS="X-Hepta-Runtime-Token: file:/etc/hepta-runtime/mcp-token"\n'
           'MCP_STARTUP_WAIT_TIMEOUT=30s\nHEALTH_LISTEN_ADDR=127.0.0.1:8788\n')
    atomic('tunnel.env', env.encode(), gid)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'hepta-runtime-tunnel.service'], check=True)
    print('Dedicated tunnel configured. Verify tunnel health and the first ChatGPT tool call; no key was printed.')

if __name__ == '__main__': main()
