#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Call the independent computer owner without a Desktop Commander installation.

This entry point also works through an already available Hepta process tool when
a client's tool catalogue has not yet incorporated the new computer tools. It
submits an action once; subsequent requests only read its original call receipt.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import sys
import time
import uuid


def private_configuration(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('Computer client configuration must be an owned regular 0600 file')
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError('Invalid computer client configuration')
    return value


def connect(config):
    release = pathlib.Path(config['release'])
    if not release.is_absolute():
        raise ValueError('An absolute immutable release path is required')
    # The installed adapter already implements the authenticated HTTP protocol,
    # contract checks and a unique per-client request identity. Reuse that code.
    sys.path.insert(0, str(release))
    from chatgpt_full_operator import NativeProxy, private_token
    from chatgpt_computer_operator import CompatibilityContract
    return NativeProxy(config['upstream'], private_token(config['token_file']),
        CompatibilityContract.load(config['compat_contract'], config['compat_contract_sha256']))


def text_value(result):
    blocks = result.get('content', [])
    texts = [block['text'] for block in blocks if block.get('type') == 'text']
    if len(texts) != 1:
        return None
    try:
        return json.loads(texts[0])
    except (TypeError, ValueError):
        return None


def invoke(proxy, tool, arguments, wait_seconds):
    request_id = uuid.uuid4().hex
    def request(name, args, identity):
        envelope = proxy.dispatch({'jsonrpc': '2.0', 'id': identity, 'method': 'tools/call',
            'params': {'name': name, 'arguments': args}})
        if 'error' in envelope:
            raise RuntimeError('Tool transport refused the request; the action was not retried: ' + str(envelope['error']))
        return envelope['result']
    result = request(tool, arguments, request_id)
    receipt = text_value(result)
    if not isinstance(receipt, dict) or receipt.get('status') != 'running' or not receipt.get('call_id'):
        return result
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        time.sleep(min(.1, max(0, deadline - time.monotonic())))
        try:
            original = request('get_tool_result', {'call_id': receipt['call_id']}, uuid.uuid4().hex)
        except Exception as error:
            preserved = dict(receipt, poll_status='unavailable', automatic_retry=False,
                poll_error=type(error).__name__, next_action='get_tool_result')
            return {'isError': True, 'content': [{'type': 'text', 'text': json.dumps(preserved, ensure_ascii=False)}]}
        value = text_value(original)
        if not isinstance(value, dict):
            raise RuntimeError('Invalid original-call receipt; resume ' + receipt['call_id'] + ' with get_tool_result; no action replay')
        if value.get('status') not in ('accepted', 'executing'):
            return value.get('result', original)
    # A deadline says nothing about whether an action happened. Preserve the
    # original call_id so the caller can continue reading instead of replaying.
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=pathlib.Path, default=pathlib.Path.home() / '.config/hepta-runtime/computer-client.json')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--list-tools', action='store_true')
    mode.add_argument('--tool')
    data = parser.add_mutually_exclusive_group()
    data.add_argument('--arguments', default='{}', help='One JSON object; values are passed without shell interpretation')
    data.add_argument('--arguments-file', type=pathlib.Path, help='Read the JSON object from a file, or - for stdin')
    parser.add_argument('--wait-seconds', type=float, default=30)
    args = parser.parse_args(argv)
    if not 0 <= args.wait_seconds <= 86400:
        parser.error('wait-seconds must be between zero and 86400')
    payload = args.arguments
    if args.arguments_file is not None:
        payload = sys.stdin.read() if str(args.arguments_file) == '-' else args.arguments_file.read_text()
    arguments = json.loads(payload)
    if not isinstance(arguments, dict):
        parser.error('arguments must be a JSON object')
    proxy = connect(private_configuration(args.config))
    try:
        initialized = proxy.dispatch({'jsonrpc': '2.0', 'id': 'init', 'method': 'initialize',
            'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'hepta-computer-client', 'version': '1'}}})
        if 'error' in initialized:
            raise RuntimeError('Computer owner initialization failed')
        if args.list_tools:
            envelope = proxy.dispatch({'jsonrpc': '2.0', 'id': 'tools', 'method': 'tools/list', 'params': {}})
            if 'error' in envelope:
                raise RuntimeError('Computer owner catalogue unavailable')
            result = envelope['result']
        else:
            result = invoke(proxy, args.tool, arguments, args.wait_seconds)
        print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
        return 1 if result.get('isError') else 0
    finally:
        proxy.close(timeout=0)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'error': str(error), 'action_retried': False}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
