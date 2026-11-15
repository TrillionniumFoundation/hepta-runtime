#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded raw/JSON-string/hex/base64/gzip scanning; findings contain no secret text."""
import base64
import gzip
import hashlib
import io
import json
import re

MAX_FILE = 32 * 1024**2
MAX_EXPANDED = 64 * 1024**2
MAX_NODES = 100000
MAX_JSON_VISITS = 1000000
MAX_DEPTH = 3
RULES = {
    'private-key-pem': re.compile(rb'-----BEGIN (?:(?:OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY-----(?:\r?\n|\\(?:r\\)?n)(?:(?:Proc-Type|DEK-Info):[^\r\n\\]{1,512}(?:\r?\n|\\(?:r\\)?n)){0,2}(?:\r?\n|\\(?:r\\)?n)?[A-Za-z0-9+/=]{16,}'),
    'github-token': re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'),
    'openai-token': re.compile(rb'sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{32,}'),
    'slack-token': re.compile(rb'xox[baprs]-[A-Za-z0-9-]{20,}'),
    'aws-access-key': re.compile(rb'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    'google-api-key': re.compile(rb'AIza[0-9A-Za-z_-]{35}'),
    'bearer-authorization': re.compile(rb'(?i)authorization["\s:]+bearer[ \t]+[A-Za-z0-9._~+/-]{20,}'),
}
ENCODED = re.compile(rb'(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{24,}={0,2}(?![A-Za-z0-9_+/=-])')
HEX_RUN = re.compile(rb'(?<![A-Za-z0-9])[0-9a-fA-F]{32,}(?![A-Za-z0-9])')


def scan(raw, path):
    """Fail closed on bounds; decoded findings retain only path and pattern labels."""
    findings, seen, queue, total, nodes = set(), {}, {}, 0, 0
    if len(raw) > MAX_FILE:
        return [{'path': path, 'pattern': 'raw:scan-size-limit'}]

    def enqueue(data, layer, depth):
        # Whole JSON/JSONL documents enqueue their strings before the queue drains.
        # Deduplicate that pending work without losing a later, shallower decode.
        digest = hashlib.sha256(data).digest()
        prior_depth = seen.get(digest)
        pending = queue.get(digest)
        if prior_depth is not None and prior_depth <= depth:
            return
        if pending is not None and pending[2] <= depth:
            return
        if pending is None and len(queue) >= MAX_NODES:
            findings.add('decoded-scan-queue-exceeded')
            return
        queue[digest] = (data, layer, depth)

    enqueue(raw, 'raw', 0)
    while queue:
        digest, (data, layer, depth) = queue.popitem()
        prior_depth = seen.get(digest)
        if prior_depth is not None and prior_depth <= depth:
            continue
        seen[digest] = depth
        total += len(data)
        nodes += 1
        if total > MAX_EXPANDED or nodes > MAX_NODES:
            findings.add('decoded-scan-budget-exceeded')
            break
        for name, rule in RULES.items():
            if rule.search(data):
                findings.add(layer + ':' + name)
        if data.startswith(b'\x7fELF'):
            findings.add(layer + ':elf-body')
        if depth >= MAX_DEPTH:
            continue
        if data.startswith(b'\x1f\x8b'):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    decoded = stream.read(MAX_EXPANDED - total + 1)
                if len(decoded) > MAX_EXPANDED - total:
                    findings.add(layer + ':gzip-expansion-limit')
                else:
                    enqueue(decoded, layer + '/gzip', depth + 1)
            except (OSError, EOFError, ValueError):
                findings.add(layer + ':invalid-gzip')
        if data.lstrip().startswith((b'{', b'[', b'"')):
            try:
                text, offset, visited = data.decode('utf-8'), 0, 0
                decoder = json.JSONDecoder()
                while offset < len(text):
                    if text[offset] in ' \t\r\n':
                        offset += 1
                        continue
                    value, offset = decoder.raw_decode(text, offset)
                    pending = [value]
                    while pending:
                        value = pending.pop()
                        visited += 1
                        if visited > MAX_JSON_VISITS or 'decoded-scan-queue-exceeded' in findings:
                            findings.add(layer + ':json-scan-budget-exceeded')
                            break
                        if isinstance(value, str):
                            enqueue(value.encode(), layer + '/json', depth + 1)
                        elif isinstance(value, dict):
                            pending.extend(value.keys())
                            pending.extend(value.values())
                        elif isinstance(value, list):
                            pending.extend(value)
                    if visited > MAX_JSON_VISITS or 'decoded-scan-queue-exceeded' in findings:
                        break
            except (json.JSONDecodeError, UnicodeError):
                pass
            except (ValueError, RecursionError):
                findings.add(layer + ':json-parser-limit')
        for token in HEX_RUN.finditer(data):
            if len(token[0]) % 2 == 0:
                enqueue(bytes.fromhex(token[0].decode('ascii')), layer + '/hex', depth + 1)
        for token in ENCODED.finditer(data):
            try:
                value = token[0]
                decoded = base64.b64decode(value + b'=' * (-len(value) % 4), altchars=b'-_', validate=True)
                enqueue(decoded, layer + '/base64', depth + 1)
            except ValueError:
                pass
        if 'decoded-scan-queue-exceeded' in findings:
            break
    return [{'path': path, 'pattern': pattern} for pattern in sorted(findings)]
