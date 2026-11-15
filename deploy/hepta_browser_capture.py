#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Capture fixed HTTP resource observations under the existing native job owner.

A generated, owned harness fetches SHA-bound local resources through a private
Chrome. Input HTML/JS is response data; application scripts are never executed.
Saved HAR response representations support offline REA inspection and replay.
This is not application-behavior recording or process-level network isolation.
"""
import argparse
import json
import sys

from dc_compat.chromium_capture import capture, cancellation_cleanup, load_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('The local capture worker is currently supported on Linux only')
    def progress(value):
        print(json.dumps(value, separators=(',', ':')), flush=True)
    try:
        with cancellation_cleanup() as cancellation:
            manifest = load_manifest(args.manifest, args.expected_sha256)
            result = capture(manifest, args.output_directory, progress, cancellation=cancellation)
        progress(dict(phase='complete', **result))
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps(dict(error=str(error)[:2048], automatic_retry=False,
                              recovery='Observe the original native job; do not submit a fresh key after uncertainty')),
              file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
