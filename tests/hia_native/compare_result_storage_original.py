# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile one original owner and replay its complete current native domain."""
from pathlib import Path
import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'build', 'native', 'output', 'native-evidence', 'rustc', 'cargo'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--native-evidence-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    sys.path.insert(0, str(root / 'scripts'))
    from hia_native_result_storage_reference import replay_domain
    from result_storage_registry import require
    require(os.getpid() == os.getpgrp(), 'original recipe requires its own externally owned process group')
    report = replay_domain(root, args.build, args.native, args.output, args.domain,
        args.native_evidence, args.native_evidence_sha256, args.rustc, args.cargo)
    print(json.dumps({'status': report['status'], 'domain': report['domain'],
        'original_requests': report['replay']['original_requests'],
        'original_processes': report['replay']['original_processes'],
        'new_native_executions': 0, 'complete_original_native_bytes_equal': True}, sort_keys=True))


if __name__ == '__main__':
    main()
