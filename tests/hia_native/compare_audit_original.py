# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freshly compile one original audit owner and compare its complete domain."""
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
    args = parser.parse_args();root = args.root.resolve(strict=True)
    sys.path[:0] = [str(root / 'scripts'), str(root / 'tests/hia_native')]
    from hia_native_audit_reference import replay_domain, original_evidence
    from audit_readiness_registry import require
    require(os.getpid() == os.getpgrp(), 'original recipe requires an externally owned process group')
    report = replay_domain(root, args.build, args.native, args.output, args.domain,
        args.native_evidence, args.native_evidence_sha256, args.rustc, args.cargo)
    original_evidence(root, args.build, args.native, args.output, args.domain,
        args.native_evidence, args.native_evidence_sha256)
    print(json.dumps({'status': report['status'], 'domain': report['domain'],
        **report['replay'], 'new_native_executions': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
