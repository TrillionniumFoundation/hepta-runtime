# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run one fresh Rust Stamp recipe inside its outer 180-second owner group."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_stamp_reference as reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('repo', 'build', 'native', 'output', 'native-evidence', 'rustc', 'cargo'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--domain', required=True, choices=reference.DOMAINS)
    parser.add_argument('--native-evidence-sha256', required=True)
    args = parser.parse_args()
    reference.require(args.repo.resolve(strict=True) == ROOT, 'Stamp reference root differs')
    observed = reference.replay(ROOT, args.build, args.native, args.output, args.domain,
        args.native_evidence, args.native_evidence_sha256, args.rustc, args.cargo)
    print(json.dumps({'status': 'PASS', 'domain': args.domain, **observed['comparison'],
        'production_activated': False, 'whole_runtime_replaced': False}, sort_keys=True))


if __name__ == '__main__':
    main()
