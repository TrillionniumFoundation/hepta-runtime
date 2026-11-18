# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run every actual Stamp process, preserving complete evidence on failure."""
from pathlib import Path
import argparse
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_stamp_qualification as q


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args();build = args.build.resolve(strict=True);output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False);before = q.source_pins(ROOT)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('HIA_')}
    processes = {};report = {'schema': 'hepta.audit-stamp.native-run.v1', 'status': 'RUNNING',
        'sources': before, 'processes': {}, 'actual_original_executions': 0,
        'production_activated': False, 'audit_storage_closed': False}
    save = lambda: (output / 'result.json').write_bytes(q.encoded(report))
    save()
    try:
        for domain, command in q.commands(ROOT, build, output).items():
            folder = output / 'processes' / domain
            q.run_process(ROOT, folder, command, environment=environment)
            processes[domain] = folder;report['processes'][domain] = str(folder);save()
        evidence = q.native_evidence(ROOT, build, output, processes)
        q.require(q.source_pins(ROOT) == before, 'Stamp sources changed during native execution')
        report.update(status='PASS', evidence=evidence)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        save()
    print(json.dumps({'status': 'PASS', 'mandatory_processes': len(processes),
        'actual_original_executions': 0, 'production_activated': False}, sort_keys=True))


if __name__ == '__main__':
    main()
