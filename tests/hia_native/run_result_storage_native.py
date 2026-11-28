# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run all private storage native domains with unchanged individual deadlines."""
from pathlib import Path
import argparse
import json
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'build', 'hepta', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    root, build, hepta = (path.resolve(strict=True) for path in (args.root, args.build, args.hepta))
    output = args.output.resolve();output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(root / 'scripts'))
    import hia_native_result_storage_qualification as q
    from result_storage_registry import encoded
    pins = q.source_pins(root);started = time.monotonic()
    report = {'schema': 'hepta.result-storage.native-run.v1', 'status': 'RUNNING', 'sources': pins,
        'checks': {}, 'new_original_processes': 0, 'whole_runtime_replaced': False,
        'production_activated': False, 'result_storage_closed': False}
    save = lambda: (output / 'result.json').write_bytes(encoded(report))
    save()
    try:
        report['build'] = q.build_evidence(root, build, hepta=hepta)
        environment = {key: value for key, value in os.environ.items() if not key.startswith('HIA_')}
        completed = {}
        for domain, command in q.commands(root, build, output).items():
            directory = output / 'processes' / domain
            report['checks'][domain] = q.run_process(root, directory, command, environment=environment)
            completed[domain] = str(directory);save()
        evidence = q.native_evidence(root, build, output, completed)
        q.require(q.source_pins(root) == pins, 'source changed during complete native domain')
        (output / 'native-evidence.json').write_bytes(encoded(evidence))
        report.update(status='PASS', evidence=q.pin(output / 'native-evidence.json'),
            domains=len(completed), sources_unchanged=True)
    except BaseException as error:
        report.update(status='FAIL', error=repr(error));raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started;save()
    print(json.dumps({'status': report['status'], 'domains': report['domains'],
        'new_original_processes': 0, 'evidence': report['evidence']}, sort_keys=True))


if __name__ == '__main__':
    main()
